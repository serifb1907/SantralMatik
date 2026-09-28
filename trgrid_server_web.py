# -*- coding: utf-8 -*-
"""
SantralMatik / TR-GRID - Render Web Sunucusu

Güvenlik prensipleri:
- Kullanıcı EPİAŞ e-posta/şifresi sunucuya yalnızca EPİAŞ'a giriş yapmak için gelir.
- Kullanıcı şifresi, TGT, kullanıcı adı veya istek gövdesi diske/veritabanına yazılmaz.
- Uygulama bunları loglamaz.
- EPİAŞ TGT'si yalnızca ilgili istek süresince bellekte tutulur ve iş bitince referansları bırakılır.
- CORS varsayılan olarak kapalıdır. Cross-origin kullanım gerekiyorsa ALLOWED_ORIGINS ayarlanmalıdır.
- İstek boyutu, parola uzunluğu, IP oranı ve eşzamanlı EPİAŞ işleri sınırlandırılır.
- Render'ın PORT değişkeni kullanılır.
"""

import gc
import ipaddress
import json
import os
import re
import secrets
import threading
import time
import uuid
from collections import defaultdict, deque
from datetime import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

import requests

HOST = "0.0.0.0"
PORT = int(os.environ.get("PORT", "10000"))

TGT_URL = "https://giris.epias.com.tr/cas/v1/tickets"
BASE_URL = "https://seffaflik.epias.com.tr/electricity-service"
HERE = Path(__file__).resolve().parent
HTML_FILE = HERE / "TRGRID_V3.html"

# -----------------------------------------------------------------------------
# Güvenlik / kapasite ayarları
# -----------------------------------------------------------------------------
MAX_BODY_BYTES = 64 * 1024
MAX_USERNAME_LEN = 254
MAX_PASSWORD_LEN = 256
MAX_DATE_LEN = 10
MAX_JOB_ID_LEN = 64

# Aynı anda çok fazla EPİAŞ isteği Render Free instance'ını boğmasın.
MAX_CONCURRENT_JOBS = max(1, int(os.environ.get("MAX_CONCURRENT_JOBS", "3")))
JOB_SEMAPHORE = threading.BoundedSemaphore(MAX_CONCURRENT_JOBS)

# Aynı IP'nin kısa sürede sürekli EPİAŞ isteği başlatmasını engeller.
RATE_LIMIT_WINDOW = 10 * 60
RATE_LIMIT_MAX = 8
RATE_LIMIT = defaultdict(deque)
RATE_LOCK = threading.Lock()

# Progress verisi kısa süreli tutulur; kimlik bilgisi içermez.
PROGRESS = {}
PROGRESS_TTL = 30 * 60
PROGRESS_LOCK = threading.Lock()

# Varsayılan davranış: yalnızca aynı origin.
# Örn. öğretim üyesinin blogundan iframe/fetch yapılacaksa:
# ALLOWED_ORIGINS=https://hoca-site.com,https://www.hoca-site.com
ALLOWED_ORIGINS = {
    x.strip().rstrip("/")
    for x in os.environ.get("ALLOWED_ORIGINS", "").split(",")
    if x.strip()
}

EMAIL_RE = re.compile(r"^[^\s@]+@[^\s@]+\.[^\s@]+$")
DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")

# -----------------------------------------------------------------------------
# Yardımcılar
# -----------------------------------------------------------------------------

def cleanup_progress():
    now = time.time()
    with PROGRESS_LOCK:
        old = [k for k, v in PROGRESS.items() if now - v.get("updated", now) > PROGRESS_TTL]
        for key in old:
            PROGRESS.pop(key, None)


def set_progress(job_id, percent, stage, detail=None):
    cleanup_progress()
    safe_detail = detail or stage
    # Progress alanına hiçbir şekilde kullanıcı adı/şifre/TGT koyulmamalıdır.
    with PROGRESS_LOCK:
        PROGRESS[job_id] = {
            "percent": int(max(0, min(100, percent))),
            "stage": str(stage)[:160],
            "detail": str(safe_detail)[:240],
            "updated": time.time(),
        }


def get_progress(job_id):
    cleanup_progress()
    with PROGRESS_LOCK:
        item = PROGRESS.get(job_id)
        if item:
            return dict(item)
    return {
        "percent": 0,
        "stage": "İşlem başlatılıyor...",
        "detail": "EPİAŞ bağlantısı hazırlanıyor...",
    }


def get_client_ip(handler):
    """Render proxy arkasında istemci IP'sini almaya çalışır.

    X-Forwarded-For Render gibi güvenilir reverse-proxy ortamında kullanılır.
    Değer doğrulanamazsa doğrudan bağlantı adresine dönülür.
    """
    forwarded = handler.headers.get("X-Forwarded-For", "")
    if forwarded:
        candidate = forwarded.split(",", 1)[0].strip()
        try:
            ipaddress.ip_address(candidate)
            return candidate
        except ValueError:
            pass
    return handler.client_address[0]


def rate_limit_ok(ip):
    now = time.time()
    with RATE_LOCK:
        q = RATE_LIMIT[ip]
        while q and now - q[0] > RATE_LIMIT_WINDOW:
            q.popleft()
        if len(q) >= RATE_LIMIT_MAX:
            return False
        q.append(now)
        return True


def valid_origin(origin):
    if not origin:
        # Aynı-origin bazı istemciler Origin göndermeyebilir.
        return True
    origin = origin.rstrip("/")
    if origin in ALLOWED_ORIGINS:
        return True

    # Uygulamanın kendi Render/custom domain origin'i otomatik olarak kabul edilir.
    external_url = os.environ.get("RENDER_EXTERNAL_URL", "").rstrip("/")
    if external_url and origin == external_url:
        return True

    return False


def validate_job_id(value):
    if not value or len(value) > MAX_JOB_ID_LEN:
        return None
    try:
        return str(uuid.UUID(value))
    except (ValueError, AttributeError, TypeError):
        return None


def validate_date(value):
    if not isinstance(value, str) or len(value) != MAX_DATE_LEN or not DATE_RE.fullmatch(value):
        raise ValueError("Geçersiz tarih.")
    try:
        datetime.strptime(value, "%Y-%m-%d")
    except ValueError:
        raise ValueError("Geçersiz tarih.")
    return value


def validate_credentials(username, password):
    if not isinstance(username, str) or not username or len(username) > MAX_USERNAME_LEN:
        raise ValueError("EPİAŞ e-posta adresi geçersiz.")
    if not EMAIL_RE.fullmatch(username):
        raise ValueError("EPİAŞ e-posta adresi geçersiz.")
    if not isinstance(password, str) or not password or len(password) > MAX_PASSWORD_LEN:
        raise ValueError("EPİAŞ şifresi geçersiz.")


def safe_json_load(handler):
    raw_length = handler.headers.get("Content-Length")
    try:
        length = int(raw_length or "0")
    except ValueError:
        raise ValueError("Geçersiz istek.")

    if length <= 0 or length > MAX_BODY_BYTES:
        raise ValueError("İstek boyutu geçersiz.")

    content_type = handler.headers.get("Content-Type", "").split(";", 1)[0].strip().lower()
    if content_type != "application/json":
        raise ValueError("İstek türü geçersiz.")

    raw = handler.rfile.read(length)
    if len(raw) != length:
        raise ValueError("İstek okunamadı.")

    try:
        data = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise ValueError("Geçersiz JSON.")

    if not isinstance(data, dict):
        raise ValueError("Geçersiz istek.")
    return data


# -----------------------------------------------------------------------------
# EPİAŞ
# -----------------------------------------------------------------------------

def get_tgt(username, password):
    response = requests.post(
        TGT_URL,
        data={"username": username, "password": password},
        headers={
            "Content-Type": "application/x-www-form-urlencoded",
            "Accept": "text/plain",
            "User-Agent": "SantralMatik-WEB/1.0",
        },
        timeout=(15, 30),
    )
    if response.status_code != 201:
        # EPİAŞ'ın hata gövdesini kullanıcıya vermiyoruz.
        raise RuntimeError("EPİAŞ giriş doğrulaması başarısız oldu.")
    tgt = response.text.strip()
    if not tgt or len(tgt) > 4096:
        raise RuntimeError("EPİAŞ giriş bileti alınamadı.")
    return tgt


def get_plants(tgt, session):
    response = session.get(
        BASE_URL + "/v1/generation/data/powerplant-list",
        headers={
            "TGT": tgt,
            "Accept": "application/json",
            "User-Agent": "SantralMatik-WEB/1.0",
        },
        timeout=(15, 60),
    )
    if response.status_code != 200:
        raise RuntimeError("EPİAŞ santral listesi alınamadı.")

    try:
        data = response.json()
    except ValueError:
        raise RuntimeError("EPİAŞ santral listesi okunamadı.")

    items = data.get("items") or []
    if not isinstance(items, list):
        raise RuntimeError("EPİAŞ santral listesi beklenmeyen formatta.")
    return [p for p in items if isinstance(p, dict) and p.get("id") is not None]


def get_generation(session, tgt, date_str, ids, group_no):
    url = BASE_URL + "/v1/generation/data/realtime-generation-bulk"
    body = {
        "date": date_str + "T00:00:00+03:00",
        "powerPlantIds": ids,
    }
    headers = {
        "TGT": tgt,
        "Content-Type": "application/json",
        "Accept": "application/json",
        "User-Agent": "SantralMatik-WEB/1.0",
    }

    last_error = None
    for attempt in range(1, 6):
        try:
            response = session.post(
                url,
                json=body,
                headers=headers,
                timeout=(15, 120),
            )
            if response.status_code == 200:
                return response

            last_error = response.status_code
            if response.status_code not in (403, 429, 500, 502, 503, 504):
                return response

        except (requests.exceptions.ConnectionError, requests.exceptions.Timeout):
            last_error = "timeout_or_connection"

        time.sleep(min(2 * attempt, 10))

    raise RuntimeError(f"EPİAŞ üretim grubu alınamadı: {group_no}.")


SOURCE_KEYS = [
    "wind", "sun", "dammedHydro", "river", "naturalGas", "lignite", "importCoal",
    "geothermal", "biomass", "fueloil", "asphaltiteCoal", "blackCoal",
    "naphta", "lng", "wasteheat"
]


def number(value):
    try:
        return float(value or 0)
    except (TypeError, ValueError):
        return 0.0


def classify_source(source_totals):
    """Santrali tek bir satıra göre değil, tüm günün kaynak toplamına göre sınıflandırır.

    Böylece özellikle güncel veride ilk satırın kaynak alanlarının boş/0 olması
    durumunda santral yanlışlıkla 'unknown' olarak kilitlenmez.
    """
    if not source_totals:
        return "unknown"
    best = max(SOURCE_KEYS, key=lambda key: source_totals.get(key, 0.0))
    return best if source_totals.get(best, 0.0) > 0 else "unknown"


def get_national_load(tgt, session):
    try:
        response = session.get(
            BASE_URL + "/v1/dashboard/realtime-consumption",
            headers={
                "TGT": tgt,
                "Accept": "application/json",
                "User-Agent": "SantralMatik-WEB/1.0",
            },
            timeout=(15, 30),
        )
        if response.status_code != 200:
            return {"value": None}

        data = response.json()
        items = data.get("items") or []
        if not items:
            return {"value": None, "latestUpdateTime": data.get("latestUpdateTime")}

        latest = items[-1]
        value = latest.get("consumption")
        if value is None:
            value = latest.get("value")

        return {
            "value": value,
            "date": latest.get("date"),
            "time": latest.get("time"),
            "latestUpdateTime": data.get("latestUpdateTime"),
        }
    except Exception:
        # Ulusal tüketim verisi ana harita için zorunlu değil.
        return {"value": None}


def fetch_epias(username, password, date_str, job_id):
    validate_date(date_str)
    validate_credentials(username, password)

    # Kimlik bilgileri yalnızca bu fonksiyon çağrısının yerel değişkenlerindedir.
    session = requests.Session()
    session.headers.update({"User-Agent": "SantralMatik-WEB/1.0"})
    tgt = None

    try:
        set_progress(job_id, 2, "EPİAŞ sunucusuna bağlanılıyor...", "Giriş bileti alınıyor...")
        tgt = get_tgt(username, password)

        set_progress(job_id, 8, "EPİAŞ bağlantısı kuruldu.", "Kimlik doğrulama tamamlandı.")
        set_progress(job_id, 12, "Santral listesi alınıyor...", "EPİAŞ santral listesi hazırlanıyor...")

        plants = get_plants(tgt, session)
        set_progress(job_id, 15, "Santral listesi hazır.", f"{len(plants)} santral bulundu.")

        all_rows = []
        batch_size = 50
        total_groups = max(1, (len(plants) + batch_size - 1) // batch_size)
        start_pct, end_pct = 15, 76

        for i in range(0, len(plants), batch_size):
            group_no = i // batch_size + 1
            ids = [p["id"] for p in plants[i:i + batch_size]]
            pct = start_pct + int((group_no - 1) / total_groups * (end_pct - start_pct))
            set_progress(
                job_id,
                pct,
                "Üretim verileri toplanıyor...",
                f"Santral grubu {group_no}/{total_groups} alınıyor...",
            )

            response = get_generation(session, tgt, date_str, ids, group_no)
            if response.status_code != 200:
                raise RuntimeError(f"EPİAŞ üretim verisi alınamadı. Grup {group_no}.")

            try:
                payload = response.json()
            except ValueError:
                raise RuntimeError(f"EPİAŞ üretim verisi okunamadı. Grup {group_no}.")

            rows = payload.get("items") or []
            if isinstance(rows, list):
                all_rows.extend(row for row in rows if isinstance(row, dict))

            completed_pct = start_pct + int(group_no / total_groups * (end_pct - start_pct))
            set_progress(
                job_id,
                completed_pct,
                "Üretim verileri toplanıyor...",
                f"{group_no}/{total_groups} santral grubu tamamlandı.",
            )
            time.sleep(0.5)

        set_progress(
            job_id,
            80,
            "Saatlik üretimler işleniyor...",
            "Üretim kayıtları santrallere göre birleştiriliyor...",
        )

        aggregate = {}
        source_totals = {}

        for row in all_rows:
            name = str(row.get("powerPlantName") or "").strip()
            if not name:
                continue

            hour = row.get("hour")
            try:
                hs = str(hour).strip()
                hour_num = int(hs.split(":", 1)[0]) if ":" in hs else int(float(hs))
                if hour_num == 24:
                    hour_num = 23
            except (TypeError, ValueError):
                continue

            if not 0 <= hour_num <= 23:
                continue

            total_value = number(row.get("total"))
            aggregate.setdefault(name, [0.0] * 24)[hour_num] += total_value

            totals = source_totals.setdefault(name, {key: 0.0 for key in SOURCE_KEYS})
            for key in SOURCE_KEYS:
                totals[key] += number(row.get(key))

        plants_out = []
        for name, hours in aggregate.items():
            source_sum = source_totals.get(name, {key: 0.0 for key in SOURCE_KEYS})
            clean_sources = {key: round(number(source_sum.get(key)), 6) for key in SOURCE_KEYS}
            plants_out.append({
                "name": name,
                "dailyTotal": round(sum(hours), 6),
                "hourly": [round(v, 6) for v in hours],
                "type": classify_source(source_sum),
                "sourceTotals": clean_sources,
            })

        set_progress(
            job_id,
            87,
            "Türkiye toplam üretimi hesaplanıyor...",
            f"{len(plants_out)} üretim kaydı hazırlandı.",
        )

        load = get_national_load(tgt, session)

        set_progress(
            job_id,
            94,
            "Harita verileri hazırlanıyor...",
            "Santral verileri harita ile eşleştiriliyor...",
        )

        result = {
            "date": date_str,
            "plantCount": len(plants_out),
            "plants": plants_out,
            "nationalLoad": load,
        }

        set_progress(job_id, 100, "Veriler hazır.", "EPİAŞ verileri başarıyla işlendi.")
        return result

    finally:
        # Python'da değişkeni silmek fiziksel belleği anında sıfırlama garantisi vermez;
        # fakat uygulamanın bu değerleri kalıcılaştırmasını ve sonraki isteklere taşımasını önler.
        tgt = None
        try:
            session.close()
        finally:
            gc.collect()


# -----------------------------------------------------------------------------
# HTTP sunucusu
# -----------------------------------------------------------------------------

class Handler(BaseHTTPRequestHandler):
    server_version = "SantralMatik/1.0"
    sys_version = ""

    def _headers(self, content_type=None):
        if content_type:
            self.send_header("Content-Type", content_type)
        self.send_header("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0")
        self.send_header("Pragma", "no-cache")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "SAMEORIGIN")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
        self.send_header("Cross-Origin-Opener-Policy", "same-origin")
        self.send_header("Cross-Origin-Resource-Policy", "same-origin")

    def _json(self, obj, status=200):
        body = json.dumps(obj, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        self.send_response(status)
        self._headers("application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _error(self, status, message):
        return self._json({"error": message}, status)

    def _origin_ok(self):
        origin = self.headers.get("Origin", "")
        return valid_origin(origin)

    def do_OPTIONS(self):
        if not self._origin_ok():
            return self._error(403, "İstek kaynağına izin verilmiyor.")

        self.send_response(204)
        self._headers()
        origin = self.headers.get("Origin", "")
        if origin:
            self.send_header("Access-Control-Allow-Origin", origin.rstrip("/"))
            self.send_header("Vary", "Origin")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.end_headers()

    def do_POST(self):
        parsed = urlparse(self.path)
        if parsed.path != "/api/epias":
            return self._error(404, "Bulunamadı.")

        if not self._origin_ok():
            return self._error(403, "İstek kaynağına izin verilmiyor.")

        client_ip = get_client_ip(self)
        if not rate_limit_ok(client_ip):
            return self._error(429, "Çok fazla istek gönderildi. Lütfen birkaç dakika sonra tekrar deneyin.")

        if not JOB_SEMAPHORE.acquire(blocking=False):
            return self._error(429, "Sunucu şu anda yoğun. Lütfen kısa süre sonra tekrar deneyin.")

        job_id = None
        username = None
        password = None

        try:
            data = safe_json_load(self)
            username = data.get("username")
            password = data.get("password")
            date_str = data.get("date")

            validate_credentials(username, password)
            validate_date(date_str)

            requested_job_id = validate_job_id(data.get("jobId"))
            job_id = requested_job_id or str(uuid.uuid4())

            set_progress(job_id, 0, "İşlem başlatılıyor...", "EPİAŞ bağlantısı hazırlanıyor...")
            result = fetch_epias(username, password, date_str, job_id)
            return self._json(result, 200)

        except ValueError as exc:
            if job_id:
                set_progress(job_id, 0, "İşlem başlatılamadı.", "Gönderilen bilgiler geçersiz.")
            return self._error(400, str(exc))

        except requests.RequestException:
            if job_id:
                set_progress(job_id, 0, "EPİAŞ bağlantısı kurulamadı.", "EPİAŞ sunucusuna ulaşılamadı.")
            return self._error(502, "EPİAŞ sunucusuna şu anda ulaşılamıyor.")

        except Exception:
            # Gerçek exception mesajını kullanıcıya göndermiyoruz. Böylece sunucu,
            # kütüphane, uzak API veya yapılandırma ayrıntısı sızdırmaz.
            if job_id:
                set_progress(job_id, 0, "Veri alınamadı.", "EPİAŞ verileri alınırken bir hata oluştu.")
            return self._error(500, "EPİAŞ verileri alınırken bir hata oluştu.")

        finally:
            username = None
            password = None
            JOB_SEMAPHORE.release()
            gc.collect()

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path

        if path == "/health":
            return self._json({"status": "ok", "service": "SantralMatik"})

        if path == "/api/epias-progress":
            if not self._origin_ok():
                return self._error(403, "İstek kaynağına izin verilmiyor.")

            job_id = validate_job_id(parse_qs(parsed.query).get("jobId", [""])[0])
            if not job_id:
                return self._error(400, "jobId gerekli.")
            return self._json(get_progress(job_id))

        if path in ("/", "/TRGRID_V3.html"):
            try:
                body = HTML_FILE.read_bytes()
            except OSError:
                return self._error(500, "Uygulama dosyası okunamadı.")

            self.send_response(200)
            self._headers("text/html; charset=utf-8")
            self.send_header(
                "Content-Security-Policy",
                "default-src 'self' https: data: blob:; "
                "script-src 'self' 'unsafe-inline' 'unsafe-eval' https:; "
                "style-src 'self' 'unsafe-inline' https:; "
                "img-src 'self' https: data: blob:; "
                "font-src 'self' https: data:; "
                "connect-src 'self' https:; "
                "frame-src 'self' https:; "
                "object-src 'none'; base-uri 'self'; form-action 'self';"
            )
            self.send_header("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return

        return self._error(404, "Bulunamadı.")

    def log_message(self, *_args):
        # Kullanıcı isteklerinin URL/header/body bilgileri loglanmaz.
        pass


if __name__ == "__main__":
    print(f"SantralMatik web sunucusu: http://{HOST}:{PORT}")
    server = ThreadingHTTPServer((HOST, PORT), Handler)
    server.daemon_threads = True
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nSunucu kapatıldı.")
    finally:
        server.server_close()
