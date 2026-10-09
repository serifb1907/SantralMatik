# SantralMatik durum kartı güncellemesi

Paket içeriği:
- `TRGRID_V3.html`: Durum kartı tüm ekranlarda görünür; sunucu kontrolü hata ayrıntısını daha anlaşılır gösterir.
- `trgrid_server_web.py`: `/health` uç noktası ve statik logo servisi.
- `santralmatik-logo.png`: Ortak logo dosyası.

## Kurulum
1. Bu üç dosyayı GitHub deposunda aynı klasöre yükleyin/değiştirin.
2. `trgrid_server_web.py` ve `TRGRID_V3.html` aynı klasörde kalmalı; logo da aynı klasörde bulunmalı.
3. Commit edin ve Render dağıtımının tamamlanmasını bekleyin.
4. Bilgisayarda siteyi `Ctrl+F5` ile yenileyin.
5. Aynı tarayıcıda `https://SİTENİZ/health` adresini açın. `{"status":"ok"...}` benzeri JSON yanıtı gelirse sunucu sağlık kontrolü çalışıyordur.

## Durum satırı
- `182 ms`: Uygulama sunucusunun sağlık kontrolüne yanıt süresi.
- `0/3 iş`: Şu anda çalışan istek sayısı / izin verilen eşzamanlı iş kapasitesi.
- `HTTP 404` gibi bir değer: Sunucunun sağlık kontrolüne verdiği HTTP yanıt kodu.
- `KONTROL EDİLEMEDİ` veya `YANIT GECİKTİ`: Tarayıcı sağlık kontrolünü alamamıştır; bu tek başına EPİAŞ bağlantısının bozuk olduğunu göstermez.
