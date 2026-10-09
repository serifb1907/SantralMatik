# SantralMatik güncellemesi

Bu paket üç dosyadan oluşur:

- `TRGRID_V3.html`: Yeni EPİAŞ durum kartı, bağlantı/ilerleme/hata göstergeleri ve küçültülmüş HTML.
- `trgrid_server_web.py`: `/health` ayrıntıları, logo için önbellekli statik rota, EPİAŞ kimlik doğrulama hatası ve oran sınırlama belleği temizliği.
- `santralmatik-logo.png`: HTML içindeki üç gömülü kopya yerine kullanılan ortak logo dosyası.

## GitHub / Render'a yükleme

1. GitHub deposundaki `TRGRID_V3.html` dosyasını paketteki dosyayla değiştirin.
2. `trgrid_server_web.py` dosyasını da pakettekiyle değiştirin.
3. `santralmatik-logo.png` dosyasını `trgrid_server_web.py` ile aynı dizine ekleyin.
4. Üç dosyayı commit edin ve Render dağıtımının tamamlanmasını bekleyin.
5. Siteyi açıp `Ctrl + F5` ile önbelleksiz yenileyin.
6. `/health` adresi `status: ok`, `activeJobs` ve `maxJobs` alanlarını göstermeli; `/santralmatik-logo.png` bir görsel döndürmeli.

Render ayarları değişmiyor: Build Command `pip install -r requirements.txt`, Start Command `python trgrid_server_web.py`.

## Notlar

- Durum kartındaki `KAYIT/EŞLEŞME` satırı, alınan üretim kayıt sayısı ile haritadaki eşleşme sayısını gösterir.
- `EPİAŞ SAATİ`, yanıtın `nationalLoad.latestUpdateTime` alanı varsa gösterilir; bu alan yoksa `--` görünür.
- Frekans HUD'u gerçek ölçüm değil, görsel simülasyon olarak açıkça etiketlenir.
- Bu paket canlı EPİAŞ hesabıyla her santralin her tarih için değerini doğrulamaz. Kod ve yerel sunucu uçları kontrol edilmiştir.
