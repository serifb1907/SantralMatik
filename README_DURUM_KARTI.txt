SantralMatik güncellemesi: durum kartı

GitHub deposunda aynı klasörde şu üç dosya bulunmalı:
- TRGRID_V3.html
- trgrid_server_web.py
- santralmatik-logo.png

Üçünü de güncelleyin/yükleyin ve commit edin. Render dağıtımı tamamlandıktan sonra siteyi Ctrl+F5 ile yenileyin.

Durum kartı artık harita, liste, santral ayrıntısı ve giriş ekranında görünür. İşlem süresi veri çekilirken saniye saniye artar; işlem bittiğinde son işlemin toplam süresinde sabit kalır. SUNUCU satırı SantralMatik sunucusunun /health uç noktasını kontrol eder. HTTP hata kodu varsa onu gösterir; bağlantı kurulamıyorsa API YANIT YOK yazar.
