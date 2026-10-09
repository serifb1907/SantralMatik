# SantralMatik güncellemesi

Bu pakette şu dosyalar bulunur:
- `TRGRID_V3.html`
- `trgrid_server_web.py`
- `santralmatik-logo.png`

## Kurulum
1. Bu üç dosyayı GitHub deposunda aynı klasöre yükleyin/değiştirin.
2. Commit edin ve Render dağıtımının bitmesini bekleyin.
3. Siteyi bilgisayarda `Ctrl+F5` ile yenileyin.
4. Sunucu durumunu test etmek için sitenin sonuna `/api/status` ekleyin. JSON içinde `"status":"ok"` görülmelidir.

## Yapılan değişiklikler
- İşlem süresi duvar saati (`Date.now`) ile ölçülür; yükleme sırasında her saniye güncellenir ve işlem bitince gerçek toplam sürede sabitlenir.
- Durum kartı sunucu kontrolünde `/health` yerine `/api/status` kullanır. Sunucu eski `/health` adresini de desteklemeye devam eder.
- Diğer uygulama davranışları mümkün olduğunca korunmuştur.
