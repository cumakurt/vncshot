# vncshot

[English](README.md) | [Türkçe](README.tr.md)

VNC güvenlik envanteri tarayıcısı. RFB/VNC uç noktalarını keşfeder,
parolasız sunucuları işaretler ve yetkili güvenlik değerlendirmeleri için
o anki framebuffer'ı PNG kanıt görüntüsü olarak kaydeder.

```
Bu aracı yalnızca sahibi olduğunuz veya yazılı izniniz olan ağlarda kullanın.
```

## Geliştirici

**Cuma KURT**
- E-posta: [cumakurt@gmail.com](mailto:cumakurt@gmail.com)
- LinkedIn: [cuma-kurt-34414917](https://www.linkedin.com/in/cuma-kurt-34414917/)
- GitHub: [cumakurt/vncshot](https://github.com/cumakurt/vncshot)

## Özellikler

- Tek IP, CIDR bloğu, IPv4 aralığı veya hedef dosyası ile tarama
- Yapılandırılabilir hız sınırı (rate limit) ile eşzamanlı worker pool
- RFB 3.3 / 3.7 / 3.8 handshake ve parolasız (`None`) tespiti
- Kimlik doğrulaması istemeyen uç noktalar için framebuffer → PNG yakalama
- JSON + kendi içinde çalışan HTML rapor (base64 thumbnail, filtre, modal)
- Süreç içi PDF rapor dışa aktarımı (harici araç gerekmez)
- Kısmi sonuçlarla birlikte zarif Ctrl+C kapanışı

## Derleme

```bash
# tek adımda önyükleme + statik derleme + /usr/local/bin kurulumu
./install.sh

# veya doğrudan derle
go build -o vncshot .

# install.sh seçenekleri
./install.sh -y               # etkileşimsiz
./install.sh --build-only     # bağımlılık kurulumunu atla
./install.sh --no-install-bin # sadece derle, sisteme kurma
```

`install.sh` işletim sistemini ve paket yöneticisini (apt, dnf, yum,
pacman, apk, zypper, brew) algılar; yalnızca eksik olan araçları kurar ve
**statik bağlanmış** (statically linked) bir ikili üretir. Varsayılan olarak
ikili dosyayı `/usr/local/bin/vncshot` altına da kurar (gerekirse `sudo`
kullanır); böylece her dizinden `vncshot` olarak çalıştırılabilir. Farklı bir
konum için `INSTALL_PREFIX` kullanılabilir.

Kurulum ayrıca tarama çıktılarının kök dizini olan `/usr/local/vncshot`
dizinini oluşturur. İki konum da ortam değişkenleriyle değiştirilebilir:

```bash
INSTALL_PREFIX="$HOME/.local/bin" REPORT_DIR="$HOME/vncshot" ./install.sh -y
```

Rapor kök dizini derleme sırasında ikilinin içine gömülür; böylece kurulu
ikili ile dizin yapısı her zaman tutarlı kalır. Derleme için gereken Go
toolchain dışında çalışma zamanı harici bağımlılık yoktur.

## Yetkiler

`vncshot` root yetkisi olmadan çalışmayı reddeder:

```bash
sudo vncshot -target 192.168.1.0/24
```

Bu kontrol uygulama başlarken yapılır; yarım çalışan bir tarama yerine
aksiyon alınabilir bir hata ile çıkılır.

## Kullanım

```bash
sudo vncshot -target 192.168.1.0/24 -ports 5900,5901-5910
sudo vncshot -file hosts.txt -workers 100 -rate 150 -timeout 800ms
sudo vncshot -target 10.0.0.1-50 -out-dir /root/assessments
```

Parametresiz çalıştırıldığında yalnızca kullanım metni (yasal uyarı olmadan)
yazdırılır ve tarama başlatılmaz.

| Bayrak | Varsayılan | Açıklama |
|--------|------------|----------|
| `-target` | | Tek IP, CIDR veya aralık (`192.168.1.1`, `192.168.1.0/24`, `192.168.1.1-50`) |
| `-file` | | Satır başına bir IP/CIDR/aralık içeren dosya (`#` yorum satırı desteklenir) |
| `-ports` | `5900` | Port listesi/aralıkları (`5900,5901-5910`) |
| `-timeout` | `1s` | TCP bağlantı zaman aşımı |
| `-vnc-timeout` | `15s` | Toplam RFB handshake/yakalama bütçesi |
| `-workers` | `150` | Eşzamanlı tarama worker sayısı |
| `-rate` | `200` | Saniyede en fazla yeni bağlantı (`0` = sınırsız) |
| `-out-dir` | `/usr/local/vncshot` | Zaman damgalı tarama klasörlerinin kök dizini |
| `-output` | `<run-dir>/vncshot_report.json` | JSON rapor yolu |
| `-html` | `<run-dir>/vncshot_report.html` | HTML rapor yolu |
| `-pdf` | `<run-dir>/vncshot_report.pdf` | PDF rapor yolu (süreç içinde üretilir) |
| `-no-pdf` | `false` | PDF üretimini atla |
| `-screenshot-dir` | `<run-dir>/screenshots` | PNG yakalamaların kaydedileceği dizin |
| `-shared` | `true` | Paylaşımlı RFB oturumu iste (aktif izleyicileri düşürmez) |
| `-yes` | `false` | Etkileşimli yetki onayını atla |

## Çıktılar

Her tarama kendi zaman damgalı klasörüne yazılır; taramalar birbirinin
üzerine yazmaz:

```
/usr/local/vncshot/20261026-205304/
├── screenshots/{ip}_{port}_{timestamp}.png
├── vncshot_report.json
├── vncshot_report.html
└── vncshot_report.pdf
```

* `screenshots/` — parolasız sunucuların ekran görüntüleri
* `vncshot_report.json` — tüm sonuç kümesi
* `vncshot_report.html` — kendi içinde çalışan rapor (gömülü thumbnail, filtre, modal)
* `vncshot_report.pdf` — tarama sonuçlarından süreç içinde üretilen PDF rapor

`-output`, `-html`, `-pdf` ve `-screenshot-dir` için verilen göreli yollar
tarama klasörü içinde çözümlenir; mutlak yollar olduğu gibi kullanılır.

## Paket yapısı

```
main.go        CLI bağlantısı, root denetimi, rapor dizini yönetimi
scanner/       hedef genişletme, worker pool, rate limit
vnc/           RFB 3.3/3.7/3.8 istemcisi, None-auth tespiti, raw yakalama
screenshot/    PNG kaydetme
report/        Result modeli, JSON/HTML/PDF dışa aktarıcıları
```

## Bağımlılıklar

| Modül | Amaç |
|-------|------|
| `github.com/go-pdf/fpdf` | PDF rapor üretimi |
| `github.com/schollz/progressbar/v3` | Terminal ilerleme çubuğu |

Diğer her şey Go standart kütüphanesini kullanır.

## Geliştirme

```bash
go test ./...          # birim + entegrasyon testleri
go vet ./...
gofmt -l .
```

## Yasal Uyaru / Kullanım Şartları

**Yalnızca yetkili kullanım.** Bu yazılım yalnızca yetkili güvenlik
testleri, savunma amaçlı araştırma ve eğitim amacıyla yayımlanmıştır.
Yalnızca sahibi olduğunuz ya da açık yazılı yetkiniz bulunan ağ ve
sistemleri tarayabilirsiniz.

Yetkisiz erişim veya dinleme, çoğu yargı alanında suç teşkil eder.
Kullanımınızın tüm yürürlükteki yerel, ulusal ve uluslararası mevzuata
uygun olduğunu sağlamak **yalnızca sizin sorumluluğunuzdadır**.

**Geliştiricinin sorumluluğu reddedilir.** Geliştirici (**Cuma KURT**),
yazılımın kullanımından, kötüye kullanımından, kullanılamamasından ya da
güvenilmesinden doğabilecek hiçbir zarar, veri kaybı, kâr kaybı, iş
kesintisi, hukuki talep, idari ya da cezai yaptırım, para cezası veya
doğrudan/dolaylı/sonuçsal hiçbir sorumluluk için **hiçbir koşulda** ve
yürürlükteki mevzuatın izin verdiği azami ölçüde **sorumlu tutulamaz** —
böyle bir zarar olasılığı kendisine bildirilmiş olsa dahi.

**Garanti verilmez.** YAZILIM "OLDUĞU GİBİ", AÇIK VEYA ZIMNİ HİÇBİR
GARANTİ OLMAKSIZIN SUNULMUŞTUR; SATILABİLİRLİK, BELİRLİ BİR AMACA
UYGUNLUK VE İHLAL ETMEME GARANTİLERİ DAHİL ANCAK BUNLARLA SINIRLI
OLMAMAK ÜZERE HİÇBİR GARANTİ VERMEZ. YAZILIMIN KALİTESİ VE PERFORMANSI
İLE İLGİLİ TÜM RİSK SİZE AİTTİR.

Aracı çalıştırarak bu beyanı okuduğunuzu, anladığınızı ve kabul
ettiğinizi beyan etmiş sayılırsınız.

## Lisans

GNU General Public License v3.0 — bkz. [LICENSE](LICENSE).

Copyright (C) 2026 Cuma KURT

Bu program özgür yazılımdır: Yazılımı Özgür Yazılım Vakfı tarafından
yayımlanan GNU Genel Kamu Lisansı sürüm 3 veya (isteğinize bağlı olarak)
daha sonraki herhangi bir sürüm koşulları altında yeniden dağıtabilir
ve/veya değiştirebilirsiniz.

Sorumlu ve yalnızca yetki dahilinde kullanın.