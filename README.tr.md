# vncshot

[English](README.md) | [Türkçe](README.tr.md)

VNC güvenlik envanteri tarayıcısı. RFB/VNC uç noktalarını keşfeder,
parolasız ve zayıf parolalı sunucuları işaretler ve yetkili güvenlik
değerlendirmeleri için o anki framebuffer'ı PNG kanıt görüntüsü olarak
kaydeder.

`vncshot` yalnızca Linux üzerinde çalışır ve root yetkisi gerektirir.

```
Bu aracı yalnızca sahibi olduğunuz veya yazılı izniniz olan ağlarda kullanın.
```

## Geliştirici

**Cuma KURT**
- E-posta: [cumakurt@gmail.com](mailto:cumakurt@gmail.com)
- LinkedIn: [cuma-kurt-34414917](https://www.linkedin.com/in/cuma-kurt-34414917/)
- GitHub: [cumakurt/vncshot](https://github.com/cumakurt/vncshot)

## Özellikler

- Yalnızca Linux; hem CLI hem GUI root olarak çalışmalıdır
- Tek IP, CIDR bloğu, IPv4 aralığı veya hedef dosyası ile tarama
- Yapılandırılabilir hız sınırı (rate limit) ile eşzamanlı worker pool
- RFB 3.3 / 3.7 / 3.8 handshake, parolasız (`None`) ve zayıf parola tespiti
- Parolasız ve zayıf parolalı uç noktalar için framebuffer → PNG yakalama
- Salt okunur sorgulama: tek kare istenir ve oturum kapatılır
- JSON + kendi içinde çalışan HTML rapor (base64 thumbnail, filtre, modal)
- Süreç içi PDF rapor dışa aktarımı (harici araç gerekmez)
- Tüm CLI seçeneklerini, canlı ilerlemeyi ve rapor bağlantılarını sunan yerel web GUI (`-gui`)
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

`install.sh` Linux dağıtımının paket yöneticisini (apt, dnf, yum, pacman,
apk, zypper) algılar; yalnızca eksik olan araçları kurar ve **statik
bağlanmış** (statically linked) bir Linux ikilisi üretir. Desteklenmeyen bir
işletim sisteminde çalışmayı reddeder. Varsayılan olarak ikili dosyayı
`/usr/local/bin/vncshot` altına da kurar (gerekirse `sudo` kullanır); böylece
her dizinden `vncshot` olarak çalıştırılabilir. Farklı bir konum için
`INSTALL_PREFIX` kullanılabilir.

Kurulum ayrıca tarama çıktılarının kök dizini olan `/usr/local/vncshot`
dizinini oluşturur. İki konum da ortam değişkenleriyle değiştirilebilir:

```bash
INSTALL_PREFIX="$HOME/.local/bin" REPORT_DIR="$HOME/vncshot" ./install.sh -y
```

Rapor kök dizini derleme sırasında ikilinin içine gömülür; böylece kurulu
ikili ile dizin yapısı her zaman tutarlı kalır. Derleme için gereken Go
toolchain dışında çalışma zamanı harici bağımlılık yoktur.

## Yetkiler

`vncshot` hem CLI hem GUI modunda root yetkisi olmadan çalışmayı reddeder:

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
sudo vncshot -target 192.168.1.0/24 -word-list /root/parolalar.txt
sudo vncshot -gui
```

Parametresiz çalıştırıldığında yalnızca kullanım metni yazdırılır ve tarama
başlatılmaz.

| Bayrak | Varsayılan | Açıklama |
|--------|------------|----------|
| `-target` | | Tek IP, CIDR veya aralık (`192.168.1.1`, `192.168.1.0/24`, `192.168.1.1-50`) |
| `-file` | | Satır başına bir IP/CIDR/aralık içeren dosya (`#` yorum satırı desteklenir) |
| `-ports` | `5900` | Port listesi/aralıkları (`5900,5901-5910`) |
| `-timeout` | `1s` | TCP bağlantı zaman aşımı |
| `-vnc-timeout` | `15s` | RFB handshake/yakalama zaman aşımı |
| `-workers` | `150` | Eşzamanlı tarama worker sayısı |
| `-rate` | `200` | Saniyede en fazla yeni bağlantı (`0` = sınırsız) |
| `-out-dir` | `/usr/local/vncshot` | Zaman damgalı tarama klasörlerinin kök dizini |
| `-output` | `<run-dir>/vncshot_report.json` | JSON rapor yolu |
| `-html` | `<run-dir>/vncshot_report.html` | HTML rapor yolu |
| `-pdf` | `<run-dir>/vncshot_report.pdf` | PDF rapor yolu (süreç içinde üretilir) |
| `-no-pdf` | `false` | PDF üretimini atla |
| `-screenshot-dir` | `<run-dir>/screenshots` | PNG yakalamaların kaydedileceği dizin |
| `-shared` | `true` | Paylaşımlı RFB oturumu iste (aktif izleyicileri düşürmez) |
| `-word-list` | | Satır başına bir ek parola adayı içeren dosya (`#` yorumları ve boş satırlar yok sayılır, en fazla 500 kayıt) |
| `-no-default-passwords` | `false` | Yerleşik zayıf parola listesini denemeyi atla |
| `-no-password-check` | `false` | Hiçbir parola deneme; yalnızca parolasız sunucuları raporla |
| `-yes` | `false` | Etkileşimli yetki onayını atla |
| `-gui` | `false` | CLI taraması yerine yerel web GUI'yi başlat |
| `-gui-host` | `127.0.0.1` | GUI dinleme adresi (yalnızca loopback) |
| `-gui-port` | `0` | GUI dinleme portu (`0` = boş port seç) |
| `-gui-no-browser` | `false` | GUI'yi tarayıcıda otomatik açma |

`-gui-*` bayrakları yalnızca `-gui` ile birlikte geçerlidir.

## Parola testi

Parola testi varsayılan olarak açıktır. Her RFB uç noktası için önce, sunucunun
sunduğu güvenlik tiplerini kimlik bilgisi göndermeden okuyan bir keşif
bağlantısı kurulur:

* Sunucu `None` güvenlik tipini sunuyorsa uç nokta parolasız olarak raporlanır
  ve framebuffer'ı yakalanır.
* Sunucu VNC kimlik doğrulaması istiyorsa her parola adayı kendi kısa ömürlü
  bağlantısında denenir. Kabul edilen ilk parola kaydedilir ve uç nokta tıpkı
  parolasız bir sunucu gibi yakalanır.
* Yalnızca başka güvenlik tipleri (örneğin TLS veya VeNCrypt) sunan sunucular,
  parola denenmeden RFB servisi olarak raporlanır.

Adaylar yerleşik zayıf parola listesinden (boş parola dahil yaklaşık 30 yaygın
VNC parolası) ve isteğe bağlı olarak `-word-list` dosyasından gelir.
`-no-default-passwords` yerleşik listeyi kaldırır, `-no-password-check` ise
deneme aşamasını tamamen atlar; böylece yalnızca parolasız sunucular raporlanır.
Keşif bağlantısı hiçbir zaman parola göndermediği için kapsam dışı bir sunucu
yalnızca tarandı diye parola denemesine maruz kalmaz.

### Tasarım gereği salt okunur

Başarılı bir girişten sonra (parolasız veya zayıf parola) istemci yalnızca
`SetPixelFormat`, `SetEncodings` ve tek bir `FramebufferUpdateRequest` mesajı
gönderir, tam olarak bir framebuffer güncellemesi okur ve bağlantıyı kapatır.
Klavye veya fare girdisi, pano (clipboard) verisi ya da kontrol mesajı asla
göndermez, sürekli güncelleme istemez ve uzak masaüstünde hiçbir değişiklik
yapmaz. Yakalama, o anki ekranın bir anlık görüntüsüdür.

### Aday sınırları

* Her aday yeni bir bağlantı kullanır; aynı sunucuyu arka arkaya denemek için
  bir oturum asla yeniden kullanılmaz.
* `SecurityResult` durumunun `2` olması (çok fazla deneme / kilitlenme) o sunucu
  için kalan adayları durdurur; durum JSON raporda `auth_locked`, HTML/PDF
  raporlarda ise "locked out" etiketiyle kaydedilir.
* Yerleşik liste, envanter taramasının dikkat çekmemesi için bilinçli olarak
  küçüktür.
* `-word-list` en fazla 500 kayıt kabul eder; yol yoksa veya bir dizini
  gösteriyorsa reddedilir.

### Hassas çıktıların işlenmesi

Raporlar zayıf parolaları, ekran görüntüleri ise yakalanmış masaüstlerini
içerir. Tarama dizinleri `0700`, ekran görüntüleri `0600`, JSON, HTML ve PDF
raporları `0600` izinleriyle oluşturulur; yani yalnızca dosya sahibi okuyabilir.
Bir tarama dizinini hassas kanıt olarak değerlendirin: paylaşımlı depolamaya
kopyalamayın ve redaksiyon yapmadan bir kayda (ticket) eklemeyin.

## GUI

```bash
sudo vncshot -gui
```

Bu komut loopback üzerinde yerel bir web arayüzü başlatır ve oturum URL'sini
terminale yazdırır. Form tüm CLI seçeneklerini sunar: hedef veya hedef dosyası,
portlar, worker sayısı, hız, bağlantı ve RFB zaman aşımları, rapor kök dizini,
JSON/HTML/PDF yol geçersiz kılmaları, ekran görüntüsü dizini, PDF atlama ve
paylaşımlı oturum.

"Passwords" paneli word list yolunu ve iki atlama seçeneğini (yerleşik zayıf
parola listesi, parola testi) sunar. Durum satırı geçerli taramanın kaç parola
adayı deneyeceğini gösterir; bulgular tablosu zayıf parola ile erişilen
sunucuları işaretler.

Tarama, yetki onay kutusu işaretlenmeden başlatılamaz; bu, `-yes` bayrağının
GUI karşılığıdır. İlerleme, sayaçlar, bulgular ve ekran görüntüleri
Server-Sent Events üzerinden canlı güncellenir. Çalışan bir tarama iptal
edilebilir; tamamlanan tarama HTML, PDF ve JSON çıktılarına bağlantı verir.

Güvenlik özellikleri:

* Loopback dışı bir `-gui-host` değeri başlangıçta reddedilir.
* Her başlatmada 24 baytlık rastgele bir oturum belirteci üretilir. Belirteç
  bir kez URL sorgu parametresi olarak verilir, HttpOnly ve SameSite=Strict
  bir çerezde saklanır; durum değiştiren isteklerde ayrıca `X-Vncshot-Token`
  başlığıyla gönderilmelidir.
* `/files/` uç noktası yalnızca geçerli tarama klasörü içindeki dosyaları sunar.
* GUI de root olarak çalışır; yazdırılan URL'ye erişen herkes tarayıcıyı
  yönetebilir. URL ve belirteci kimlik bilgisi olarak değerlendirin.
* Uzak erişim için loopback bağlamasını koruyup portu SSH üzerinden yönlendirin
  (`ssh -L 8080:127.0.0.1:<port> ...`); portu herkese açık bir arayüze
  bağlamayın.

Portu sabitlemek için `-gui-port`, otomatik `xdg-open` çağrısını kapatmak için
`-gui-no-browser` kullanılabilir.

## Çıktılar

Her tarama `-out-dir` altında kendi zaman damgalı klasörüne yazılır;
taramalar birbirinin üzerine yazmaz. Varsayılan olan `/usr/local/vncshot`
`install.sh` tarafından derleme sırasında ikilinin içine gömülür ve aynı
betik bu dizini oluşturur:

```
/usr/local/vncshot/20261026-205304/
├── screenshots/{ip}_{port}_{timestamp}.png
├── vncshot_report.json
├── vncshot_report.html
└── vncshot_report.pdf
```

* `screenshots/` — parolasız ve zayıf parolalı sunucuların ekran görüntüleri
* `vncshot_report.json` — tüm sonuç kümesi
* `vncshot_report.html` — kendi içinde çalışan rapor (gömülü thumbnail, filtre, modal)
* `vncshot_report.pdf` — tarama sonuçlarından süreç içinde üretilen PDF rapor

JSON raporundaki her sonuç, zayıf bir parola kabul edildiğinde `password` ve
`password_source` (`default` veya `word-list`) alanlarını taşır; özette ayrıca
`weak_credentials` sayacı bulunur. HTML ve PDF raporları aynı sayacı "Weak creds"
istatistiği olarak gösterir ve parolayı kaynağıyla birlikte bulgu kartlarında ve
uç nokta tablosunda sunar.

Bir tarama dizini parola ve yakalanmış masaüstü içerdiği için `0700` izniyle,
her ekran görüntüsü ve rapor dosyası ise `0600` izniyle oluşturulur.

`-output`, `-html`, `-pdf` ve `-screenshot-dir` için verilen göreli yollar
tarama klasörü içinde çözümlenir; mutlak yollar olduğu gibi kullanılır.
Derlemeye gömülü varsayılan dizin yazılabilir değilse tarama
`~/.local/share/vncshot` altına düşer; açıkça verilen `-out-dir` ise her
zaman olduğu gibi kullanılır.

HTML ve PDF raporları açık renkli "technical dossier" temasını kullanır. PDF,
Türkçe ve diğer ASCII dışı karakterlerin doğru görüntülenmesi için Liberation
Sans yazı tipini (SIL Open Font License) gömer.

## Paket yapısı

```
main.go        CLI bayrakları, root denetimi, GUI başlatma
app/           CLI ve GUI'nin paylaştığı tarama oturumu ve çıktı düzeni
gui/           gömülü web arayüzü (index.html + HTTP sunucusu)
scanner/       hedef genişletme, worker pool, rate limit
vnc/           RFB 3.3/3.7/3.8 istemcisi, None-auth ve zayıf parola kimlik doğrulaması, raw yakalama
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

## Yasal Uyarı / Kullanım Şartları

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