# vncshot

[English](README.md) | [Türkçe](README.tr.md)

VNC güvenlik envanteri tarayıcısı. RFB/VNC uç noktalarını keşfeder, parolasız
ve zayıf parolalı sunucuları işaretler ve yetkili güvenlik değerlendirmeleri
için güncel ekran görüntüsünü PNG kanıtı olarak kaydeder.

`vncshot` yalnızca Linux üzerinde çalışır ve root yetkisi gerektirir.

```
Yalnızca sahibi olduğunuz veya açık yazılı izniniz bulunan ağlarda kullanın.
```

![vncshot GUI panosu](docs/screenshots/gui-dashboard.png)

*Yerel GUI: canlı sayaçlar, taşıma sütunu, yakalanan kareler ve önceki tarama
geçmişi; tümü loopback üzerinde.*

## İçindekiler

- [Geliştirici](#geliştirici)
- [Özellikler](#özellikler)
- [Gereksinimler](#gereksinimler)
- [Hızlı başlangıç](#hızlı-başlangıç)
- [Derleme ve kurulum](#derleme-ve-kurulum)
- [Yetkiler](#yetkiler)
- [Kullanım](#kullanım)
  - [Yapılandırma ve öncelik](#yapılandırma-ve-öncelik)
- [Parola testi](#parola-testi)
  - [Tasarım gereği salt okunur](#tasarım-gereği-salt-okunur)
  - [Aday sınırları](#aday-sınırları)
  - [Hassas çıktıların işlenmesi](#hassas-çıktıların-işlenmesi)
- [Bağlantı ve taşıma katmanı](#bağlantı-ve-taşıma-katmanı)
  - [Güvenlik tipleri ve TLS](#güvenlik-tipleri-ve-tls)
  - [Yeniden deneme ve hedef başına sınırlar](#yeniden-deneme-ve-hedef-başına-sınırlar)
- [Tarama nasıl çalışır](#tarama-nasıl-çalışır)
  - [Hedef genişletme](#hedef-genişletme)
  - [Sondalama hattı](#sondalama-hattı)
- [GUI](#gui)
  - [GUI HTTP API](#gui-http-api)
- [Çıktılar](#çıktılar)
  - [JSON şeması](#json-şeması)
  - [CSV biçimi](#csv-biçimi)
  - [Manifest dosyası](#manifest-dosyası)
  - [Temel karşılaştırma](#temel-karşılaştırma)
  - [Webhook bildirimleri](#webhook-bildirimleri)
- [Çıkış kodları](#çıkış-kodları)
- [Performans ayarı](#performans-ayarı)
- [Sorun giderme](#sorun-giderme)
- [Paket yapısı](#paket-yapısı)
- [Bağımlılıklar](#bağımlılıklar)
- [Geliştirme](#geliştirme)
- [Yasal Uyarı / Kullanım Şartları](#yasal-uyarı--kullanım-şartları)
- [Lisans](#lisans)

## Geliştirici

**Cuma KURT**
- E-posta: [cumakurt@gmail.com](mailto:cumakurt@gmail.com)
- LinkedIn: [cuma-kurt-34414917](https://www.linkedin.com/in/cuma-kurt-34414917/)
- GitHub: [cumakurt/vncshot](https://github.com/cumakurt/vncshot)

## Özellikler

- Yalnızca Linux; hem CLI hem GUI root olarak çalışmalıdır
- Tek IP, CIDR bloğu, IPv4 aralığı veya hedef dosyası tarama
- Yapılandırılabilir hız sınırı ve hedef başına eşzamanlılık sınırı olan
  eşzamanlı worker havuzu
- RFB 3.3 / 3.7 / 3.8 el sıkışması, parolasız (`None`) tespiti ve
  zayıf parola tespiti
- Parolasız ve zayıf parolalı uç noktalar için PNG'ye ekran görüntüsü
- Salt okunur sondalama: tek kare istenir ve oturum kapatılır
- JSON + kendi kendine yeten HTML raporu (gömülü küçük görseller, filtre, modal)
- Süreç içinde PDF raporu (harici araç gerekmez)
- Elektronik tablolar ve ardışık düzenler için sabit sütun düzenli CSV çıktısı
- Güvenlik tipi envanteri: her bulgu duyurulan `security_types` listesini ve
  `tls` bayrağını kaydeder
- Önceki taramayla temel karşılaştırma (yeni, çözülen ve değişen bulgular)
- Delil bütünlüğü için her çıktının SHA-256 manifesti (`-manifest`)
- Yeni bulgu veya açık uç nokta varsa isteğe bağlı webhook bildirimi
- Yapılandırma dosyası (`-config`) ve `VNCSHOT_*` ortam değişkenlerinden
  bayrak varsayılanları
- Tekrarlanan taramaların doğrudan karşılaştırılabilmesi için deterministik,
  sıralı sonuçlar
- Hedef başına tek TCP bağlantısı ve sınırlı eşzamanlılık
- Canlı ilerleme, rapor bağlantıları ve önceki tarama geçmişi olan yerel web
  GUI'si (`-gui`)
- `-version` root gerektirmeden derleme bilgisini yazdırır
- Ctrl+C ile kısmi sonuçlarla düzgün kapanış

## Gereksinimler

| Alan | Gereksinim |
|------|------------|
| İşletim sistemi | Linux (ikili dosya ve `install.sh` diğer sistemleri reddeder) |
| Yetki | CLI ve GUI taramaları için doğrudan veya `sudo` ile root |
| Derleme araç zinciri | Yalnızca kaynaktan derlerken Go 1.22 veya üzeri |
| Çalışma zamanı | Yok; ikili dosya statik bağlanmıştır |
| Ağ | Taranan VNC portlarına TCP erişimi |

Aracın masaüstü ortamına, X11'e, tarayıcıya veya harici yardımcı programa
çalışma zamanı bağımlılığı yoktur. GUI yerel bir web sayfasıdır; `xdg-open`
yalnızca tarayıcıyı otomatik açmak için kullanılır (`-gui-no-browser` bunu
kapatır).

## Hızlı başlangıç

```bash
# 1. Derle ve kur (tarama çıktısı için /usr/local/vncshot oluşturulur)
git clone https://github.com/cumakurt/vncshot.git
cd vncshot
./install.sh

# 2. İkili dosyayı doğrula ve seçenekleri incele
vncshot -version
vncshot -h

# 3. Yetkili bir aralığı tara ve kanıt topla
sudo vncshot -target 192.168.1.0/24 -ports 5900,5901-5910

# 4. Oluşan raporu aç
sudo find /usr/local/vncshot -name vncshot_report.html
```

Her tarama kendi zaman damgalı klasörüne yazılır; ardışık taramalar birbirinin
üzerine yazmaz. Terminal özeti tam yolları en sonda yazdırır.

## Derleme ve kurulum

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

`install.sh` Linux dağıtımının paket yöneticisini (apt, dnf, yum, pacman, apk,
zypper) algılar, yalnızca eksik araçları kurar ve **statik bağlanmış**,
simgelerinden arındırılmış bir Linux ikilisi üretir. Başka bir işletim
sisteminde çalışmayı reddeder. Varsayılan olarak ayrıca:

* ikili dosyayı `/usr/local/bin/vncshot` altına kurar (gerekirse `sudo`
  kullanır); böylece her dizinden çalıştırılabilir, ve
* tarama çıktılarının kök dizini olan `/usr/local/vncshot` dizinini oluşturur.

İki konum da `INSTALL_PREFIX` ve `REPORT_DIR` ile değiştirilebilir:

```bash
INSTALL_PREFIX="$HOME/.local/bin" REPORT_DIR="$HOME/vncshot" ./install.sh -y
```

`GO_VERSION` uygun bir araç zinciri yokken indirilecek Go sürümünü sabitler;
`VERSION` ise ikiliye gömülen ve `-version` ile yazdırılan sürüm dizesini
belirler. Rapor kök dizini ikilinin içine gömülür; bu sayede kurulu ikili ile
kurulu dizin her zaman tutarlı kalır. Derleme için gereken Go araç zinciri
dışında çalışma zamanı harici bağımlılık yoktur.

### Kaldırma

```bash
sudo rm -f /usr/local/bin/vncshot
sudo rm -rf /usr/local/vncshot     # tüm raporları ve ekran görüntülerini siler
```

`install.sh` tarafından indirilen önbellekteki Go arşivini de silmek için
`~/.cache/vncshot-install` dizinini kaldırın.

## Yetkiler

`vncshot` hem CLI hem GUI modunda root yetkisi olmadan çalışmayı reddeder:

```bash
sudo vncshot -target 192.168.1.0/24
```

Bu kontrol uygulama başlarken yapılır; yarım çalışan bir tarama yerine aksiyon
alınabilir bir hata ile çıkılır. Tek istisna, root kontrolünden önce derleme
bilgisini yazdırıp çıkan `-version` bayrağıdır.

## Kullanım

```bash
sudo vncshot -target 192.168.1.0/24 -ports 5900,5901-5910
sudo vncshot -file hosts.txt -workers 100 -rate 150 -timeout 800ms
sudo vncshot -target 10.0.0.1-50 -out-dir /root/assessments
sudo vncshot -target 192.168.1.0/24 -word-list /root/parolalar.txt
sudo vncshot -target 192.168.1.0/24 -baseline /usr/local/vncshot/20261020-090000
sudo vncshot -target 10.0.0.0/24 -manifest -webhook https://hooks.example.test/vncshot
sudo vncshot -target 192.168.1.0/24 -config /root/vncshot.conf
sudo vncshot -gui
vncshot -version
```

Araç parametresiz çalıştırıldığında kullanım metnini yazdırır ve tarama
başlatmadan çıkar. `-version` araç adını, derleme sürümünü, GOOS/GOARCH ve Go
çalışma zamanı sürümünü yazdırır; örneğin
`vncshot dev (linux/amd64, go1.27.2)`. Yayın sürümünü `install.sh` derleme
sırasında gömer.

| Bayrak | Varsayılan | Açıklama |
|--------|-----------|----------|
| `-version` | `false` | Derleme bilgisini yazdır ve çık (root gerektirmez) |
| `-target` | | Tek IP, CIDR veya aralık (`192.168.1.1`, `192.168.1.0/24`, `192.168.1.1-50`) |
| `-file` | | Satır başına bir IP/CIDR/aralık içeren dosya (`#` yorum satırı desteklenir) |
| `-ports` | `5900` | Port listesi/aralıkları (`5900,5901-5910`) |
| `-timeout` | `1s` | TCP bağlantı zaman aşımı |
| `-vnc-timeout` | `15s` | RFB el sıkışma/yakalama zaman aşımı |
| `-workers` | `150` | Eşzamanlı tarama worker sayısı (en fazla 4096) |
| `-rate` | `200` | Saniyede en fazla yeni bağlantı (`0` = sınırsız, en fazla 100000) |
| `-retries` | `1` | Geçici hatalar için ek bağlantı denemesi (`0` = yok) |
| `-out-dir` | `/usr/local/vncshot` | Zaman damgalı tarama klasörlerinin kök dizini |
| `-output` | `<run-dir>/vncshot_report.json` | JSON rapor yolu |
| `-html` | `<run-dir>/vncshot_report.html` | HTML rapor yolu |
| `-pdf` | `<run-dir>/vncshot_report.pdf` | PDF rapor yolu (süreç içinde üretilir) |
| `-csv` | `<run-dir>/vncshot_report.csv` | CSV rapor yolu |
| `-baseline` | | Önceki tarama dizini; bulgular bununla karşılaştırılır |
| `-manifest` | `false` | Her çıktının SHA-256 özetlerini içeren `<run-dir>/manifest.json` yaz |
| `-webhook` | | Yeni bulgu veya açık uç nokta varsa bu adrese JSON özeti POST et |
| `-config` | | Bayrak varsayılanları içeren yapılandırma dosyası (JSON veya düz `key: value` YAML) |
| `-no-pdf` | `false` | PDF üretimini atla |
| `-screenshot-dir` | `<run-dir>/screenshots` | PNG yakalamaların kaydedileceği dizin |
| `-shared` | `true` | Paylaşımlı RFB oturumu iste (aktif izleyicileri düşürmez) |
| `-word-list` | | Ek parola adayları, satır başına bir tane (`#` yorumları ve boş satırlar yok sayılır, en fazla 500 kayıt) |
| `-no-default-passwords` | `false` | Yerleşik zayıf parola listesini deneme |
| `-no-password-check` | `false` | Hiç parola deneme; yalnızca parolasız sunucuları raporla |
| `-yes` | `false` | Etkileşimli yetki onayını atla |
| `-gui` | `false` | CLI taraması yerine yerel web GUI'sini başlat |
| `-gui-host` | `127.0.0.1` | GUI dinleme adresi (yalnızca loopback) |
| `-gui-port` | `0` | GUI dinleme portu (`0` = boş port seç) |
| `-gui-no-browser` | `false` | GUI'yi tarayıcıda otomatik açma |

`-gui-*` bayrakları yalnızca `-gui` ile birlikte anlamlıdır.

`-h` aynı bayrak başvurusunu yazdırır ve `0` ile çıkar. Bilinmeyen bir bayrak
`flag provided but not defined: <ad>` satırını ve kullanım metnini yazdırıp
`2` ile çıkar.

### Yapılandırma ve öncelik

Her tarama bayrağı bir `VNCSHOT_*` ortam değişkeniyle veya bir yapılandırma
dosyasıyla da verilebilir. Öncelik, en yüksekten başlayarak:

```
komut satırı bayrağı > ortam değişkeni > yapılandırma dosyası > yerleşik varsayılan
```

Açıkça verilen komut satırı bayrağı her zaman kazanır; ortam değerleri yalnızca
komut satırında verilmemiş bayraklara, yapılandırma dosyası değerleri ise
yalnızca diğer iki kaynakta da verilmemiş bayraklara uygulanır.

Ortam değişkeni adı, bayrak adının büyük harfe çevrilip her `-` karakterinin
`_` ile değiştirilmesiyle oluşur: `-out-dir` → `VNCSHOT_OUT_DIR`,
`-vnc-timeout` → `VNCSHOT_VNC_TIMEOUT` vb. Boş ortam değerleri yok sayılır.

Yapılandırma dosyası `-config <yol>` ile veya bu bayrak verilmediğinde
`VNCSHOT_CONFIG` ile yüklenir. `.json` uzantılı dosya düz bir JSON nesnesi
olarak; diğer uzantılar ise düz `key: value` YAML alt kümesi olarak
ayrıştırılır. Bu alt küme iç içe yapıları, listeleri, blok metinleri, tekrarlı
anahtarları ve bilinmeyen anahtarları sessizce yok saymak yerine reddeder.
Anahtarlar bayrak adlarının aynısıdır:

```yaml
# /root/vncshot.conf
out-dir: /root/assessments
ports: 5900,5901-5910
workers: 200
rate: 150
timeout: 2s
vnc-timeout: 20s
shared: true
no-pdf: false
```

JSON biçimi eşdeğerdir:

```json
{
  "out-dir": "/root/assessments",
  "workers": 200,
  "timeout": "2s"
}
```

`-version`, ortam, yapılandırma dosyası ve root kontrollerinden önce
değerlendirilir; böylece bozuk veya eksik bir yapılandırma derleme bilgisini
asla gizlemez ve bu bayrak komut satırından verilmelidir.

## Parola testi

Parola testi varsayılan olarak açıktır. Her RFB uç noktasına önce, hiçbir
kimlik bilgisi göndermeden duyurulan güvenlik tiplerini okuyan bir keşif
bağlantısı yapılır:

* Sunucu `None` güvenlik tipini sunuyorsa host parolasız olarak raporlanır ve
  ekran görüntüsü alınır.
* Sunucu VNC kimlik doğrulaması istiyorsa her aday parola kendi kısa ömürlü
  bağlantısında denenir. İlk kabul edilen parola kaydedilir ve host tıpkı
  parolasız bir host gibi yakalanır.
* Yalnızca başka güvenlik tipleri (örneğin TLS veya VeNCrypt) sunan sunucular
  parola denenmeden RFB servisi olarak raporlanır.

Adaylar yerleşik zayıf parola listesinden (boş parola dahil yaklaşık 30 yaygın
VNC parolası) ve isteğe bağlı olarak `-word-list` dosyasından gelir.
`-no-default-passwords` yerleşik listeyi kaldırır, `-no-password-check` ise
deneme aşamasını tamamen atlar; böylece yalnızca parolasız hostlar raporlanır.
Keşif aşaması hiç parola göndermediği için kapsam dışı bir host, yalnızca
tarandığı için saldırıya uğramaz.

### Tasarım gereği salt okunur

Başarılı bir girişten sonra — parolasız veya zayıf parola — istemci yalnızca
`SetPixelFormat`, `SetEncodings` ve tek bir `FramebufferUpdateRequest` mesajı
gönderir, tam olarak bir kare güncellemesi okur ve bağlantıyı kapatır. Hiçbir
zaman klavye veya fare girdisi, pano verisi ya da kontrol mesajı göndermez,
sürekli güncelleme istemez ve uzak masaüstünü değiştirmez. Yakalama, mevcut
ekranın anlık görüntüsüdür; fazlası değil.

RFB istemcisinin tamamı yaklaşık 1.100 satırdır ve tek oturumda denetlenebilir:
`vnc/protocol.go` tel sabitlerini ve kodlayıcıları, `vnc/auth.go` kimlik
doğrulamayı, `vnc/client.go` ise el sıkışma ve yakalama akışını içerir.

### Aday sınırları

* Her aday yeni bir bağlantı kullanır; tek bir sunucuyu arka arkaya denemek
  için oturum asla yeniden kullanılmaz.
* `SecurityResult` durumunun `2` olması (çok fazla deneme / kilitlenme) o
  sunucu için kalan adayları durdurur; durum JSON raporda `auth_locked`, HTML
  ve PDF raporlarında ise "locked out" etiketiyle kaydedilir.
* Yerleşik liste, envanter taramasının dikkat çekmemesi için bilinçli olarak
  küçüktür.
* `-word-list` en fazla 500 kayıt kabul eder; yol yoksa veya bir dizini
  gösteriyorsa reddedilir.
* Sekiz bayttan uzun adaylar RFB kimlik doğrulama şeması gereği sekiz bayta
  kırpılır; rapora kabul edilen değer yazılır.

### Hassas çıktıların işlenmesi

Raporlar zayıf parolaları, ekran görüntüleri ise yakalanan masaüstlerini
içerir. Çalışma dizinleri `0700`, ekran görüntüleri `0600`, JSON, HTML, PDF,
CSV raporları ve manifest dosyası `0600` izinleriyle oluşturulur; yalnızca
sahibi okuyabilir. Çalışma dizinini hassas delil olarak değerlendirin: ortak
depolamaya kopyalamayın veya redakte etmeden bir kayda eklemeyin.

## Bağlantı ve taşıma katmanı

### Güvenlik tipleri ve TLS

Her sonuç, sunucunun duyurduğu RFB güvenlik tiplerini duyuru sırasına göre
okunabilir adlarla `security_types` alanında kaydeder (örneğin
`["VNC authentication", "VeNCrypt"]`). Adlar IANA RFB güvenlik tipi kayıt
defterini izler; `None`, `VNC authentication`, `Tight`, `Ultra`, `TLS`,
`VeNCrypt`, `SASL`, `MSLogon II` ve `Apple Remote Desktop` gibi kayıtlar
protokol adlarıyla, bilinmeyen numaralar ise `type <n>` biçiminde görünür.

Sonuç ayrıca bir `tls` bayrağı taşır; bu bayrak, duyurulan tiplerden en az biri
şifreli bir kanal kuruyor veya müzakere ediyorsa işaretlenir. Şifreli sayılan
tipler: `RA2`, `Tight`, `Ultra`, `TLS`, `VeNCrypt` ve `SASL`. `Tight`, `Ultra`
ve `SASL` dahil edilmiştir çünkü gizlilik müzakere edebilirler; dolayısıyla
bayrak, her oturumun TLS kullandığını garanti etmez, sunulan yeteneği
tanımlar. `None`, `VNC authentication` ve diğer tipler açık metin kabul edilir.
Hem `None` hem de şifreli bir tip sunan sunucu, sonda zayıf `None` yolunu
izlese bile `tls: true` alır.

Özet, `tls_services` sayacını içerir (JSON anahtarı `tls_services`, HTML ve PDF
etiketi `TLS services`, GUI sayacı `TLS services`). HTML uç nokta tablosuna bir
Security sütunu, PDF uç nokta tablosuna `SECURITY` sütunu ve her bulgu kartına
bir `Transport` satırı, GUI bulgu tablosuna ise bir Transport sütunu eklenir.
`security_types` ve `tls`, boş veya `false` olduklarında JSON'dan çıkarılır.

### Yeniden deneme ve hedef başına sınırlar

* Bir sonda tam olarak bir TCP bağlantısı kullanır: bağlantı sonucunu belirleyen
  dial, RFB el sıkışmasını ve tek kare yakalamayı yapan bağlantının kendisidir.
  Ayrı bir açıklık dial'ı ve ardından ikinci bir el sıkışma dial'ı yoktur.
* İstisna parola adaylarıdır: her aday, parola testi bölümünde anlatıldığı gibi
  kendi kısa ömürlü bağlantısında denenir.
* Tarayıcının yeniden deneme politikası, geçici bir bağlantı hatasını en fazla
  bir kez yeniden dener ve 150 ms ile başlayan, jitter eklenmiş üstel geri
  çekilme kullanır (ilk yeniden deneme 150–225 ms bekler). Zaman aşımları,
  `ECONNRESET`, `EPIPE` ve `EHOSTUNREACH` geçici sayılır; `ECONNREFUSED`
  kesindir ve hiç yeniden denenmez. Varsayılan bütçe bir yeniden denemedir;
  `-retries 0` ile varsayılan tarama hedef başına tek bağlantı denemesi yapar.
* JSON sonucundaki, CSV sütunundaki ve rapor işaretlerindeki `attempts` alanı
  kaç TCP bağlantı denemesi gerektiğini kaydeder. İlk denemede başarılı bir
  hedef `1`, hiç bağlanamayan bir hedef `0` bildirir; yeniden denenen hedef
  daha yüksek sayı gösterir ve HTML/PDF/GUI çıktısında yeniden denendi olarak
  işaretlenir.
* Hedef başına eşzamanlılık, IP başına 2 eşzamanlı sondayla sınırlıdır; böylece
  çok sayıda portu taranan bir sunucuya tüm worker'lar aynı anda yüklenmez.
  Global `-workers` ve `-rate` sınırları geçerliliğini korur.
* `-workers` ve `-rate` için sert üst sınırlar vardır (4096 ve 100000). Bir
  worker bir goroutine ve en az bir soket demektir; saniyede 100000 bağlantının
  üzerinde ise hız aralığı sıfıra yuvarlanır. Bu nedenle iki değer de sessizce
  yok sayılmak yerine reddedilir.

İptal edilen bir sonda, tetiklediği soket zaman aşımı hatasıyla değil iptal
nedeniyle kaydedilir; aksi halde `i/o timeout` okuyan operatör olmayan bir ağ
arızasını araştırır.

## Tarama nasıl çalışır

### Hedef genişletme

`-target` tek adres, CIDR bloğu, kapsayıcı son oktet aralığı (`10.0.0.10-20`)
veya IPv6 adresi/CIDR kabul eder. `-file` aynı sözdizimini satır başına bir
kayıt olarak okur; `#` yorumları ve boş satırlar yok sayılır. İki kaynak
birleştirilebilir ve tekrarlar ayıklanır. `-ports` virgülle ayrılmış port
listesi ve kapsayıcı aralıklar kabul eder.

Genişletme sınırlıdır; böylece bir yazım hatası devasa bir tarama başlatamaz:

| Sınır | Değer | Davranış |
|-------|-------|----------|
| Tarama başına host:port çifti | 1.048.576 (2^20) | Hedefi veya port listesini daraltma mesajıyla reddedilir |
| Tek CIDR belirtimindeki host sayısı | 65.536 (2^16, yani `/16` veya daha uzun) | Reddedilir; daha büyük blokları birkaç belirtime bölün |
| Word-list kaydı | 500 | Reddedilir |

Hedefler hiçbir paket gönderilmeden önce genişletilir; geçersiz bir girdi
kısmi tarama bırakmadan hemen hata verir.

### Sondalama hattı

Her `host:port` çifti için worker şunları yapar:

1. **Dial** — `-timeout` ile. Reddedilen veya zaman aşımına uğrayan bağlantı
   portu kapalı işaretler (hata geçici ise bir kez yeniden dener).
2. **Protokol başlığı** — `RFB xxx.yyy` okunur, iki tarafın da desteklediği en
   iyi sürümle (3.3, 3.7 veya 3.8) yanıtlanır.
3. **Güvenlik müzakeresi** — duyurulan tipler okunur. `None` hemen devam eder;
   VNC kimlik doğrulaması aday döngüsünü tetikler; diğer her şey durumu
   kaydedip durur.
4. **Oturum başlatma** — `ClientInit`/`ServerInit` masaüstü adını ve
   çerçeve tamponu geometrisini verir (kenar başına en fazla 8192x8192).
5. **Yakalama** — 32 bit gerçek renk piksel formatı, raw kodlama, tek tam kare
   güncellemesi istenir ve bağlantı kapatılır.
6. **Kalıcılaştırma** — parolasız/zayıf parolalı hostlar için PNG yazılır ve
   sonuç bellekteki kümeye eklenir.

Sonuçlar toplayıcıya akar; toplayıcı ilerleme çubuğunu, GUI olay akışını ve
son sıralı çıktı kümesini besler. Ctrl+C bağlamı iptal eder; uçuştaki sondalar
durur ve kısmi sonuçlar yine de yazılır.

## GUI

```bash
sudo vncshot -gui
```

Bu, loopback üzerinde yerel bir web arayüzü başlatır ve oturum URL'sini
terminale yazdırır. Form tarama seçeneklerini sunar: hedef veya hedef dosyası,
portlar, worker sayısı, hız, bağlantı ve RFB zaman aşımları, rapor kökü,
JSON/HTML/PDF yol geçersiz kılmaları, ekran görüntüsü dizini, PDF atlama ve
paylaşımlı oturum. Tarama düzeyi seçenekler (`-baseline`, `-manifest`,
`-webhook`, `-csv` ve `-config`) formda yer almaz; başlatma komut satırında
verilen değerler GUI'den başlatılan taramalara devralınır.

"Passwords" paneli word-list yolunu ve iki atlama anahtarını (yerleşik zayıf
parola listesi, parola testi) barındırır. Durum satırı geçerli taramanın kaç
parola adayı deneyeceğini gösterir ve bulgu tablosu zayıf kimlik bilgisiyle
erişilen hostları işaretler.

Özet şeridi bir `TLS services` sayacı içerir; bulgu tablosunda duyurulan
güvenlik tiplerini (`·` ile birleştirilmiş) listeleyen ve şifreli uç noktalar
için `tls` etiketi ekleyen bir Transport sütunu vardır.

"Previous runs" paneli rapor kökü altındaki tarama klasörlerini listeler
(`GET /api/runs`, en yeni önce, en fazla son 100 kayıt). Bir tarama seçildiğinde
JSON raporu panoya yüklenir (`POST /api/runs/open`); böylece eski bir tarama
yeni tarama başlatmadan incelenebilir. Tarama çalışırken bu istek
`409 Conflict` ile reddedilir. Tarama adları yalnızca zaman damgası klasör
adları olarak doğrulanır; hazırlanmış bir ad rapor kökünün dışına çıkamaz.

Form değerleri sayfa yenilenmesinden sonra `localStorage` içinde korunur
(hedef, portlar, zaman aşımları, çıktı yolları, parola seçenekleri ve diğer
form alanları). Yetki onay kutusu bilinçli olarak asla saklanmaz ve her tarama
için yeniden işaretlenmelidir.

Yetki onay kutusu işaretlenmeden tarama başlayamaz; bu, GUI karşılığı `-yes`
seçeneğidir. İlerleme, sayaçlar, bulgular ve ekran görüntüleri Server-Sent
Events ile canlı güncellenir. Çalışan bir tarama iptal edilebilir ve tamamlanan
tarama HTML, PDF ve JSON çıktılarına bağlantı verir.

Güvenlik özellikleri:

* Loopback dışı bir `-gui-host` değeri başlangıçta reddedilir.
* Her başlatmada 24 baytlık rastgele bir oturum token'ı üretilir. Token bir kez
  URL sorgu parametresi olarak verilir, HttpOnly ve SameSite=Strict bir
  çerezde saklanır ve durum değiştiren isteklerde ayrıca `X-Vncshot-Token`
  başlığıyla gönderilmelidir.
* `/files/` uç noktası yalnızca geçerli tarama klasörü içindeki dosyaları sunar.
* GUI de root olarak çalışır; yazdırılan URL'ye sahip olan herkes tarayıcıyı
  yönetebilir. URL'yi ve token'ı kimlik bilgisi olarak değerlendirin.
* Uzak erişim için loopback bağlamayı koruyup portu SSH üzerinden yönlendirin
  (`ssh -L 8080:127.0.0.1:<port> ...`); genel bir arayüze açmayın.

Portu sabitlemek için `-gui-port`, otomatik `xdg-open` çağrısını kapatmak için
`-gui-no-browser` kullanın.

![Bulgu tablosu ve tarama geçmişi](docs/screenshots/gui-findings.png)

*Bulgular taşıma tipini, parola kaynağını ve yakalanan karenin küçük görselini
taşır; sol ray önceki taramaları tek tıkla erişilebilir tutar.*

### GUI HTTP API

Pano, küçük bir JSON API'si üzerinde ince bir istemcidir. HTML sayfası dışındaki
her uç nokta oturum çereziyle ve durum değiştiren isteklerde
`X-Vncshot-Token` başlığıyla korunur.

| Yöntem | Yol | Amaç |
|--------|-----|------|
| `GET` | `/` | Pano sayfası (oturumu kurmak için `?t=<token>` kabul eder) |
| `GET` | `/api/state` | Geçerli tarama anlık görüntüsü: durum, sayaçlar, bulgular, çıktı bağlantıları |
| `GET` | `/api/events` | Aynı anlık görüntünün Server-Sent Events akışı |
| `POST` | `/api/scan` | Tarama başlat (`authorized: true` gerekir) |
| `POST` | `/api/cancel` | Çalışan taramayı iptal et |
| `GET` | `/api/runs` | Rapor kökü altındaki önceki taramalar, en yeni önce |
| `POST` | `/api/runs/open` | Önceki bir taramayı panoya yükle |
| `GET` | `/files/<yol>` | Geçerli tarama klasöründeki bir çıktıyı sun |

Hata yanıtları standart HTTP durum kodlarını kullanır: geçersiz girdi için
`400`, oturum yoksa `401`, token başlığı veya yetki yoksa `403`, eksik tarama
veya çıktı için `404`, tarama zaten çalışıyorsa `409`, yanlış yöntem için `405`.

## Çıktılar

Her tarama `-out-dir` altındaki kendi zaman damgalı klasörüne yazılır; taramalar
birbirinin üzerine yazmaz. Varsayılan `/usr/local/vncshot` dizini `install.sh`
tarafından ikilinin içine gömülür ve aynı betik tarafından oluşturulur:

```
/usr/local/vncshot/20261026-205304/
├── screenshots/{ip}_{port}_{timestamp}.png
├── manifest.json                  (-manifest ile)
├── vncshot_report.csv
├── vncshot_report.json
├── vncshot_report.html
└── vncshot_report.pdf
```

* `screenshots/` — parolasız ve zayıf parolalı sunucuların ekran görüntüleri
* `vncshot_report.json` — tüm sonuç kümesi
* `vncshot_report.html` — kendi içinde çalışan rapor (gömülü küçük görseller, filtre, modal)
* `vncshot_report.pdf` — tarama sonuçlarından süreç içinde üretilen PDF rapor
* `vncshot_report.csv` — aynı sonuç kümesinin düz aktarımı
* `manifest.json` — yalnızca `-manifest` ile yazılan SHA-256 özetleri

Klasör adı, yerel tarama başlangıç zamanının `YYYYMMDD-HHMMSS` biçimidir (GUI
ve temel karşılaştırma bu düzene dayanır). Ekran görüntüsü adları aynı biçimde
yakalama zamanını kullanır; böylece bir tarama klasörü kendini tanımlar.

Sonuçlar herhangi bir çıktı yazılmadan önce bir kez sıralanır: sayısal olarak
IP adresine, sonra porta göre. Bu nedenle JSON, HTML, PDF, CSV ve terminal
özeti uç noktaları her zaman aynı sırada listeler ve değişmeyen bir ağın
tekrarlanan taramaları doğrudan karşılaştırılabilir dosyalar üretir. Adresi
geçerli bir IP olmayan hostlar (örneğin bir ana makine adı) sayısal adreslerden
sonra, sözlük sırasına göre sıralanır.

JSON raporundaki her sonuç, zayıf bir parola kabul edildiğinde `password` ve
`password_source` (`default` veya `word-list`) taşır; özet ise
`weak_credentials` sayacını içerir. HTML ve PDF raporları aynı sayacı
"Weak creds" istatistiği olarak gösterir ve parolayı kaynağıyla birlikte bulgu
kartlarında ve uç nokta tablosunda görüntüler.

Çalışma dizini parola ve yakalanmış masaüstü içerdiği için `0700`, her ekran
görüntüsü ve rapor dosyası `0600` izniyle oluşturulur.

`-output`, `-html`, `-pdf`, `-csv` veya `-screenshot-dir` için verilen göreli
yollar tarama klasörü içinde çözümlenir; mutlak yollar olduğu gibi kullanılır.
İkilinin içine gömülü varsayılan dizin yazılamıyorsa tarama
`~/.local/share/vncshot` altına düşer; açıkça verilen `-out-dir` ise her zaman
olduğu gibi kullanılır.

HTML ve PDF raporları açık renkli bir "teknik dosya" teması kullanır. PDF,
Liberation Sans yazı tipini gömer (SIL Open Font License); böylece Türkçe ve
diğer ASCII dışı karakterler doğru görüntülenir.

![HTML raporu](docs/screenshots/html-report.png)

*Kendi kendine yeten HTML raporu: sayaç şeridi, kimlik doğrulama rozetli
yakalanmış kareler, temel farkı ve açık uç nokta tablosu.*

![PDF rapor kapağı](docs/screenshots/pdf-report.png)

*PDF raporu süreç içinde üretilir; tarayıcı veya harici araç kullanılmaz.*

![Yakalanan ekran görüntüsü](docs/screenshots/framebuffer-capture.png)

*Kaydedilmiş bir yakalama. Araç tam olarak bir kare isteyip bağlantıyı kapatır;
delil anlık bir görüntüdür, canlı oturum değildir.*

### JSON şeması

`vncshot_report.json` tek bir nesnedir:

```json
{
  "generated_at": "2026-10-26T20:53:04.512Z",
  "tool": "vncshot",
  "summary": {
    "targets": 254,
    "open": 3,
    "rfb": 2,
    "passwordless": 1,
    "weak_credentials": 1,
    "tls_services": 1,
    "screenshots": 2,
    "errors": 0
  },
  "results": [
    {
      "ip": "192.0.2.10",
      "port": 5900,
      "open": true,
      "rfb": true,
      "passwordless": false,
      "password": "hunter2",
      "password_source": "word-list",
      "security_types": ["VNC authentication", "VeNCrypt"],
      "tls": true,
      "attempts": 1,
      "server_name": "lab-pc",
      "screen_width": 1920,
      "screen_height": 1080,
      "screenshot": "/usr/local/vncshot/20261026-205304/screenshots/192.0.2.10_5900_20261026-205304.png",
      "duration_ms": 84,
      "timestamp": "2026-10-26T20:53:04.428Z"
    }
  ]
}
```

Sonuç alanları:

| Alan | Tip | Not |
|------|-----|-----|
| `ip`, `port` | string, int | Hedef uç nokta |
| `open` | bool | TCP bağlantısı başarılı |
| `rfb` | bool | RFB el sıkışması ve oturum başlatma başarılı |
| `passwordless` | bool | Sunucu `None` sundu ve kabul etti |
| `password` | string | Yalnızca zayıf parola kabul edildiyse bulunur; hassas |
| `password_source` | string | `default` (yerleşik liste) veya `word-list` |
| `auth_locked` | bool | Yalnızca sunucu ek denemeleri engellediyse bulunur |
| `security_types` | []string | Duyurulan tip adları, boşsa yok |
| `tls` | bool | `false` ise yok |
| `attempts` | int | Kullanılan TCP denemesi, sıfırsa yok |
| `server_name` | string | `ServerInit` masaüstü adı, boşsa yok |
| `screen_width`, `screen_height` | int | Çerçeve tamponu geometrisi, bilinmiyorsa yok |
| `screenshot` | string | PNG'nin mutlak yolu, yakalama yoksa yok |
| `error` | string | Kapalı portlarda yok; kısmi hatalarda bulunur |
| `duration_ms` | int | Sondalama süresi (milisaniye) |
| `timestamp` | string | UTC olarak RFC 3339 |

### CSV biçimi

CSV raporu her zaman yazılır, virgülle ayrılmış alanlarla standart CSV
alıntılaması kullanır ve sabit sütun düzenine sahiptir:

```
ip,port,open,rfb,passwordless,weak_password,password_source,tls,security_types,server_name,screen_width,screen_height,screenshot,error,duration_ms,attempts,timestamp
```

Boolean değerler `yes` veya `no` olarak yazılır. `security_types`, duyurulan tip
adlarını `;` ile birleştirir; böylece liste tek alanda kalır. `timestamp` UTC
olarak RFC 3339 biçimindedir. Satırlar, diğer çıktılarda olduğu gibi IP ve
porta göre sıralanır. Dosya parola içerebildiği için `0600` izniyle yazılır.

### Manifest dosyası

`-manifest`, diğer tüm çıktılardan sonra `<run-dir>/manifest.json` dosyasını
yazar; böylece özetler son dosyaları tanımlar:

```json
{
  "generated_at": "2026-10-26T20:53:04Z",
  "algorithm": "sha256",
  "root": "20261026-205304",
  "files": [
    {"path": "vncshot_report.csv", "size": 8192, "sha256": "..."}
  ]
}
```

`generated_at` UTC olarak RFC 3339, `algorithm` `sha256`, `root` tarama
klasörünün taban adıdır (tam yerel yol asla değil) ve `files` tarama dizinine
göre eğik çizgiyle ayrılmış yola göre sıralanır. Yalnızca normal dosyalar
özetlenir; sembolik bağlantılar atlanır, böylece tarama klasörü dışını
gösteren bir bağlantı yabancı içeriği manifeste taşıyamaz. Manifest kendini
hariç tutar; yeniden çalıştırıldığında aynı dosya listesini üretir ve tarama
klasörü parola ile yakalanmış masaüstü içerdiği için `0600` izniyle yazılır.
Amaç delil bütünlüğüdür: bir denetçi klasörü yeniden özetleyip her boyutu ve
özeti bu dosyayla karşılaştırabilir.

Kodu, bir tarama klasörünü yeniden özetleyip eksik, fazla veya değişmiş ilk
dosyayı bildiren bir doğrulama yardımcısı (`app.VerifyManifest`) içerir; bu
yardımcı CLI bayrağı olarak sunulmaz.

### Temel karşılaştırma

`-baseline <dizin>` önceki bir tarama dizinini belirtir; araç onun
`vncshot_report.json` dosyasını okur ve bulguları `ip:port` anahtarıyla
karşılaştırır. Eksik dizin, dizin olmayan bir yol, okunamayan rapor veya
geçersiz JSON, hiçbir sonda çalışmadan önce kesin hatadır; böylece başarısız
bir karşılaştırma arkasında boş bir tarama klasörü bırakmaz.

Karşılaştırma üç grupta raporlanır:

* **yeni** — bu taramada olup temelde olmayan uç noktalar
* **çözülen** — temelde olup artık görünmeyen uç noktalar
* **değişen** — risk durumu değişen uç noktalar ve nedeni

Neden metinleri sabit İngilizce metinlerdir:

| Neden | Anlamı |
|-------|--------|
| `no longer RFB` | Port daha önce yanıt veriyordu ama artık RFB konuşmuyor |
| `became passwordless` | Uç nokta artık `None` güvenlik tipini sunuyor |
| `weak password discovered` | Artık zayıf bir parola kabul ediliyor |
| `password no longer accepted` | Önceki zayıf parola artık çalışmıyor |
| `became TLS` | Artık şifreli bir güvenlik tipi duyuruluyor |
| `lost TLS` | Artık şifreli bir güvenlik tipi duyurulmuyor |

Durumu değişen bir hedef, hem yeni hem çözülen bulgu olarak değil, değişen
altında tek kez görünür. Sayımlar CLI özetinde yazdırılır (temel, yeni bulgular,
çözülen, değişen), HTML ve PDF raporlarında "Changes since baseline" bölümü
olarak gösterilir ve aşağıda açıklanan webhook yüküne eklenir. JSON ve CSV
çıktıları her zaman yalnızca geçerli taramayı içerir. Yeni bulgular ayrıca
webhook yükünün tetikleyicisidir.

### Webhook bildirimleri

`-webhook <url>`, tamamlanan bir taramadan sonra bir HTTP veya HTTPS uç
noktasına JSON belgesi POST eder; ancak yalnızca `-baseline` en az bir yeni
bulgu ürettiyse veya tarama parolasız ya da zayıf parolalı bir uç nokta
bulduysa. Kesintiye uğrayan taramalar asla bildirilmez. İsteğin 10 saniyelik
zaman aşımı ve `vncshot/<sürüm>` User-Agent değeri vardır; 2xx dışı yanıt hata
sayılır.

Yük şu biçimdedir:

```json
{
  "tool": "vncshot",
  "version": "1.0.0",
  "generated_at": "2026-10-26T20:53:04Z",
  "run_dir": "20261026-205304",
  "summary": { "targets": 254, "open": 3, "rfb": 2, "passwordless": 1,
               "weak_credentials": 1, "tls_services": 1, "screenshots": 2,
               "errors": 0 },
  "new_findings": [
    { "ip": "192.0.2.10", "port": 5900, "open": true, "rfb": true,
      "passwordless": false, "password_source": "word-list", "tls": false,
      "server_name": "lab-pc" }
  ],
  "weak_credentials": [
    { "ip": "192.0.2.10", "port": 5900, "password_source": "word-list" }
  ]
}
```

Parola değeri asla dahil edilmez: webhook kayıtları yalnızca
`password_source` (`default` veya `word-list`) taşır. `run_dir` tarama
klasörünün taban adıdır; böylece alıcı yerel dosya sistemi yolunu öğrenmez ve
hata mesajları erişim token'ı taşıyabildikleri için uç noktanın sorgu dizesini
ve kullanıcı bilgisini gizler. Temel istenmediyse `new_findings` boştur.

Teslimat hatası, başarısız tarama değil uyarıdır: CLI özetten sonra stderr'e
`warning: webhook notification failed: ...` yazar, çıktılar bozulmadan kalır ve
çıkış durumu yine taramanın kendisini yansıtır.

## Çıkış kodları

| Kod | Anlamı |
|-----|--------|
| `0` | Tarama tamamlandı, yardım yazdırıldı veya `-version` yazdırıldı |
| `1` | Yapılandırma, yetki, hedef, G/Ç veya rapor hatası |
| `2` | Bilinmeyen komut satırı bayrağı (flag paketi kullanım hatası) |
| `130` | Ctrl+C veya SIGTERM ile kesildi; kısmi sonuçlar yazıldı |

Açık uç nokta bulan tamamlanmış bir tarama yine `0` ile çıkar: bulgular veridir,
araç arızası değil. Bir ardışık düzenin bulgu üzerine başarısız olması
gerekiyorsa JSON özetini veya webhook'u kullanın.

## Performans ayarı

Varsayılanlar tek portlu bir `/24` ağını birkaç saniyede hedefler. Diğer
durumlar için:

| Durum | Ayar |
|-------|------|
| Host başına çok port | `-workers` düşürün; hedef başına eşzamanlılık 2'de kalır |
| Büyük aralıklar | `-rate` ve `-workers` değerlerini birlikte artırın, kaybı izleyin |
| WAN veya kayıplı bağlantılar | `-timeout` değerini `2s`–`5s` yapın, `-retries 1` bırakın |
| Yavaş veya gömülü VNC sunucuları | `-vnc-timeout` değerini `30s` yapın |
| Güvenilmeyen veya izlenen ağlar | Dikkat çekmemek için `-rate` düşürün (ör. `20`) |
| Çok büyük word-list | Kısaltın; her aday ayrı bir bağlantıdır |

Bellek kullanımına yakalanan kareler egemen olur: uçuştaki her yakalama için
bir RGBA tamponu (en fazla `-workers` kadar) artı HTML raporuna gömülen küçük
görseller. `-workers 500` ile on binlerce port taramak mümkündür ancak her
yakalama base64 olarak gömüldüğü için HTML raporu hızla büyür; çok büyük
envanterlerde `-no-pdf` kullanın ve worker sayısını düşürün.

## Sorun giderme

**`error: root privileges required; re-run with sudo`**
Komutu `sudo` ile çalıştırın. Yalnızca `-version` ve `-h` istisnadır.

**`create report directory /usr/local/vncshot/...: permission denied`**
İkilinin içine gömülü rapor kökü yazılabilir değil. Root olarak çalıştırın veya
sahibi olduğunuz açık bir `-out-dir` verin.

**Raporlar `/usr/local/vncshot` yerine `/root/.local/share/vncshot` altında**
Varsayılan kök yazılabilir değildi ve `-out-dir` verilmedi; tarama kullanıcı
dizinine düştü. CLI nedeniyle birlikte bir uyarı yazdırır.

**`refusing to scan N host:port pairs (limit 1048576)`**
Aralığı daraltın, CIDR'ı bölün veya port listesini azaltın.

**`CIDR ... is too large (… /16 or longer prefixes only …)`**
`vncshot` CIDR belirtimi başına en fazla 65.536 host genişletir; bir `/8`
bloğunu `/16` bloklarına bölün veya gerçekten sahibi olduğunuz alt ağlarla
`-file` kullanın.

**Bir host `open: true`, `rfb: false` gösteriyor**
TCP portu yanıt verdi ancak servis RFB el sıkışmasını tamamlamadı. Protokol
hatası `error` alanında raporlanır; böylece 5900 portundaki VNC olmayan bir
servis sessizce kapalı sayılmak yerine görünür olur.

**`auth_locked: true`**
Sunucu `SecurityResult` durumu 2 döndürdü. Hesabı daha fazla kilitlememek için
kalan adaylar bırakıldı; elle inceleyin.

**GUI URL'si açılıyor ama pano boş kalıyor**
Token URL sorgu dizesindedir; yalnızca host ve portu kopyaladıysanız çerez hiç
kurulmamıştır. Yazdırılan tam URL'yi yeniden açın.

**`warning: webhook notification failed`**
Tarama ve tüm çıktılar sağlamdır; yalnızca bildirim başarısız oldu. DNS, TLS
güveni ve alıcıyı kontrol edin, gerekirse saklanan JSON'dan yeniden gönderin.

**HTML raporu çok büyük**
Her yakalama base64 olarak gömülür. `-no-pdf` kullanın ve worker sayısını
düşürün veya taramayı daha küçük çalıştırmalara bölün.

## Paket yapısı

```
main.go        CLI bayrakları, root kontrolü, GUI başlatma
app/           tarama oturumu, çıktı düzeni, temel farkı, manifest, webhook
config/        yapılandırma dosyası ve VNCSHOT_* ortam değişkenlerinden bayrak varsayılanları
gui/           gömülü web arayüzü (index.html + HTTP sunucusu)
scanner/       hedef genişletme, worker havuzu, hız sınırı, yeniden deneme ve hedef başına sınırlar
vnc/           RFB 3.3/3.7/3.8 istemcisi, None-auth ve zayıf parola kimlik doğrulaması, raw yakalama
screenshot/    PNG kalıcılaştırma
report/        Sonuç modeli, JSON/HTML/PDF/CSV dışa aktarıcıları, gömülü PDF yazı tipi
```

## Bağımlılıklar

| Modül | Amaç |
|-------|------|
| `github.com/go-pdf/fpdf` | PDF rapor üretimi |
| `github.com/schollz/progressbar/v3` | Terminal ilerleme çubuğu |

Geri kalan her şey Go standart kütüphanesini kullanır.

## Geliştirme

```bash
go test ./...          # birim + entegrasyon testleri
go test -race ./...    # eşzamanlılık kontrolleri
go vet ./...
gofmt -l .
go build ./...
shellcheck -S warning install.sh
```

Test paketi tamamen çevrimdışı çalışır: RFB uç noktaları süreç içinde
benzetilir, bu nedenle VNC sunucusu veya ağ erişimi gerekmez. Kapsam; RFB
3.3/3.7/3.8 el sıkışmasını, DES kimlik doğrulamasının bağımsız bir
uygulamayla karşılaştırılmasını, parolasız ve zayıf parolalı yakalamayı,
kilitlenme işlemesini, hiçbir girdi veya pano mesajı gönderilmediğini doğrulayan
tel düzeyi bir testi, GUI API'sini ve token/yol aşımı korumalarını,
CSV/manifest/temel/webhook davranışını ve rapor üreticilerini içerir.

CI, Linux üzerinde (`.github/workflows/ci.yml`) `main` dalına her push, her
pull request ve elle tetiklemede çalışır. `gofmt -l .` kontrolünü yapar,
`go vet ./...`, `go build ./...` ve `go test -race -count=1 ./...` komutlarını
çalıştırır ve `install.sh` dosyasını shellcheck ile (warning seviyesi, iki
bilinen bilgilendirici bulgu için `SC2034` hariç) denetler.

Yeni bir bayrak eklerken `README.md` **ve** `README.tr.md` dosyalarını
güncelleyin; iki dosya eşzamanlı tutulur ve birlikte incelenir.

## Yasal Uyarı / Kullanım Şartları

**Yalnızca yetkili kullanım.** Bu yazılım yalnızca yetkili güvenlik testleri,
savunma amaçlı güvenlik araştırması ve eğitim amacıyla yayımlanmıştır.
Yalnızca sahibi olduğunuz veya açık yazılı yetkiniz bulunan ağ ve sistemleri
tarayabilirsiniz.

Yetkisiz erişim veya dinleme, çoğu yargı alanında suç teşkil eder.
Kullanımınızın tüm yürürlükteki yerel, ulusal ve uluslararası mevzuata uygun
olduğunu sağlamak **yalnızca sizin sorumluluğunuzdadır**.

**Geliştiricinin sorumluluğu reddedilir.** Geliştirici (**Cuma KURT**),
yazılımın kullanımından, kötüye kullanımından, kullanılamamasından ya da
güvenilmesinden doğabilecek hiçbir zarar, veri kaybı, kâr kaybı, iş kesintisi,
hukuki talep, idari ya da cezai yaptırım, para cezası veya doğrudan, dolaylı,
arızi, özel, sonuçsal ya da cezai hiçbir sorumluluk için, hiçbir koşulda ve
yürürlükteki mevzuatın izin verdiği azami ölçüde sorumlu tutulamaz — geliştirici
bu tür zararların olasılığı hakkında bilgilendirilmiş olsa dahi.

**Garanti yoktur.** YAZILIM "OLDUĞU GİBİ", AÇIK VEYA ZIMNİ HİÇBİR GARANTİ
OLMAKSIZIN SUNULMUŞTUR; SATILABİLİRLİK, BELİRLİ BİR AMACA UYGUNLUK VE İHLAL
ETMEME GARANTİLERİ DAHİL ANCAK BUNLARLA SINIRLI OLMAMAK ÜZERE HİÇBİR GARANTİ
VERMEZ. YAZILIMIN KALİTESİ VE PERFORMANSIYLA İLGİLİ TÜM RİSK SİZE AİTTİR.

Bu aracı çalıştırarak bu beyanı okuduğunuzu, anladığınızı ve kabul ettiğinizi
beyan etmiş sayılırsınız.

## Lisans

GNU Genel Kamu Lisansı v3.0 — bkz. [LICENSE](LICENSE).

Telif Hakkı (C) 2026 Cuma KURT

Bu program özgür yazılımdır: Free Software Foundation tarafından yayımlanan GNU
Genel Kamu Lisansı'nın 3. sürümü veya (tercihinize göre) daha sonraki bir
sürümünün koşulları altında yeniden dağıtabilir ve/veya değiştirebilirsiniz.

Sorumlulukla ve yalnızca yetkiniz varsa kullanın.
