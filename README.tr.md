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
- Elektronik tablolar ve ardışık düzenler için sabit sütun sıralı CSV dışa aktarımı
- Güvenlik tipi envanteri: her bulgu duyurulan `security_types` listesini ve
  bir `tls` bayrağını kaydeder
- Önceki bir taramaya göre temel karşılaştırma (yeni, çözülen ve değişen bulgular)
- Kanıt bütünlüğü için her çıktı dosyasının SHA-256 manifestosu (`-manifest`)
- Yeni bulgu veya açık uç nokta olduğunda isteğe bağlı webhook bildirimi
- Yapılandırma dosyası (`-config`) ve `VNCSHOT_*` ortam değişkenlerinden bayrak varsayılanları
- Tekrarlanan taramaların doğrudan karşılaştırılabilmesi için deterministik, sıralı sonuçlar
- Hedef başına tek TCP bağlantısı ve sınırlı hedef başına eşzamanlılık
- Canlı ilerleme, rapor bağlantıları ve önceki tarama geçmişi sunan yerel web GUI (`-gui`)
- `-version` root yetkisi gerektirmeden derleme bilgisini yazdırır
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
aksiyon alınabilir bir hata ile çıkılır. Tek istisna `-version` bayrağıdır;
derleme bilgisini yazdırır ve root denetiminden önce çıkar.

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

Parametresiz çalıştırıldığında yalnızca kullanım metni yazdırılır ve tarama
başlatılmaz. `-version` araç adını, derleme sürümünü, GOOS/GOARCH değerlerini
ve Go çalışma zamanı sürümünü yazdırır; örneğin
`vncshot dev (linux/amd64, go1.27.2)`. Sürüm bilgisi `install.sh` tarafından
derleme sırasında eklenir.

| Bayrak | Varsayılan | Açıklama |
|--------|------------|----------|
| `-version` | `false` | Derleme bilgisini yazdır ve çık (root gerektirmez) |
| `-target` | | Tek IP, CIDR veya aralık (`192.168.1.1`, `192.168.1.0/24`, `192.168.1.1-50`) |
| `-file` | | Satır başına bir IP/CIDR/aralık içeren dosya (`#` yorum satırı desteklenir) |
| `-ports` | `5900` | Port listesi/aralıkları (`5900,5901-5910`) |
| `-timeout` | `1s` | TCP bağlantı zaman aşımı |
| `-vnc-timeout` | `15s` | RFB handshake/yakalama zaman aşımı |
| `-workers` | `150` | Eşzamanlı tarama worker sayısı |
| `-rate` | `200` | Saniyede en fazla yeni bağlantı (`0` = sınırsız) |
| `-retries` | `1` | Geçici hatalar için ek bağlantı denemesi (`0` = yok) |
| `-out-dir` | `/usr/local/vncshot` | Zaman damgalı tarama klasörlerinin kök dizini |
| `-output` | `<run-dir>/vncshot_report.json` | JSON rapor yolu |
| `-html` | `<run-dir>/vncshot_report.html` | HTML rapor yolu |
| `-pdf` | `<run-dir>/vncshot_report.pdf` | PDF rapor yolu (süreç içinde üretilir) |
| `-csv` | `<run-dir>/vncshot_report.csv` | CSV rapor yolu |
| `-baseline` | | Önceki tarama dizini; bulgular bununla karşılaştırılır |
| `-manifest` | `false` | Her çıktı dosyasının SHA-256 özetlerini içeren `<run-dir>/manifest.json` yaz |
| `-webhook` | | Taramada yeni bulgu veya açık uç nokta olduğunda bu URL'ye JSON özeti POST et |
| `-config` | | Bayrak varsayılanlarını içeren yapılandırma dosyası (JSON veya düz `key: value` YAML) |
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

### Yapılandırma ve öncelik

Her tarama bayrağı ayrıca bir `VNCSHOT_*` ortam değişkeni veya bir
yapılandırma dosyası ile verilebilir. Öncelik, en yüksekten başlayarak:

```
komut satırı bayrağı > ortam değişkeni > yapılandırma dosyası > yerleşik varsayılan
```

Komut satırında açıkça verilen bir bayrak her zaman kazanır; ortam değerleri
yalnızca komut satırında verilmeyen bayraklara, yapılandırma dosyası değerleri
ise yalnızca diğer iki kaynakta da verilmeyen bayraklara uygulanır.

Ortam değişkeni adları, bayrak adının büyük harfe çevrilip her `-` karakterinin
`_` ile değiştirilmesiyle oluşur: `-out-dir` → `VNCSHOT_OUT_DIR`,
`-vnc-timeout` → `VNCSHOT_VNC_TIMEOUT` vb. Boş ortam değişkeni değerleri yok
sayılır.

Yapılandırma dosyası `-config <yol>` ile veya bu bayrak verilmediğinde
`VNCSHOT_CONFIG` ortam değişkeninden yüklenir. `.json` uzantılı dosya düz bir
JSON nesnesi olarak, diğer uzantılar ise düz `key: value` YAML alt kümesi
olarak ayrıştırılır. Bu alt küme iç içe yapıları, listeleri, blok skalerleri,
yinelenen anahtarları ve bilinmeyen anahtarları sessizce yok saymak yerine
reddeder. Anahtarlar bayrak adlarının aynısıdır:

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

`-version` ortam değişkeni, yapılandırma dosyası ve root denetimleri
uygulanmadan önce değerlendirilir; böylece bozuk veya eksik bir yapılandırma
derleme bilgisini gizlemez ve bayrağın kendisi komut satırından verilmelidir.

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
içerir. Tarama dizinleri `0700`, ekran görüntüleri `0600`, JSON, HTML, PDF, CSV
raporları ve manifesto `0600` izinleriyle oluşturulur; yani yalnızca dosya
sahibi okuyabilir. Bir tarama dizinini hassas kanıt olarak değerlendirin:
paylaşımlı depolamaya kopyalamayın ve redaksiyon yapmadan bir kayda (ticket)
eklemeyin.

## Bağlantı ve taşıma katmanı

### Güvenlik tipleri ve TLS

Her sonuç, sunucunun duyurduğu RFB güvenlik tiplerini duyuru sırasıyla
`security_types` alanında okunabilir adlarla kaydeder (örneğin
`["VNC authentication", "VeNCrypt"]`). Adlar IANA RFB güvenlik tipi
kayıtlarına dayanır; `None`, `VNC authentication`, `Tight`, `Ultra`, `TLS`,
`VeNCrypt`, `SASL`, `MSLogon II` ve `Apple Remote Desktop` gibi tipler protokol
adlarıyla, bilinmeyen numaralar ise `type <n>` biçiminde görünür.

Sonuç ayrıca, duyurulan tiplerden en az biri şifreli bir kanal kuruyor veya
müzakere edebiliyorsa `true` değerini alan bir `tls` bayrağı taşır. Şifreli
sayılan tipler: `RA2`, `Tight`, `Ultra`, `TLS`, `VeNCrypt` ve `SASL`. `Tight`,
`Ultra` ve `SASL` gizlilik müzakere edebildikleri için dahildir; yani bayrak
her oturumun TLS kullandığını garanti etmez, sunulan yeteneği tanımlar. `None`,
`VNC authentication` ve diğer tipler açık metin olarak değerlendirilir. Hem
`None` hem de şifreli bir tip duyuran sunucu, sorgulama zayıf `None` yolunu
izlese bile `tls: true` alır.

Özette bir `tls_services` sayacı bulunur (JSON anahtarı `tls_services`, HTML ve
PDF etiketi `TLS services`, GUI sayacı `TLS services`). HTML uç nokta tablosuna
Security, PDF uç nokta tablosuna `SECURITY` sütunu ve her bulgu kartına bir
`Transport` satırı, GUI bulgu tablosuna ise Transport sütunu eklenir.
`security_types` ve `tls`, JSON çıktısında boş veya false olduklarında
yazılmaz.

### Yeniden deneme ve hedef başına sınırlar

* Bir sorgulama tam olarak bir TCP bağlantısı kullanır: bağlantı durumunu
  belirleyen dial, RFB handshake ve tek kare yakalamanın yapıldığı bağlantının
  kendisidir. Ayrı bir açıklık denemesi ve ardından ikinci bir handshake
  bağlantısı yoktur.
* Parola adayları bunun istisnasıdır: her aday, parola testi bölümünde
  açıklandığı gibi kendi kısa ömürlü bağlantısında denenir.
* Tarayıcının yeniden deneme politikası, geçici bir bağlantı hatasını en fazla
  bir kez yeniden dener ve 150 ms ile başlayan, jitter eklenmiş üstel geri
  çekilme kullanır (ilk yeniden deneme 150–225 ms bekler). Zaman aşımları,
  `ECONNRESET`, `EPIPE` ve `EHOSTUNREACH` geçici sayılır; `ECONNREFUSED`
  kesindir ve hiç yeniden denenmez. Varsayılan bütçe bir yeniden denemedir;
  `-retries 0` ile varsayılan tarama hedef başına tek bağlantı denemesi yapar.
* JSON sonucundaki, CSV sütunundaki ve rapor işaretlerindeki `attempts` alanı
  kaç TCP bağlantı denemesi gerektiğini kaydeder. İlk denemede başarılı bir
  hedef `1`, hiç bağlanamayan bir hedef `0` bildirir; yeniden denenen hedef
  daha yüksek bir değer gösterir ve HTML/PDF/GUI çıktısında yeniden denendi
  olarak işaretlenir.
* Hedef başına eşzamanlılık, aynı hedef IP'ye karşı en fazla 2 eşzamanlı
  sorgulama ile sınırlıdır; böylece çok sayıda portu taranan bir sunucu tüm
  worker'lar tarafından aynı anda dövülmez. Genel `-workers` ve `-rate`
  sınırları yine geçerlidir.

## GUI

```bash
sudo vncshot -gui
```

Bu komut loopback üzerinde yerel bir web arayüzü başlatır ve oturum URL'sini
terminale yazdırır. Form tarama seçeneklerini sunar: hedef veya hedef dosyası,
portlar, worker sayısı, hız, bağlantı ve RFB zaman aşımları, rapor kök dizini,
JSON/HTML/PDF yol geçersiz kılmaları, ekran görüntüsü dizini, PDF atlama ve
paylaşımlı oturum. `-baseline`, `-manifest`, `-webhook`, `-csv` ve `-config`
gibi tarama düzeyi seçenekler formda yer almaz; başlatma komut satırında
verilen değerler GUI'den başlatılan taramalar tarafından devralınır.

"Passwords" paneli word list yolunu ve iki atlama seçeneğini (yerleşik zayıf
parola listesi, parola testi) sunar. Durum satırı geçerli taramanın kaç parola
adayı deneyeceğini gösterir; bulgular tablosu zayıf parola ile erişilen
sunucuları işaretler.

Özet şeridi bir `TLS services` sayacı içerir; bulgular tablosunda duyurulan
güvenlik tiplerini (`·` ile ayrılmış) listeleyen ve şifreli uç noktalar için
`tls` etiketi ekleyen bir Transport sütunu bulunur.

"Previous runs" paneli rapor kök dizini altındaki tarama klasörlerini listeler
(`GET /api/runs`, en yeniden eskiye, en fazla son 100 tarama). Bir tarama
seçildiğinde JSON raporu panoya yeniden yüklenir (`POST /api/runs/open`),
böylece eski bir tarama yeni tarama başlatmadan incelenebilir; bir tarama
çalışırken istek `409 Conflict` ile reddedilir. Tarama adları yalnızca zaman
damgası klasör adı olarak doğrulanır; hazırlanmış bir ad rapor kök dizininin
dışına çıkamaz.

Form değerleri sayfa yenilendiğinde `localStorage` içinde korunur (hedef,
portlar, zaman aşımları, çıktı yolları, parola seçenekleri ve diğer form
alanları). Yetki onay kutusu bilinçli olarak hiçbir zaman saklanmaz ve her
tarama için yeniden işaretlenmelidir.

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
├── manifest.json                  (-manifest ile)
├── vncshot_report.csv
├── vncshot_report.json
├── vncshot_report.html
└── vncshot_report.pdf
```

* `screenshots/` — parolasız ve zayıf parolalı sunucuların ekran görüntüleri
* `vncshot_report.json` — tüm sonuç kümesi
* `vncshot_report.html` — kendi içinde çalışan rapor (gömülü thumbnail, filtre, modal)
* `vncshot_report.pdf` — tarama sonuçlarından süreç içinde üretilen PDF rapor
* `vncshot_report.csv` — aynı sonuç kümesinin düz dışa aktarımı
* `manifest.json` — yalnızca `-manifest` ile yazılan, çıktı dosyalarının SHA-256 özetleri

Sonuçlar herhangi bir çıktı yazılmadan önce bir kez sıralanır: önce IP adresine
göre sayısal, sonra porta göre. Bu nedenle JSON, HTML, PDF, CSV ve terminal
özeti uç noktaları her zaman aynı sırada listeler ve değişmeyen bir ağın
tekrarlanan taramaları doğrudan karşılaştırılabilir dosyalar üretir. Geçerli bir
IP olmayan adresler (örneğin bir ana makine adı) sayısal adreslerden sonra
sözlüksel sırayla gelir.

JSON raporundaki her sonuç, zayıf bir parola kabul edildiğinde `password` ve
`password_source` (`default` veya `word-list`) alanlarını taşır; özette ayrıca
`weak_credentials` sayacı bulunur. HTML ve PDF raporları aynı sayacı "Weak creds"
istatistiği olarak gösterir ve parolayı kaynağıyla birlikte bulgu kartlarında ve
uç nokta tablosunda sunar.

Bir tarama dizini parola ve yakalanmış masaüstü içerdiği için `0700` izniyle,
her ekran görüntüsü ve rapor dosyası ise `0600` izniyle oluşturulur.

`-output`, `-html`, `-pdf`, `-csv` ve `-screenshot-dir` için verilen göreli
yollar tarama klasörü içinde çözümlenir; mutlak yollar olduğu gibi kullanılır.
Derlemeye gömülü varsayılan dizin yazılabilir değilse tarama
`~/.local/share/vncshot` altına düşer; açıkça verilen `-out-dir` ise her
zaman olduğu gibi kullanılır.

HTML ve PDF raporları açık renkli "technical dossier" temasını kullanır. PDF,
Türkçe ve diğer ASCII dışı karakterlerin doğru görüntülenmesi için Liberation
Sans yazı tipini (SIL Open Font License) gömer.

### CSV biçimi

CSV raporu her zaman yazılır, standart CSV alıntılaması ve virgülle ayrılmış
alanlar kullanır ve sabit bir sütun sırasına sahiptir:

```
ip,port,open,rfb,passwordless,weak_password,password_source,tls,security_types,server_name,screen_width,screen_height,screenshot,error,duration_ms,attempts,timestamp
```

Boolean değerler `yes` veya `no` olarak yazılır. `security_types`, duyurulan tip
adlarını `;` ile birleştirir; böylece liste tek bir alanda kalır. `timestamp`
UTC olarak RFC 3339 biçimindedir. Satırlar diğer çıktılarda olduğu gibi IP ve
porta göre sıralanır.

### Manifesto

`-manifest`, diğer tüm çıktılardan sonra `<run-dir>/manifest.json` dosyasını
yazar; böylece özetler nihai dosyaları tanımlar:

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
klasörünün taban adıdır (tam yerel yol asla yazılmaz) ve `files` tarama
dizininden göreli, eğik çizgiyle ayrılmış yola göre sıralanır. Yalnızca normal
dosyalar özetlenir; sembolik bağlantılar atlanır, böylece tarama klasörü
dışını gösteren bir bağlantı yabancı içeriği manifestoya taşıyamaz. Manifesto
kendisini hariç tutar; bu yüzden yeniden çalıştırıldığında aynı dosya listesini
üretir. Tarama klasörü parola ve yakalanmış masaüstü içerdiği için manifesto
`0600` izniyle yazılır. Amaç kanıt bütünlüğüdür: bir inceleyici klasörü yeniden
özetleyip her boyut ve özeti bu dosyayla karşılaştırabilir.

### Temel karşılaştırma

`-baseline <dizin>` önceki bir tarama dizinini belirtir; araç onun
`vncshot_report.json` dosyasını okur ve bulguları `ip:port` anahtarıyla
karşılaştırır. Dizinin bulunmaması, yolun dizin olmaması, raporun okunamaması
veya geçersiz JSON, herhangi bir sorgulamadan önce sert bir hatadır; böylece
başarısız bir karşılaştırma geride boş bir tarama klasörü bırakmaz.

Karşılaştırma üç grupta bildirilir:

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
bulgu ürettiyse ya da tarama parolasız veya zayıf parolalı bir uç nokta
bulduysa. Kesintiye uğrayan taramalar hiçbir zaman bildirilmez. İsteğin 10
saniyelik zaman aşımı ve `vncshot/<sürüm>` User-Agent değeri vardır; 2xx
olmayan bir yanıt hata sayılır.

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

Parola değeri hiçbir zaman eklenmez: webhook kayıtları yalnızca
`password_source` (`default` veya `word-list`) taşır. `run_dir` tarama
klasörünün taban adıdır; alıcı yerel dosya sistemi yolunu asla öğrenmez. Hata
mesajları, erişim belirteci taşıyabildikleri için uç noktanın sorgu dizesini ve
kullanıcı bilgisini gizler. Temel istenmediyse `new_findings` boştur.

Teslimat hatası başarısız bir tarama değil, uyarıdır: CLI özetten sonra stderr
üzerine `warning: webhook notification failed: ...` yazar, çıktılar bozulmadan
kalır ve çıkış durumu yine taramanın kendisini yansıtır.

## Paket yapısı

```
main.go        CLI bayrakları, root denetimi, GUI başlatma
app/           tarama oturumu, çıktı düzeni, temel karşılaştırma, manifesto, webhook
config/        yapılandırma dosyası ve VNCSHOT_* ortam değişkenlerinden bayrak varsayılanları
gui/           gömülü web arayüzü (index.html + HTTP sunucusu)
scanner/       hedef genişletme, worker pool, rate limit, yeniden deneme ve hedef başına sınırlar
vnc/           RFB 3.3/3.7/3.8 istemcisi, None-auth ve zayıf parola kimlik doğrulaması, raw yakalama
screenshot/    PNG kaydetme
report/        Result modeli, JSON/HTML/PDF/CSV dışa aktarıcıları
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

CI Linux üzerinde (`.github/workflows/ci.yml`) `main` dalına her push, her pull
request ve elle tetiklenen çalıştırmalar için koşar; `gofmt -l .` denetimini
yapar, `go vet ./...`, `go build ./...` ve `go test -race -count=1 ./...`
komutlarını çalıştırır ve `install.sh` dosyasını shellcheck ile denetler
(uyarı düzeyi; iki bilinen bilgilendirici bulgu için `SC2034` hariç).

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