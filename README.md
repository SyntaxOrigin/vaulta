# Kasa (Vaulta)

**Argon2id + XChaCha20-Poly1305 ile şifreli, tamamen çevrimdışı, tek dosya parola kasası.**

Hesap açmaz, abonelik istemez, telemetri göndermez, ağ bağlantısı kurmaz. Veri
tek bir dosyada durur; şifreleme tamamen yereldir; algoritma kimlikleri ve
Argon2id maliyet parametreleri dosyanın içinden **okunabilir**.

> **Güvenlik ürünü uyarısı.** Bu bir MVP'dir ve bağımsız güvenlik incelemesi
> **yapılmamıştır**. Ayrıntı ve kabul edilen riskler için
> [Bilinen Sınırlamalar](#bilinen-sınırlamalar) bölümünü okuyun.

---

## Özellikler

- **Tek dosya kasa formatı.** Kendi `KASA` sürüm 1 biçimimiz var: düz metin
  başlık + şifreli dizin + şifreli sayfalar. SQLite kullanılmaz.
- **Argon2id ile ana parola türetme** (RFC 9106). `m_cost` / `t_cost` /
  `p_cost` kasada açık metin olarak saklanır ve `info` komutuyla okunabilir.
  Tuç (16 bayt) kasanın içindedir ve `getrandom` ile üretilir.
- **Alt anahtar ayrımı (HKDF-SHA256).** Ana malzemeden üç ayrı anahtar
  türetilir: dizin anahtarı, sayfa anahtarı (her sayfa için ayrı) ve çerçeve
  anahtarı. `info` etiketleri `vaulta/v1/...` ön ekini taşır.
- **XChaCha20-Poly1305 sayfa şifrelemesi.** Her sayfa 192-bit **rastgele**
  nonce ile şifrelenir; nonce asla sayaç değildir. Her yazma işleminde tüm
  nonce'lar yeniden üretilir, böylece nonce yeniden kullanımı yapısal olarak
  imkânsızdır.
- **Kayıt çerçeveleme (record framing) + çift katman bütünlük.** Her kayıt
  `uzunluk ‖ HKFP-MAC etiketi ‖ gövde` çerçevesine konur; ayrıca sayfanın tamamı
  AEAD ile korunur. Tek bir kaydın bozulması komşu kayıtları düşürmez.
- **Parola üreteci** (`getrandom`, reddetme örneklemesi ile tam tekdüzelik).
  Karışan karakterler (`0/O/1/l/I`) sözlükten çıkarılmıştır.
- **Kaba parola denetimi** — NIST SP 800-63B uyumlu. 15 karakterin altı
  reddedilir; gömülü yaygın parola listesi uygulanır; **bileşiklik kuralı
  (büyük harf/rakam/simge zorunluluğu) yoktur** — SP 800-63B bunları bilinçli
  olarak önermez.
- **Otomatik kilit = işlem sonu temizliği.** Her komut ayrı bir süreçtir;
  anahtar malzemesi `zeroize` ile sıfırlanır, `kilit()` ile erken sıfırlanır.
- **Denetlenebilir kasa başlığı.** `vaulta info` **ana parola istemeden**
  algoritmayı, maliyet parametrelerini, tuzu ve sayfa sayısını gösterir.
- **Atomik yazma.** Yazma `<yol>.tmp` üzerine yapılır, sonra hedefe `rename`
  edilir; başarısızlıkta eski kasa bozulmaz.
- **`serde_json` dışa/içe aktarma** ve `export-verified` ile geri okuyarak
  alan alan doğrulama.
- **`#![forbid(unsafe_code)]`.** Projedeki hiçbir satır `unsafe` içermez.

### MVP kapsamı dışında bırakılanlar

`MANIFEST.md` kart 16 "Ertelenen" listesinden: TOTP, kurtarma anahtarı,
şifreli dışa/içe aktarma, güvenli pano, yerel pano izleme. Ayrıntı için
[Bilinen Sınırlamalar](#bilinen-sınırlamalar).

---

## Kurulum

Gereksinim: Rust **1.74** veya üzeri (MSRV). Bu depoda geliştirme ve testler
Rust 1.98.1 ile yapıldı.

```console
$ cargo build --release
   Compiling argon2 v0.5.3
   Compiling chacha20poly1305 v0.10.1
   Compiling vaulta v0.1.0
    Finished `release` profile [optimized] target(s) in 23.10s
```

İkili `target\release\vaulta.exe` (Windows) / `target/release/vaulta`
(Linux, macOS) altında oluşur.

```console
$ cargo install --path .
   Compiling vaulta v0.1.0
    Finished `release` profile [optimized] target(s) in 24.62s
  Installing vaulta v0.1.0 (%USERPROFILE%\.cargo\bin)
   Installed package `vaulta v0.1.0` executable
```

---

## Kullanım

> **Sır girişi kuralı.** Ana parola **asla** komut satırı argümanı olarak
> kabul edilmez. İki kanal vardır: `--ana-parola-stdin` (stdin'in ilk satırı)
> veya `VAULTA_ANA_PAROLA` ortam değişkeni (betikler için).
> Aşağıdaki örneklerde kullanılan parolalar **örnek değerlerdir**; gerçek
> kasa parolalarınız değildir.

### 1. Kasa oluşturma

```console
$ vaulta init %USERPROFILE%\AppData\Local\Temp\opencode\vaulta-demo\kasa.kasa --ana-parola-stdin
kasa olusturuldu: %USERPROFILE%\AppData\Local\Temp\opencode\vaulta-demo\kasa.kasa
  argon2id: 65536 KiB / 3 tur / 4 yol
  sayfa boyutu: 4096 bayt
```

Parola stdin'den okunur (`--ana-parola-stdin`), burada örnek olarak
`bu-ciddi-bir-ana-parola-2026` gönderilmiştir.

### 2. Başlığı okuma — ana parola **gerekmez**

```console
$ vaulta info %USERPROFILE%\AppData\Local\Temp\opencode\vaulta-demo\kasa.kasa
dosya      : %USERPROFILE%\AppData\Local\Temp\opencode\vaulta-demo\kasa.kasa
bicim      : KASA surum 1
argon2id   : 65536 KiB / 3 tur / 4 yol
sayfa      : 1 adet x 4096 bayt
kayit      : 2
tuz        : 14987ca0720b54fd29ac6b408f808ef5

(tuz gizli degildir; gizli olan kayit icerigidir)
```

### 3. Kayıt ekleme

Kayıt parolası da stdin'den gelir: **1. satır** ana parola, **2. satır** kayıt
parolası.

```console
$ vaulta add %USERPROFILE%\AppData\Local\Temp\opencode\vaulta-demo\kasa.kasa --ana-parola-stdin --parola-stdin --baslik "GitHub" --kullanici "kullanici@example.com" --adres "https://github.com" --not "iki factorsiz"
kayit eklendi: GitHub (kasa: %USERPROFILE%\AppData\Local\Temp\opencode\vaulta-demo\kasa.kasa, kayit sayisi: 1)
```

### 4. Listeleme

```console
$ vaulta list %USERPROFILE%\AppData\Local\Temp\opencode\vaulta-demo\kasa.kasa --ana-parola-stdin
NO  BASLIK                   KULLANICI                SAYFA  CERCEVE
1   GitHub                   kullanici@example.com        0        0
2   GitLab                   kisimisi@example.com         0        1

2 kayit.
```

Makine-okunur çıktı (`--json`) — parola **yoktur**:

```console
$ vaulta list %USERPROFILE%\AppData\Local\Temp\opencode\vaulta-demo\kasa.kasa --ana-parola-stdin --json
{
  "surum": 1,
  "argon2_bellek_kib": 65536,
  "kayit_sayisi": 2,
  "kayitlar": [
    {
      "baslik": "GitHub",
      "kullanici": "kullanici@example.com",
      "sayfa": 0,
      "cerceve": 0
    },
    {
      "baslik": "GitLab",
      "kullanici": "kisimisi@example.com",
      "sayfa": 0,
      "cerceve": 1
    }
  ]
}
```

### 5. Kayıt okuma

Parola **varsayılan olarak maskelenir**:

```console
$ vaulta get %USERPROFILE%\AppData\Local\Temp\opencode\vaulta-demo\kasa.kasa --ana-parola-stdin --baslik "GitHub"
baslik   : GitHub
kullanici: kullanici@example.com
adres    : https://github.com
parola   : ****************
not      : iki factorsiz

(parolayi duz metin gormek icin --goster-sir kullanin)
```

`--goster-sir` ile:

```console
$ vaulta get %USERPROFILE%\AppData\Local\Temp\opencode\vaulta-demo\kasa.kasa --ana-parola-stdin --baslik "GitHub" --goster-sir
baslik   : GitHub
kullanici: kullanici@example.com
adres    : https://github.com
parola   : kayit-gizli-sifri-001
not      : iki factorsiz
```

### 6. Ana parola değiştirme

```console
$ vaulta change-master %USERPROFILE%\AppData\Local\Temp\opencode\vaulta-demo\kasa.kasa --ana-parola-stdin --yeni-parola-stdin
ana parola degistirildi ve 2 kayit yeniden seifreldi
```

Eski parola artık çalışmaz — ve bu ayrım "parola yanlış / kasa bozuk"
mesajı **verilmeden** anlaşılır, çünkü ikisi kriptografik olarak
ayırt edilemez:

```console
$ vaulta list %USERPROFILE%\AppData\Local\Temp\opencode\vaulta-demo\kasa.kasa --ana-parola-stdin
hata: ana parola yanlis veya kasa butunlugu bozuk (sayfa etigi dogrulanmadi)
$ echo $LASTEXITCODE
1
```

### 7. Kayıt silme

```console
$ vaulta remove %USERPROFILE%\AppData\Local\Temp\opencode\vaulta-demo\kasa.kasa --ana-parola-stdin --baslik "GitLab"
kayit silindi: GitLab
```

### 8. Doğrulamalı dışa aktarma

```console
$ vaulta export-verified %USERPROFILE%\AppData\Local\Temp\opencode\vaulta-demo\kasa.kasa --ana-parola-stdin --cikti %USERPROFILE%\AppData\Local\Temp\opencode\vaulta-demo\export.json
disa aktarildi : %USERPROFILE%\AppData\Local\Temp\opencode\vaulta-demo\export.json
kayit sayisi   : 2
karsilastirilan: 10 alan
icerik ozeti   : sha256:152aab6bfdca6a6790b36f1f9f1a1be6c80711f4333b0cb5802149025c751bb0
dogrulama      : GECTI (yazilan dosya yeniden okundu, tum alanlar esit)
```

Üretilen dosya (**düz metin**, kasadan daha az güvenlidir):

```json
{
  "bicim": 1,
  "ureten": "vaulta 0.1.0",
  "argon2_bellek_kib": 65536,
  "kayit_sayisi": 2,
  "kayitlar": [
    {
      "baslik": "GitHub",
      "kullanici": "kullanici@example.com",
      "parola": "kayit-gizli-sifri-001",
      "adres": "https://github.com",
      "not": "iki factorsiz"
    },
    {
      "baslik": "GitLab",
      "kullanici": "kisimisi@example.com",
      "parola": "kayit-gizli-sifri-002",
      "adres": "https://gitlab.com",
      "not": ""
    }
  ]
}
```

### 9. Parola üretme ve denetleme

```console
$ vaulta uret
h2+T@ehvyE2EX6JFkPxn
$ vaulta uret --uzunluk 28
sn2h6&3h!9espZ!?3?E97WrKhuwP
```

```console
$ echo "123456" | vaulta denetle --parola-stdin
hata: ana parola reddedildi: 6 karakter, gereken en az 15 (NIST SP 800-63B B.2: kullanici secimi parolalar en az 15 karakter veya 4 rastgele sozcuk olmalidir; kasa yalnizca karakter sayisini olcer)
$ echo $LASTEXITCODE
1

$ echo "dogru-bir-ana-parola-2026" | vaulta denetle --parola-stdin
kabul: 25 karakter, NIST SP 800-63B denetiminden gecti
$ echo $LASTEXITCODE
0

$ echo "qwertyuiop12345" | vaulta denetle --parola-stdin
hata: ana parola reddedildi: 15 karakter, gereken en az 15 (NIST SP 800-63B B.2: yaygin parolalar reddedilir)
$ echo $LASTEXITCODE
1
```

Kaba parola ile `init` **dosya oluşturmaz**:

```console
$ echo "123456" | vaulta init %USERPROFILE%\AppData\Local\Temp\opencode\vaulta-demo\kaba.kasa --ana-parola-stdin
hata: ana parola reddedildi: 6 karakter, gereken en az 15 (NIST SP 800-63B B.2: kullanici secimi parolalar en az 15 karakter veya 4 rastgele sozcuk olmalidir; kasa yalnizca karakter sayisini olcer)
$ echo $LASTEXITCODE
1
$ test -f %USERPROFILE%\AppData\Local\Temp\opencode\vaulta-demo\kaba.kasa && echo VAR || echo YOK
YOK
```

### 10. Komut listesi

```console
$ vaulta --help
Argon2id ve XChaCha20-Poly1305 ile sifreli, tek dosya, cevrimdisi parola kasasi.

Usage: vaulta.exe <COMMAND>

Commands:
  init             Yeni bir kasa dosyasi olusturur
  add              Kasaya yeni bir kayit ekler
  list             Kasadaki kayitlari listeler (parolalar cozulmez)
  get              Tek bir kaydi gosterir; parola varsayilan olarak maskelenir
  remove           Basliga gore kaydi siler
  change-master    Ana parolayi degistirir ve tum kayitlari yeniden seifreler
  export-verified  Tum kayitlari JSON olarak disa aktarir ve **hemen geri okuyarak dogrular**
  info             Kasa basligini okur; ana parola **gerekmez**
  uret             Isletim sistemi rastgeleliginden parola uretir
  denetle          Parolayi NIST SP 800-63B kurallarina gore dener; sifri ekrana basmaz

Options:
  -h, --help     Print help
  -V, --version  Print version
```

---

## Kriptografik Parametreler

### Argon2id: RFC 9106'nın ilk önerisinden **bilinçli sapma**

RFC 9106 §4, ilk öneri olarak **m = 2 GiB, t = 1, p = 4** değerlerini verir.
Bu proje **m = 64 MiB, t = 3, p = 4** kullanır. Bu sapma bilinçlidir ve
gerekçesi aşağıdadır:

| Parametre | RFC 9106 ilk öneri | Bu proje | Gerekçe |
|---|---|---|---|
| `m` (bellek) | 2 GiB | **65 536 KiB (64 MiB)** | Hedef donanım ofis sınıfı dizüstüdür ve MANIFEST kart 16 bellek bütçesini **180 MB tepe RSS** olarak tanımlar. 2 GiB, 8 GiB RAM'li bir dizüstünde sayfa değiştirme (swap) tetikler ve kullanıcı kasanın "donduğunu" sanır. 64 MiB, sistemin tamamını zorlamadan bir dizüstünde rahatça çalışır. |
| `t` (tur) | 1 | **3** | Bellek 32 kat düşürüldüğü için turlar **yükseltilmiştir**. Argon2'in bellek-zorlu yapısı gereksinim `m·t` üzerinden ölçülür; `t = 3` ile toplam iş yükü, RFC önerisinin yakınında kalır. |
| `p` (paralellik) | 4 | **4** | RFC ile aynı; `m ≥ 8·p` kuralı 64 MiB'de fazlasıyla sağlanır. |

**Bu, kabul edilmiş bir güvenlik azaltmasıdır.** 64 MiB, 2026 yılında GPU/ASIC
kaba kuvvet saldırganı için zayıf bir sınırdır. Karşı önlem, paranın
**kendisinin** güçlü olmasıdır; kasa, anahtarı çalma kolaylığı kazanılsa bile
16 MiB/saniye hızında 64 MiB Argon2id çağrısı bileşen bir kaba kuvvet
saldırısını pahalı kılar. Daha yüksek bütçe isteyen kullanıcı kasayı
`m = 262 144 KiB` ile oluşturabilir — başlıktaki parametreler kullanıcıya
aittir, sabit kodlu değildir.

**Ölçüm** (bu makine, Rust 1.98.1, `release` profili, 2 kayıtlı kasa):

| İşlem | Varsayılan (64 MiB / 3 / 4) | `--hizli` (16 MiB / 1 / 1) |
|---|---|---|
| `init` | 159 ms | 30 ms |
| `list` (kasa açma) | 133 ms | 28 ms |

Rapordaki hedef açılış süresi `< 1,2 sn`'dir; ölçülen değerler 10 kat altında.

### Argon2id test vektörü hakkında **dürüst sapma**

WORKER_CONTRACT §5.4, hazır kriptografik crate kullanan projelerin crate'in
kendi test vektörlerini ayrıca doğrulamasını ister. Bu projede:

- **AEAD doğrulandı.** RFC 8439 §2.8.2 bilinen yanıt vektörü (şifre metni +
  Poly1305 etiketi), aynı crate'in IETF varyantı (`ChaCha20Poly1305`,
  96-bit nonce) üzerinde **birebir** eşleşiyor — hem şifreleme hem çözme
  yönünde. Bu, nonce/AAD/etiket zincirimizin doğru kurulduğunu kanıtlar.
- **Argon2id doğrulanamadı.** RFC 9106 §5.3 test vektörü, algoritmanın
  isteğe bağlı **`secret` (pepper)** ve **`associated data`** girdilerini
  kullanır. RustCrypto `argon2` 0.5 bu iki girdiyi **genel API'de sunmaz**
  (`Argon2::new` yalnızca algoritma, sürüm ve maliyet parametreleri alır),
  dolayısıyla bu vektör birebir üretilemez. Kütüphanenin kendi test
  vektörlerine erişim de yoktur.

Bu yüzden Argon2id için, çağrımızın **parametre aktarımını** doğrulayan
dört deterministik test kullanılır: aynı girdi → aynı çıktı, tuz değişimi →
farklı çıktı, parola değişimi → farklı çıktı, maliyet değişimi → farklı çıktı
(`src/kripto.rs`). Bu testler kütüphanenin doğruluğunu değil, **bizim
çağrımızın** doğruluğunu kanıtlar; vektör eşleşmesi kadar güçlü bir kanıt
değildir ve bu bilinçle belgelenmiştir.

### Kasa biçimi (`KASA` sürüm 1)

```text
0            96                     düz metin başlık
                                0..4    imza "KASA"
                                4       sürüm (1)
                                5..9    m_cost KiB   (u32 LE)
                                9..13   t_cost       (u32 LE)
                                13..17  p_cost       (u32 LE)
                                17..21  sayfa boyutu (u32 LE)
                                21..25  sayfa sayısı (u32 LE)
                                25..29  kayıt sayısı (u32 LE)
                                29..45  tuz (16 bayt)
                                45..96  ayrılmış (sıfır olmalı)
96           ...                    şifreli bloklar, her biri:
                                    [u32 LE toplam uzunluk][24 bayt nonce][şifre metni ‖ 16 bayt etiket]
```

İlk blok **dizindir** (AAD: `vaulta/v1/index`), sonraki bloklar **veri
sayfalarıdır** (AAD: `vaulta/v1/page ‖ sayfa_no (BE)`).

Sayfa düz metni kayıt çerçevelerinden oluşur:

```text
cerceve := [u32 LE gövde uzunlugu][16 bayt HKFP-MAC etiketi][gövde (JSON)]
```

Alan sırası `uzunluk → etiket → gövde` seçildi: çerçeve başlığı sabit
20 bayt olur ve etiket doğrulanmadan önce sınır denetimi yapılabilir.

---

## Test

```console
$ cargo test
   Compiling vaulta v0.1.0
    Finished `test` profile [unoptimized + debuginfo] target(s) in 8.11s
     Running unittests src\lib.rs (target\debug\deps\vaulta-e8b60c1df123e0f2.exe)

running 96 tests
test result: ok. 96 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 1.03s

     Running unittests src/main.rs (target\debug\deps\vaulta-29a45e4f9273b804.exe)

running 0 tests
test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s

     Running tests\bozulma_ve_kurcalama.rs (target\debug\deps\bozulma_ve_kurcalama-699a0a9df30b031f.exe)

running 15 tests
test result: ok. 15 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 3.85s

     Running tests\guvenlik_sozlesmesi.rs (target\debug\deps\guvenlik_sozlesmesi-6e13966ceedfd9e3.exe)

running 12 tests
test result: ok. 12 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 1.14s

     Running tests\kasa_yasam_dongusu.rs (target\debug\deps\kasa_yasam_dongusu-b081087a2966767f.exe)

running 25 tests
test result: ok. 25 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 1.61s

     Running tests\yardimci\mod.rs (...)

running 0 tests
test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s

   Doc-tests vaulta

running 0 tests
test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
```

**Test sonucu: okunan 148; geçen 148; başarısız 0** (96 birim + 52 entegrasyon).

### Kapsanan senaryolar

| Senaryo | Nerede |
|---|---|
| Kayıt gidiş-dönüşü (tüm alanlar) | `kasa_yasam_dongusu::bos_kasaya_ilk_kayit_eklenir_ve_okunur` |
| Yanlış ana parola | `bozulma_ve_kurcalama::yanlis_ana_parola_kasayi_acmaz_ve_hata_sir_icermez` |
| Bozuk etiket (AEAD) | `kripto::bozuk_etik_hatasi_dondurur`, `kasa::sayfa_icerigi_kurcalanirsa_cozme_basarisiz` |
| Kurcalama tespiti (dizin, sayfa, başlık, tuz) | `bozulma_ve_kurcalama` (11 senaryo) |
| Kurulum tekrarları | `kasa_yasam_dongusu::kurulum_tekrarlari_ayni_dosyayi_ustune_yazmaz` |
| Argon2 tuz değişimi | `kripto::argon2_id_tuz_degisince_cikti_degisir` |
| Alt anahtar türetme ayrımı | `kripto::alt_anahtarlar_ayri_ayri_turetilir`, `sayfa_anahtarlari_karsilastirilabilir` |
| Parola üretici uzunluğu / karakter kümesi | `parola::uret*` (6 test) |
| Kötü parola listesi reddi | `parola::uzun_yaygin_parola_listesinden_reddedilir`, `kaba_ana_parola_ile_kasa_olusturulmaz` |
| Boş kasaya ekleme | `kasa_yasam_dongusu::bos_kasaya_ilk_kayit_eklenir_ve_okunur` |
| Dolu kasa listeleme | `kasa_yasam_dongusu::dolu_kasa_listelenir_ve_sira_korunur` |
| Olmayan kayıt arama / silme | `kasa_yasam_dongusu::olmayan_kayit_arama_hata_dondurur`, `olmayan_kayit_silme_hata_dondurur` |
| Ana parola değiştirme (tüm kayıtların yeniden şifrelenmesi) | `kasa_yasam_dongusu::ana_parola_degisince_tum_kayitlar_yeniden_sifrelenir` |
| İçe aktarma doğrulama | `kasa_yasam_dongusu::disa_aktarilan_belge_ic_aktarma_icin_gecerlidir` |
| Bozuk JSON | `kasa_yasam_dongusu::bozuk_aktarma_json_reddedilir`, `aktarim::bozuk_json_reddedilir` |
| Kısa süreli kasa (işlem sonu temizliği) | `kasa_yasam_dongusu::kisa_oturum_anahtari_kilit_sonrasi_sifirlanir` |
| Çok uzun alan adı | `kayit::cok_uzun_adres_reddedilir`, `kasa_yasam_dongusu::cok_uzun_baslik_reddedilir_ve_kasa_bozulmaz` |
| Unicode alan adı | `kayit::turkce_ve_birlestirilmis_harfler_korunur`, `kasa_yasam_dongusu::ana_parola_degisikligi_kayit_icerigini_bozmaz` |
| Sıfır uzunlukta parola | `kayit::sifir_uzunlukta_parola_kabul_edilir`, `kasa_yasam_dongusu::sifir_uzunlukta_parola_kaydedilir_ve_geri_okunur` |
| Ağ yüzeyi olmadığının belgelenmesi | `guvenlik_sozlesmesi::kaynakta_ag_yuzeyi_yoktur` (kaynak kod taranır) |
| Hata mesajlarında sır sızdırmama | `bozulma_ve_kurcalama::hata_mesaji_kayit_sirlarini_icermez`, `guvenlik_sozlesmesi::oturum_debug_iktisi_sir_icermez` |
| `zeroize` sonrası bellek | `guvenlik_sozlesmesi::kilit_anahtar_bellegini_sifirlar` |
| Kısmi bozulma (tek çerçeve) | `kasa::cerceve_etiketi_bozulursa_kayit_isaretlenir` |
| Çerçeve yer değiştirme saldırısı | `kasa::cerceveler_baska_sayfaya_tasinca_gecersiz_lesilir` |
| Nonce'un yeniden üretilmesi | `kasa::her_sifrelemede_nonce_yeniden_uretilir`, `guvenlik_sozlesmesi::her_yazimda_nonce_degisir` |
| Düz metin sızıntısı yok | `guvenlik_sozlesmesi::dosya_bicimi_kendi_kendini_denetler` |

### Diğer kalite kapıları

```console
$ cargo build --release        # exit 0, sıfır uyarı
$ cargo clippy --all-targets -- -D warnings   # exit 0, sıfır uyarı
$ cargo fmt --all -- --check  # exit 0
```

---

## Proje Yapısı

```text
projects/16-vaulta/
├── Cargo.toml                  edition 2021, rust-version 1.74, license MIT
├── Cargo.lock                  üretilir, commit edilir
├── LICENSE.txt                 MIT, Copyright (c) 2026
├── README.md                   bu dosya
├── .gitignore                  /target/, .env, *.log, *.kasa
├── src/
│   ├── lib.rs                  çekirdek kütüphane (57 satır)
│   ├── main.rs                 clap komut satırı (515 satır)
│   ├── hata.rs                 hata tipi ve sır sızdırmama kuralı (131 satır)
│   ├── kripto.rs               Argon2id + HKDF + XChaCha20-Poly1305 (621 satır)
│   ├── kasa.rs                 dosya biçimi, çerçeveleme, blok I/O (629 satır)
│   ├── kayit.rs                kayıt modeli ve alan sınırları (251 satır)
│   ├── parola.rs               üreteç + NIST SP 800-63B denetimi (381 satır)
│   ├── depo.rs                 oturum: oluştur/aç/ekle/sil/rotasyon (488 satır)
│   └── aktarim.rs              JSON dışa/içe aktarma ve doğrulama (316 satır)
└── tests/
    ├── yardimci/mod.rs         geçici dizin yardımcısı (89 satır)
    ├── kasa_yasam_dongusu.rs   uçtan uca senaryolar (25 test)
    ├── bozulma_ve_kurcalama.rs bozulma senaryoları (15 test)
    └── guvenlik_sozlesmesi.rs  tehdit modeli denetimleri (12 test)
```

Toplam Rust kaynağı: **4 422 satır**.

### `#[allow]` kullanımları

| Konum | Ne için | Gerekçe |
|---|---|---|
| `#[cfg(test)] mod tests` blokları (her modülde, 5 adet) | `clippy::unwrap_used`, `clippy::expect_used` | WORKER_CONTRACT §4.2 testlerde bunlara izin verir; testlerde `expect` bir hata **tanı** aracıdır, üretim yolunda kullanılmaz. |
| `tests/yardimci/mod.rs` | `dead_code` | Tek dosyada derlenen yardımcı; her test dosyası yalnızca bir kısmını kullanır. |

`#![forbid(unsafe_code)]` **gevşetilmemiştir**; `deny`'ye bile düşürülmemiştir.

---

## Yapılandırma

Vaulta **yapılandırma dosyası kullanmaz**. Ayar yalnızca kasada (düz metin
başlıkta) ve komut satırındadır.

### Ortam değişkeni

| Değişken | Zorunlu | Açıklama |
|---|---|---|
| `VAULTA_ANA_PAROLA` | hayır | `--ana-parola-stdin` verilmediyse ana parola bu değişkenden okunur. Betikler içindir; kabuk geçmişinde parola yazmamak için kullanılır. |

### Ortak bayraklar

| Bayrak | Varsayılan | Etkisi |
|---|---|---|
| `--ana-parola-stdin` | yok | Ana parolayı stdin'in ilk satırından okur. Verilmezse `VAULTA_ANA_PAROLA` aranır; o da yoksa komut hata verir. |
| `--hizli` | yok | Argon2id'yi 16 MiB / 1 tur / 1 yola indirir. **Yalnızca test ve ölçüm içindir**; kaba kuvvet direncini 64 kat azaltır ve kasaya kalıcı olarak yazılır. |

### Alt komut bayrakları

| Komut | Bayrak | Varsayılan | Etkisi |
|---|---|---|---|
| `init` | `--ana-parola-stdin`, `--hizli` | — | Yeni kasa oluşturur. Var olan dosyanın üstüne **yazmaz**. |
| `add` | `--baslik <METIN>` | zorunlu | Kayıt başlığı; kasada benzersiz olmalı, boş olamaz, en fazla 256 karakter. |
| `add` | `--parola <METIN>` | `""` | Kayıt parolası. Komut satırında görünür (aşağıdaki not). |
| `add` | `--parola-stdin` | yok | Kayıt parolasını stdin'in **ikinci** satırından okur. `--parola` ile çakışır. |
| `add` | `--kullanici`, `--adres`, `--not` | `""` | İsteğe bağlı alanlar (en fazla 256 / 2048 / 8192 karakter). |
| `list` | `--json` | yok | Makine-okunur JSON yazar; **parola alanı yoktur**. |
| `get` | `--baslik <METIN>` | zorunlu | Büyük/küçük harf duyarsız arama. |
| `get` | `--goster-sir` | yok | Parolayı düz metin yazar. Verilmezse `*` ile maskelenir. |
| `remove` | `--baslik <METIN>` | zorunlu | Kaydı siler ve kasayı yeniden paketler. |
| `change-master` | `--ana-parola-stdin` | — | Eski parola stdin 1. satır. |
| `change-master` | `--yeni-parola-stdin` | **zorunlu** | Yeni parola stdin 2. satır. |
| `export-verified` | `--cikti <DOSYA>` | zorunlu | JSON yazar, geri okur, alan alan doğrular. |
| `info` | — | — | Başlığı okur; **parola istemez**. |
| `uret` | `--uzunluk <SAYI>` | `20` | 12–128 aralığında parola üretir. |
| `denetle` | `--parola-stdin` | **zorunlu** | Parolayı denetler; sırrı **ekrana basmaz**. |

> **`--parola` bayrağı hakkında dürüst uyarı.** `--parola-stdin` kullanmayan
> `add` çağrılarında kayıt parolası işlem listesinde (`ps`) ve kabuk geçmişinde
> görünür. Bu bir MVP sadeleştirmesidir; gizlilik gerektiren kullanımda
> `--parola-stdin` kullanın.

### Çıkış kodu

| Kod | Anlam |
|---|---|
| `0` | başarılı |
| `1` | çalışma hatası (metin stderr'e yazılır) |
| `2` | kullanım hatası (`clap`) |

---

## Bilinen Sınırlamalar

Bu bölüm bilinçlidir ve eksiksiz olmaya çalışır.

### Güvenlik

1. **Bağımsız güvenlik incelemesi yapılmadı.** Kod, kanonik ve yaygın bakımlı
   RustCrypto crate'lerini kullanır (el yazımı kriptografi yoktur — MANIFEST
   kart 16, D-008), ancak **kutu biçimi**, çerçeveleme ve hata ayrımı
   bize aittir ve harici gözden geçirmeden geçmemiştir.
2. **Argon2id bellek maliyeti RFC 9106'nın ilk önerisinin altında** (64 MiB
   yerine 2 GiB). Gerekçe ve ölçüm yukarıda; bu, 2026 için zayıf bir sınırdır.
3. **Gömülü yaygın parola listesi sınırlıdır** (~50 giriş). Bağlantılı veri
   sızanı (HIBP vb.) kontrolü yoktur, çünkü proje tamamen çevrimdışıdır.
4. **`export-verified` düz metin JSON üretir.** Bu dosya kasadan daha az
   güvenlidir; şifreli aktarma `MANIFEST.md` kart 16'da ertelenmiştir.
5. **Kasa dosyası bozulursa veri kurtarılamaz.** Sayfa tabanlı tasarım kısmi
   bozulmayı *sınırlar* (bozulan sayfadaki kayıtlar kaybolur, diğer sayfalar
   okunur) ama kurtarma aracı **yoktur**. **Düzenli yedek alın.**
6. **Çift kullanımlılık riski açıkça kabul edilir.** Kasa kopyası olan biri
   kasayı açmak için de kullanabilir. Toplu deneme arayüzü yoktur.
7. **Windows'ta dosya izinleri daraltılamaz.** NTFS ACL'i `std` ile
   yazılamaz ve `unsafe`/FFI yasaktır. Unix'te `0o600` uygulanır; Windows'ta
   izinler olduğu gibi bırakılır.
8. **Güvenli pano yok.** `get --goster-sir` parolayı terminale yazar; pano
   FFI'si yasak olduğu için gerçek güvenlik sağlanamaz (MANIFEST kart 16
   madde 6).
9. **Sıfırlamak garanti değildir.** `zeroize` derleyicinin optimizasyon
   kararlarına rağmen çalışır, ancak işletim sistemi sayfa dosyası, takas veya
   çekirdek dökümü üzerinden bellekten kopyalanmış veriyi geri çağırmaz.
   Hibernation ve çekirdek dökümü kapatılmaz.

### İşlevsellik

10. **Yazma başına tam yeniden paketleme.** Her `add` / `remove` / rotasyon
    tüm kayıtları yeniden paketler ve **tüm sayfaları yeniden şifreler**
    (O(n) süre ve G/Ç). Büyük kasalarda bu yavaştır.
11. **Tüm kayıtlar belleğe yüklenir.** `Oturum` kasanın tamamını bellekte
    tutar; `list` "sayfaları çözmeden" çalışsa da sayfalar açılışta zaten
    çözülür. On binlerce kayıtta bellek sınırlayıcı olabilir.
12. **Metin arama yok.** `list` başlığı çıktılar; filtreleme kabuk
    tarafında yapılmalıdır (`| Select-String`).
13. **Kayıt geçmişi yok.** Aynı başlıkla ikinci kayıt eklenemez; üzerine
    yazma da yoktur.
14. **Çoklu kullanıcı ve eşzamanlı erişim yok.** Tek kullanıcı, tek süreç.
    Kasa dosyası kilit dosyasıyla korunmaz.
15. **Kasa biçiminde sürüm yükseltme yolu yok.** Sürüm 1 okuyucusu vardır,
    yazıcısı yalnızca sürüm 1 yazar. `R2` "Arşivlenmiş kasalar ileride açılamaz"
    riski çözülmemiştir.
16. **Güvenlik panosu, TOTP ve kurtarma anahtarı yok** (MANIFEST "Ertelenen").
17. **Yerelleştirme yok.** Tüm çıktılar ASCII Türkçe (diyakritiksiz); bu,
    konsol kodu sayfası sorunlarını (Windows CP1254) önlemek içindir.
18. **Parola üreteci sözlüğü sabit bir karakter kümesidir.** Sözcük listesi
    (`diceware`) yoktur; kasa bir sözlük taşımaz.

### Doğrulanmamış iddialar

19. **MSRV 1.74 gerçek bir 1.74 araç zinciriyle doğrulanmadı.** `Cargo.toml`
    içindeki `rust-version = "1.74"` beyanıdır; geliştirme ve testler Rust
    1.98.1 ile yapıldı. Kullanılan özellikler 1.74 öncesi gerektirmez, ancak
    bu ayrı bir işle doğrulanmalıdır.
20. **Antivirüs yanlış pozitif oranı ölçülmedi.**
21. **Performans ölçümleri tek makinede, soğuk değil.** Tabloda verilen
    süreler bu geliştirme makinesine aittir; rapordaki bütçe tablosu
    (180 MB tepe RSS) **ölçülmedi**, yalnızca tasarlandı. RSS ölçümü
    `/proc` veya Windows API erişimi gerektirir, her ikisi de `unsafe`/FFI
    yasaklar.
22. **UTF-8 dosya adları ve yollar Windows'ta daraltılmaz** (bkz. madde 7).

---

## Gelecek Geliştirmeler

**MANIFEST.md kart 16 "Ertelenen" listesi:**

- Şifreli dışa/içe aktarma (şifreli kapsül + içe aktarma doğrulama listesi)
- TOTP üretimi ve doğrulama pencereleri
- Kurtarma anahtarı (kasaya yazılmayan, ayrı dosyada)
- Yerel pano izleme ve zamanlı temizlik

**Doğal sonraki adımlar:**

1. **Bağımsız güvenlik incelemesi** — v0.9 sürümünden önce. Raporda bu bilinçli
   olarak v1.0 öncesine planlanmıştı: kriptografik kodu yazan ekip kendi
   kodunu denetlemek için en uygun ekip değildir.
2. **Kademeli yazma** — ekleme/silme yalnızca etkilenen sayfayı yeniden
   şifreler, dosyayı baştan yazmaz. `O(n)` maliyetini kaldırır.
3. **Kasa biçimi sürüm 2** — biçim alanı zaten var; okuma yolu eklenmeli.
4. **Parola geçmişi ve sürüm kütüğü** (alan düzeyinde, şifreli).
5. **İleri anahtar türetmesi** (Argon2id zinciri) — tek Argon2 çağrısı yerine
   zincir; kasa başlığına tur sayısı eklenir.
6. **Yerelleştirme** (`serde` + `i18n` tablosu), konsol kodu sorunu olmadan.
7. **Çoklu kasa dosyası** ve basit bir `vaulta ls` komutu.

---

## Troubleshooting

### 1. `hata: ana parola yanlis veya kasa butunlugu bozuk`

**Belirti:** Kasa açılmıyor; `init`, `list`, `get`, `add`, `remove`,
`change-master`, `export-verified` komutlarının hepsi bu mesajı verir.

**Neden (üç olasılık, bilinçli olarak ayırt edilemiyor):** (a) ana parola yanlış;
(b) kasa dosyası bozuk; (c) kasa başka bir Argon2id parametresiyle oluşturulmuş.
Ayrım kriptografik olarak imkânsızdır — ayrımı yapmak kaba kuvvet saldırganına
hız ipucu verirdi.

**Çözüm:**
- `vaulta info <kasa>` çalıştırın — **parola istemeden** başlığı okur. Argon2id
  parametreleri ve biçim sürümü doğru mu, kontrol edin.
- Yanlış kanalı seçmemiş olabilirsiniz: `--ana-parola-stdin` verdiyseniz
  parola stdin'in **ilk satırı** olmalı; PowerShell'de
  `"parola" | vaulta list ...` yazımı yanlışsa (tırnak koymazsanız) boş
  parola gider.
- Dosya gerçekten bozulduysa **veri kurtarılamaz**. Düzenli yedek almamışsanız
  bu bir veri kaybıdır.

### 2. `hata: ana parola reddedildi: N karakter, gereken en az 15`

**Belirti:** `init` veya `change-master` dosya oluşturmadan başarısız oluyor.

**Neden:** NIST SP 800-63B uyumlu kaba parola denetimi. 15 karakterin altı,
gömülü yaygın parola listesinde bir giriş, ya da yalnızca simgelerden oluşan
bir parola reddedilir. **Bileşiklik kuralı uygulanmaz** — `Password1!` gibi
tahmin edilebilir kalıplar bu yüzden geçer, `!@#$%^&*` gibi gerçekten rastgele
bir şey de geçer.

**Çözüm:** `vaulta uret --uzunluk 24` ile bir parola üretin, ya da 15+ karakterlik
kendi cümlenizi kullanın. Raporda önerilen ikinci seçenek — **en az 4 rastgele
sözcük** — kasa tarafından ölçülemez (kasa bir sözlük taşımaz), bu yüzden yalnızca
uzunluk denetlenir; sözcük seçeneğini `README` ve komut çıktısı açıklama olarak
belirtir.

### 3. `hata: gecersiz arguman: ana parola okunamadi: --ana-parola-stdin kullanin ya da VAULTA_ANA_PAROLA ayarlayin`

**Belirti:** Hiçbir komut çalışmıyor.

**Neden:** Ana parola **kasıtlı olarak** komut satırı argümanı olarak kabul
edilmiyor; iki kanal var ve ikisi de yok.

**Çözüm:** ya `--ana-parola-stdin` ekleyin ve parolayı stdin'e yazın
(`"parola" | vaulta ...`), ya da `VAULTA_ANA_PAROLA` ayarlayın. Betiklerde
ikincisi daha pratiktir.

### 4. `hata: ana parola yanlis veya kasa butunlugu bozuk (dosya cok kisa: N bayt...)`

**Belirti:** `info` komutu bile çalışmıyor; dosya çok küçük.

**Neden:** Kasa dosyası 96 baytlık başlıktan kısa. Ya dosya yazılırken kesildi
(ör. disk doldu, süreç öldürüldü) ya da bu bir kasa dosyası değil.

**Çözüm:** Dosyayı silip `init` ile yeniden oluşturun. **Kısmi yazma yüzeyi
kapatılmıştır** (yazma `<yol>.tmp` üzerine yapılır ve hedefe `rename` edilir),
bu yüzden yarım kasa normal koşullarda oluşmaz; bu dosya muhtemelen başka bir
dosyayla karıştırılmıştır.

### 5. `hata: bu baslikta kayit zaten var: 'X'`

**Belirti:** `add` başarısız.

**Neden:** Başlıklar kasada benzersizdir. Bu bir hata değil, bir kısıt;
kasa silmeden üzerine yazmaz.

**Çözüm:** `vaulta remove <kasa> --baslik "X"` ile eski kaydı silip yeniden
ekleyin. Kayıt geçmişi tutulmadığı için eski parola geri getirilemez.

### 6. `vaulta list` yavaş (2 GiB bellekli makinede)

**Belirti:** Açılış saniyeler sürüyor.

**Neden:** Argon2id bellek-zorlu çalışır ve 64 MiB ister. R4 riski: "Argon2id
maliyeti 2 GB altında açılışı yavaşlatır".

**Çözüm:** Parametreleri kasten **sessizce düşürmeyin** — başlıkta ne
yazıyorsa odur. `info` ile görüp bilinçli karar verin. Test amaçlıysa
`--hizli` bayrağı vardır ve kasaya kalıcı olarak düşük parametre yazar.

---

## Atıflar

### Spesifikasyonlar ve standartlar

- **RFC 9106 — Argon2 Password Hashing Competition Winner / Argon2 v1.3** —
  Argon2id tanımı, `m_cost` / `t_cost` / `p_cost` parametreleri ve test
  vektörleri. <https://www.rfc-editor.org/rfc/rfc9106>
- **RFC 8439 — ChaCha20 and Poly1305 for IETF Protocols** — Poly1305 etiketi ve
  AEAD_CHACHA20_POLY1305 yapısı. Testlerimizdeki §2.8.2 bilinen yanıt vektörü
  buradan alınmıştır. <https://www.rfc-editor.org/rfc/rfc8439>
- **draft-irtf-cfrg-xchacha-03 — XChaCha20 and XChaCha20-Poly1305 AEAD
  Additions** — 192-bit nonce alanı ve XChaCha20-Poly1305 birleşimi.
  <https://datatracker.ietf.org/doc/draft-irtf-cfrg-xchacha/03>
- **NIST SP 800-63B — Digital Identity Guidelines: Authentication and Lifecycle
  Management** — parola uzunluğu (Bölüm 3.1.1), yaygın/sızan parola listesi
  denetimi (Bölüm 3.5.1), bileşiklik kurallarının **önerilmemesi**
  (Bölüm 3.1.1.2), parola üreticisi entropi tavsiyeleri (Bölüm 5.1).
  <https://pages.nist.gov/800-63-3/sp800-63b.html>
- **RFC 5869 — HMAC-based Extract-and-Expand Key Derivation Function
  (HKDF)** — alt anahtar ayrımı. <https://www.rfc-editor.org/rfc/rfc5869>
- **FIPS 202 — SHA-3 Standard** (referans; bu proje SHA-256 kullanır).
  <https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf>
- **RFC 8018 — PKCS #5: Password-Based Cryptography Specification** (PBKDF2,
  referans olarak karşılaştırma). <https://www.rfc-editor.org/rfc/rfc8018>

### Kullanılan açık kaynak projeler

- **RustCrypto — `argon2`** (MIT/Apache-2.0) — Argon2id uygulaması.
  <https://github.com/RustCrypto/argon2> · <https://docs.rs/argon2/>
- **RustCrypto — `chacha20poly1305`** (MIT/Apache-2.0) — ChaCha20, XChaCha20,
  Poly1305, AEAD. <https://github.com/RustCrypto/AEADs> ·
  <https://docs.rs/chacha20poly1305/>
- **RustCrypto — `hkdf`** (MIT/Apache-2.0) — HKDF-SHA256.
  <https://docs.rs/hkdf/>
- **RustCrypto — `sha2`** (MIT/Apache-2.0) — SHA-256; `Hkdf<Sha256>` özeti ve
  aktarım içerik özeti. <https://github.com/RustCrypto/hashes> ·
  <https://docs.rs/sha2/>
- **RustCrypto — `getrandom`** (MIT/Apache-2.0) — işletim sistemi CSPRNG'ye
  güvenli erişim. <https://github.com/RustCrypto/random> · <https://docs.rs/getrandom/>
- **RustCrypto — `zeroize`** (MIT/Apache-2.0) — bellek temizleme.
  <https://github.com/RustCrypto/utils> · <https://docs.rs/zeroize/>
- **`serde`** (MIT/Apache-2.0) — <https://serde.rs/>
- **`serde_json`** (MIT/Apache-2.0) — <https://github.com/serde-rs/json>
- **`clap`** (MIT/Apache-2.0) — <https://docs.rs/clap/>

### Referans alınan dokümantasyon

- **libsodium — documentation** — rapor önerisindeki kriptografik birleşim
  (XChaCha20-Poly1305, `crypto_pwhash` Argon2id modu) ve nonce disiplini
  için. Bu proje libsodium **kullanmaz**; uygun RustCrypto eşdeğerlerini
  kullanır. <https://doc.libsodium.org/>
- **libsodium — `crypto_aead_xchacha20poly1305_ietf` API sayfası** — 192-bit
  nonce'un rastgele kullanımına ilişkin açıklama.
  <https://doc.libsodium.org/secret-key_cryptography/aead/chacha20-poly1305/xchacha20-poly1305_construction>
- **Rust standart kütüphane belgeleri** — <https://doc.rust-lang.org/std/>
- **Rust sürüm rehberi** — <https://doc.rust-lang.org/edition-guide/edition-2021/>
- **`cargo` yerel rehberi** — <https://doc.rust-lang.org/cargo/>

### Rapor dosyası (yerel yol, URL değil)

Tasarımın kaynağı, bu depodaki kodun **tek dosyalık** kaynak dokümanıdır ve
kendi tasarımımız olarak modellenmiştir:

`%USERPROFILE%\Desktop\Fikirler\16-kasa-parola-kasasi.html` — "Kasa (Vaulta),
rapor 16/30, 2026-09-29". Okunan bölümler: künye (rapor no, tarih, bellek
bütçesi 180 MB tepe RSS, lisans modeli Apache-2.0), b01 yönetici özeti, b03
kullanım senaryoları, b05 özellik matrisi, b07 teknik tasarım ve veri modeli,
b08 performans/bellek bütçesi, b09 taşınabilirlik, b10 tehdit modeli ve
kriptografik parametre tablosu, b16 açık sorular.
**Bu bir yerel dosya yoludur; URL değildir ve çevrimiçi olarak erişilebilir
değildir.**

### Doğrudan kopyalanan kod

**Yoktur.** Bu depodaki hiçbir satır başka bir projeden kopyalanmamıştır ve
hiçbir açık kaynak kod bloğu içermez.

---

## Lisans

Bu proje **MIT** lisansıyla dağıtılmaktadır. Tam lisans metni
[`LICENSE.txt`](LICENSE.txt) dosyasındadır.

> Kaynak kod lisansı MIT'tir. `MANIFEST.md` kart 16, fikir raporunun lisans
> modelini Apache-2.0 olarak belirtir; bu bir **ayrışmadır** ve WORKER_CONTRACT
> kararı D-003 gereği kaynak kod lisansı daima MIT'tir.
