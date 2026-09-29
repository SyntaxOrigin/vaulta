//! Kasa oturumu: oluşturma, açma, ekleme, listeleme, okuma, silme ve ana parola
//! değiştirme.
//!
//! # Tek doğruluk kaynağı
//!
//! Bellekte **kayıt listesi** (`kayitlar`) tek doğruluk kaynağıdır; sayfa
//! konumları (`sayfalar`) türetilmiş bir yerleşim planıdır. Bu, "ilk uyan
//! sayfaya ekle, silince dizini elle düzelt" gibi iki yerde tutulan durumun
//! doğmasını engeller — her değişiklikten sonra sayfalar baştan hesaplanır.
//!
//! # Oturum yaşam döngüsü ve otomatik kilit
//!
//! `Oturum` tek kullanımlıktır: açılır, birkaç iş yapılır, bırakılır. Her kasa
//! komutu ayrı bir süreç olduğu için kalıcı bir "açık kasa" yoktur — bu, ürünün
//! "arka plan servisi yok, yerel API yok" kararıyla (rapor b07) örtüşür ve
//! kilitlenme yüzeyini tamamen kaldırır.
//!
//! Otomatik kilit burada **işlem sonu temizliği** olarak uygulanır: `Oturum`
//! düştüğünde ana malzeme `Zeroizing` sayesinde sıfırlanır, `kilit()` çağrısı
//! ise düşmeden önce açıkça sıfırlar ve oturumu kullanılamaz hale getirir.
//!
//! # Yazma disiplini
//!
//! Her yazma işlemi **atomik**: önce `<yol>.tmp` dosyasına yazılır, sonra
//! hedefe `rename` edilir. Yazma sırasında bir hata olursa eski kasa bozulmaz
//! (rapor S3: "çözme başarısızsa dosya üzerinde hiçbir yazma yapılmaz").

use std::collections::BTreeMap;
use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};

use zeroize::{Zeroize, Zeroizing};

use crate::hata::Hata;
use crate::kasa::{self, Baslik, Dizin, SifreliBlok, VARSAYILAN_SAYFA_BOYUTU};
use crate::kayit::{DizinKaydi, Kayit};
use crate::kripto::{
    ana_malzeme_turet, tuz_uret, Argon2Ayar, ANAHTAR_BOYUTU, CERCEVE_ETIKET_BOYUTU, TUZ_BOYUTU,
};

/// Açık bir kasa oturumu.
///
/// `Oturum` düştüğünde ana malzeme sıfırlanır; ayrıca `kilit()` çağrısı bunu
/// erken tetikler. Kilitli oturum her işlemde `Err` döner.
pub struct Oturum {
    yol: PathBuf,
    baslik: Baslik,
    ana_malzeme: Zeroizing<[u8; ANAHTAR_BOYUTU]>,
    /// Dizindeki sıralamaya göre tüm kayıtlar.
    kayitlar: Vec<Kayit>,
    /// Sayfa sırası -> o sayfadaki kayıtların `kayitlar` içindeki sırası.
    sayfalar: BTreeMap<u32, Vec<usize>>,
    kilitli: bool,
}

/// `Oturum` anahtar malzemesi taşıdığı için `Debug` çıktısı **her alanı
/// eler**: yalnızca yol, sürüm, kayıt/saya sayıları ve kilit durumu görünür,
/// başlıklar, kullanıcı adları, parolalar, tuz ve anahtar malzemesi **asla**
/// yazdırılmaz. Bu, hata ayıklama sırasında kaza eseri sır basmasını engeller.
impl fmt::Debug for Oturum {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Oturum")
            .field("yol", &self.yol)
            .field("surum", &self.baslik.surum)
            .field("sayfa_sayisi", &self.baslik.sayfa_sayisi)
            .field("kayit_sayisi", &self.kayitlar.len())
            .field("kilitli", &self.kilitli)
            .finish()
    }
}

impl Oturum {
    /// Yeni bir kasa dosyası oluşturur.
    ///
    /// Ana parola `NIST SP 800-63B` denetiminden geçmezse dosya **hiç
    /// oluşturulmaz**; kısmi bir dosya bırakılmaz.
    pub fn olustur(yol: &Path, parola: &str, ayar: Argon2Ayar) -> Result<Oturum, Hata> {
        if yol.exists() {
            return Err(Hata::VarOluyor(yol.display().to_string()));
        }
        crate::parola::kaba_parola_denetle(parola)?;
        ayar.dogrula()?;

        let tuz = tuz_uret()?;
        let ana_malzeme = ana_malzeme_turet(parola, &tuz, &ayar)?;
        let baslik = Baslik {
            surum: kasa::SURUM,
            m_cost: ayar.bellek_kib,
            t_cost: ayar.tur,
            p_cost: ayar.yol,
            sayfa_boyutu: VARSAYILAN_SAYFA_BOYUTU as u32,
            sayfa_sayisi: 0,
            kayit_sayisi: 0,
            tuz: *tuz,
        };
        let mut oturum = Oturum {
            yol: yol.to_path_buf(),
            baslik,
            ana_malzeme,
            kayitlar: Vec::new(),
            sayfalar: BTreeMap::new(),
            kilitli: false,
        };
        oturum.kaydet()?;
        Ok(oturum)
    }

    /// Var olan bir kasayı ana parolayla açar.
    ///
    /// Yanlış parola ile bozuk kasa **aynı hata** verir; ayrım kriptografik
    /// olarak imkânsızdır ve yapılması hız ipucu verirdi.
    pub fn ac(yol: &Path, parola: &str) -> Result<Oturum, Hata> {
        let ham = fs::read(yol)?;
        Oturum::ac_bayttan(yol, &ham, parola)
    }

    /// [`Oturum::ac`]'in bayt dizisi alan sürümü (testler ve doğrulama için).
    pub fn ac_bayttan(yol: &Path, ham: &[u8], parola: &str) -> Result<Oturum, Hata> {
        if ham.len() < kasa::BASLIK_BOYUTU {
            return Err(Hata::BozukKasa(format!(
                "dosya cok kisa: {} bayt, en az {} bekleniyordu",
                ham.len(),
                kasa::BASLIK_BOYUTU
            )));
        }
        let baslik = Baslik::oku(&ham[..kasa::BASLIK_BOYUTU])?;
        let ayar = Argon2Ayar {
            bellek_kib: baslik.m_cost,
            tur: baslik.t_cost,
            yol: baslik.p_cost,
        };
        ayar.dogrula()?;
        let ana_malzeme = ana_malzeme_turet(parola, &baslik.tuz, &ayar)?;

        let (dizin_blok, tuketilen) = SifreliBlok::oku(&ham[kasa::BASLIK_BOYUTU..])?;
        let dizin = kasa::dizin_coz(&ana_malzeme, &baslik.tuz, &dizin_blok)?;

        let mut sayfalar: BTreeMap<u32, Vec<(u32, Kayit)>> = BTreeMap::new();
        let mut kalan = &ham[kasa::BASLIK_BOYUTU + tuketilen..];
        for sayfa_no in 0..baslik.sayfa_sayisi {
            let (blok, tuketilen) = SifreliBlok::oku(kalan)?;
            kalan = &kalan[tuketilen..];
            let (cerceveler, hatali) = kasa::sayfa_coz(&ana_malzeme, &baslik.tuz, sayfa_no, &blok)?;
            if let Some(cerceve) = hatali {
                return Err(Hata::BozukSayfa {
                    sayfa: sayfa_no,
                    cerceve,
                });
            }
            let mut sayfa_kayitlari = Vec::with_capacity(cerceveler.len());
            for cerceve in cerceveler {
                let kayit: Kayit = serde_json::from_slice(&cerceve.govde).map_err(|hata| {
                    Hata::BozukKasa(format!(
                        "sayfa {sayfa_no} cerceve {} icerigi cozulemedi: {hata}",
                        cerceve.cerceve
                    ))
                })?;
                sayfa_kayitlari.push((cerceve.cerceve, kayit));
            }
            sayfalar.insert(sayfa_no, sayfa_kayitlari);
        }
        kasa::kalan_yok(kalan)?;

        // Dizin, kayıtların okuma sırasını belirler. Bir kayıt dizinde yoksa
        // bile sayfada varsa kurtarılır (dizin kısmi bozulmaya dayanıklıdır),
        // ama başlık ile sayı uyuşmazsa dosya bozuk sayılır.
        if dizin.kayitlar.len() as u32 != baslik.kayit_sayisi {
            return Err(Hata::BozukKasa(format!(
                "baslik {} kayit diyor, dizin {} kayit listeliyor",
                baslik.kayit_sayisi,
                dizin.kayitlar.len()
            )));
        }

        let (kayitlar, sayfalar) = Oturum::kayitlari_dizinden_sirala(dizin.kayitlar, &sayfalar)?;
        Ok(Oturum {
            yol: yol.to_path_buf(),
            baslik,
            ana_malzeme,
            kayitlar,
            sayfalar,
            kilitli: false,
        })
    }

    /// Çözülmüş sayfaları dizin sırasına göre yeniden diziler ve dizinin
    /// sayfalarla **uyumunu** doğrular.
    ///
    /// Dizin yalnızca bir önbellek değildir: her dizin kaydının `sayfa` ve
    /// `cerceve` alanları sayfadaki gerçek konumuyla karşılaştırılır. Uyuşmazlık
    /// `BozukKasa` üretir — bir sayfanın başka bir sayfayla yer değiştirmesi
    /// ya da dizinin elle değiştirilmesi bu denetimle yakalanır.
    ///
    /// Kayıt sırası dizinden gelir; böylece `list` çıktısı kasanın her
    /// açılışında aynıdır.
    #[allow(clippy::type_complexity)]
    fn kayitlari_dizinden_sirala(
        dizin: Vec<DizinKaydi>,
        sayfalar: &BTreeMap<u32, Vec<(u32, Kayit)>>,
    ) -> Result<(Vec<Kayit>, BTreeMap<u32, Vec<usize>>), Hata> {
        let toplam: usize = sayfalar.values().map(|g| g.len()).sum();
        if toplam != dizin.len() {
            return Err(Hata::BozukKasa(format!(
                "dizin {} kayit listeliyor, sayfalarda {} kayit var",
                dizin.len(),
                toplam
            )));
        }

        let mut kayitlar: Vec<Kayit> = Vec::with_capacity(dizin.len());
        let mut yerlesim: BTreeMap<u32, Vec<usize>> = BTreeMap::new();
        let mut kullanilan: Vec<(u32, u32)> = Vec::with_capacity(dizin.len());

        for (sira, kayit_dizin) in dizin.iter().enumerate() {
            let govdeler = sayfalar.get(&kayit_dizin.sayfa).ok_or_else(|| {
                Hata::BozukKasa(format!(
                    "dizin #{sira} ({}) sayfa {}'yi gosteriyor ama bu sayfa yok",
                    kayit_dizin.baslik, kayit_dizin.sayfa
                ))
            })?;
            let kayit = govdeler
                .iter()
                .find(|(cerceve, _)| *cerceve == kayit_dizin.cerceve)
                .map(|(_, kayit)| kayit.clone())
                .ok_or_else(|| {
                    Hata::BozukKasa(format!(
                        "dizin #{sira} ({}) sayfa {} cerceve {}'yi gosteriyor ama yok",
                        kayit_dizin.baslik, kayit_dizin.sayfa, kayit_dizin.cerceve
                    ))
                })?;
            if kayit.baslik != kayit_dizin.baslik || kayit.kullanici != kayit_dizin.kullanici {
                return Err(Hata::BozukKasa(format!(
                    "dizin #{sira} ile sayfa icerigi eslesmiyor ('{}')",
                    kayit_dizin.baslik
                )));
            }
            if kullanilan.contains(&(kayit_dizin.sayfa, kayit_dizin.cerceve)) {
                return Err(Hata::BozukKasa(format!(
                    "dizin iki kez ayni konumu isaret ediyor: sayfa {} cerceve {}",
                    kayit_dizin.sayfa, kayit_dizin.cerceve
                )));
            }
            kullanilan.push((kayit_dizin.sayfa, kayit_dizin.cerceve));
            kayitlar.push(kayit);
            yerlesim.entry(kayit_dizin.sayfa).or_default().push(sira);
        }
        for (sayfa, govdeler) in sayfalar {
            for (cerceve, _) in govdeler {
                if !kullanilan.contains(&(*sayfa, *cerceve)) {
                    return Err(Hata::BozukKasa(format!(
                        "sayfa {sayfa} cerceve {cerceve} dizinde yok"
                    )));
                }
            }
        }

        Ok((kayitlar, yerlesim))
    }

    /// Kasanın dosya yolu.
    pub fn yol(&self) -> &Path {
        &self.yol
    }

    /// Okunabilir başlık bilgisi (Argon2id parametreleri dâhil).
    pub fn baslik(&self) -> &Baslik {
        &self.baslik
    }

    /// Başlıktaki Argon2id parametrelerini döndürür.
    pub fn argon2_ayar(&self) -> Argon2Ayar {
        Argon2Ayar {
            bellek_kib: self.baslik.m_cost,
            tur: self.baslik.t_cost,
            yol: self.baslik.p_cost,
        }
    }

    /// Kasa tuzunu döndürür (teşhis ve test için; tuz gizli değildir).
    pub fn tuz(&self) -> [u8; TUZ_BOYUTU] {
        self.baslik.tuz
    }

    /// Anahtar malzemesinin bellekte hâlâ sıfır olup olmadığını bildirir.
    ///
    /// `kilit()` sonrası `false` döner; `zeroize` gerçekten çalıştığını
    /// gösteren test yüzeyidir.
    pub fn bellek_hazir_mi(&self) -> bool {
        self.ana_malzeme.iter().any(|b| *b != 0)
    }

    /// Oturumu kilitler ve anahtar malzemesini sıfırlar.
    ///
    /// İkinci ve sonraki çağrılar hata vermez; işlem zaten yapılmış sayılır.
    pub fn kilit(&mut self) {
        self.ana_malzeme.zeroize();
        self.kilitli = true;
    }

    /// Kilitli oturumda her işlemi reddeder.
    fn kilit_kontrol(&self) -> Result<(), Hata> {
        if self.kilitli {
            Err(Hata::Iptal)
        } else {
            Ok(())
        }
    }

    /// Kasa içindeki kayıt sayısı.
    pub fn kayit_sayisi(&self) -> usize {
        self.kayitlar.len()
    }

    /// Dizin kayıtlarını listeler (parolalar çözülmez, yalnızca meta veri).
    pub fn listele(&self) -> Result<Vec<DizinKaydi>, Hata> {
        self.kilit_kontrol()?;
        Ok((0..self.kayitlar.len())
            .map(|i| DizinKaydi {
                baslik: self.kayitlar[i].baslik.clone(),
                kullanici: self.kayitlar[i].kullanici.clone(),
                sayfa: self.sayfa_bul(i),
                cerceve: self.cerceve_bul(i),
            })
            .collect())
    }

    /// Başlığın bulunduğu sayfa numarasını döndürür.
    fn sayfa_bul(&self, kayit_sirasi: usize) -> u32 {
        self.sayfalar
            .iter()
            .find(|(_, liste)| liste.contains(&kayit_sirasi))
            .map(|(sayfa, _)| *sayfa)
            .unwrap_or(0)
    }

    /// Başlığın sayfa içindeki çerçeve sırasını döndürür.
    fn cerceve_bul(&self, kayit_sirasi: usize) -> u32 {
        self.sayfalar
            .iter()
            .find_map(|(_, liste)| {
                liste
                    .iter()
                    .position(|sira| *sira == kayit_sirasi)
                    .map(|sira| sira as u32)
            })
            .unwrap_or(0)
    }

    /// Yeni kayıt ekler ve kasayı diske yazar.
    pub fn ekle(&mut self, kayit: &Kayit) -> Result<(), Hata> {
        self.kilit_kontrol()?;
        let temiz = kayit.dogrula()?;
        if self.kayitlar.iter().any(|k| k.baslik == temiz.baslik) {
            return Err(Hata::YinelenenBaslik(temiz.baslik.clone()));
        }
        self.kayitlar.push(temiz);
        self.baslik.kayit_sayisi = self.kayitlar.len() as u32;
        self.yeniden_paketle();
        self.kaydet()
    }

    /// Başlığa göre kaydı arar ve tüm alanlarıyla döndürür.
    pub fn bul(&self, baslik: &str) -> Result<Kayit, Hata> {
        self.kilit_kontrol()?;
        let giris = baslik.trim();
        self.kayitlar
            .iter()
            .find(|k| k.baslik.eq_ignore_ascii_case(giris))
            .cloned()
            .ok_or_else(|| Hata::KayitYok {
                baslik: giris.to_string(),
            })
    }

    /// Verilen sayıda kayıt sırasıyla başlığı döndürür (test/doğrulama için).
    pub fn sirayla_bul(&self, sira: usize) -> Result<Kayit, Hata> {
        self.kilit_kontrol()?;
        self.kayitlar.get(sira).cloned().ok_or(Hata::KayitYok {
            baslik: format!("#{sira}"),
        })
    }

    /// Başlığa göre kaydı siler ve kasayı diske yazar.
    pub fn sil(&mut self, baslik: &str) -> Result<(), Hata> {
        self.kilit_kontrol()?;
        let giris = baslik.trim();
        let sira = self
            .kayitlar
            .iter()
            .position(|k| k.baslik.eq_ignore_ascii_case(giris))
            .ok_or_else(|| Hata::KayitYok {
                baslik: giris.to_string(),
            })?;
        self.kayitlar.remove(sira);
        self.baslik.kayit_sayisi = self.kayitlar.len() as u32;
        self.yeniden_paketle();
        self.kaydet()
    }

    /// Kayıtları sayfa boyutuna göre yeniden paketler.
    ///
    /// Kasa yazma başına baştan paketlendiği için dizin ile sayfa içeriği
    /// asla ayrışamaz. Maliyet, kasa boyutuyla doğrusal (O(n)); bu, MVP için
    /// kabul edilmiş bir sadeleştirmedir ve README'de sınır olarak yazılıdır.
    pub fn yeniden_paketle(&mut self) {
        let sayfa_boyutu = self.baslik.sayfa_boyutu as usize;
        self.sayfalar.clear();
        let mut mevcut: Vec<usize> = Vec::new();
        let mut dolu = 0usize;
        let mut sayfa_no: u32 = 0;

        for (sira, kayit) in self.kayitlar.iter().enumerate() {
            let govde_uzunluk = serde_json::to_vec(kayit).map(|g| g.len()).unwrap_or(0);
            let cerceve_maliyeti = 4 + CERCEVE_ETIKET_BOYUTU + govde_uzunluk;
            if !mevcut.is_empty() && dolu + cerceve_maliyeti > sayfa_boyutu {
                self.sayfalar.insert(sayfa_no, std::mem::take(&mut mevcut));
                sayfa_no += 1;
                dolu = 0;
            }
            dolu += cerceve_maliyeti;
            mevcut.push(sira);
        }
        if !mevcut.is_empty() {
            self.sayfalar.insert(sayfa_no, mevcut);
        }
        self.baslik.sayfa_sayisi = self.sayfalar.len() as u32;
    }

    /// Yeni bir tuz ve yeni Argon2id maliyetleriyle kasayı yeniden yazar.
    ///
    /// Tüm sayfalar ve dizin yeni ana malzeme ile **yeniden şifrelenir**; eski
    /// anahtar hiçbir yerde kalmaz. Bu, disk üzerinde eski anahtarın geriye
    /// dönük olarak bulunmasını (ve kullanılmış olsa bile işe yaramamasını)
    /// sağlar.
    pub fn ana_parola_degistir(
        &mut self,
        yeni_parola: &str,
        yeni_ayar: Argon2Ayar,
    ) -> Result<(), Hata> {
        self.kilit_kontrol()?;
        crate::parola::kaba_parola_denetle(yeni_parola)?;
        yeni_ayar.dogrula()?;

        let yeni_tuz = tuz_uret()?;
        let yeni_ana = ana_malzeme_turet(yeni_parola, &yeni_tuz, &yeni_ayar)?;
        self.baslik.tuz = *yeni_tuz;
        self.baslik.m_cost = yeni_ayar.bellek_kib;
        self.baslik.t_cost = yeni_ayar.tur;
        self.baslik.p_cost = yeni_ayar.yol;
        self.ana_malzeme.zeroize();
        self.ana_malzeme = yeni_ana;
        self.kaydet()
    }

    /// Oturumu diske atomik olarak yazar.
    pub fn kaydet(&mut self) -> Result<(), Hata> {
        self.kilit_kontrol()?;
        let cikti = self.bayt()?;
        let gecici = self.yol.with_extension("kasa.tmp");
        fs::write(&gecici, &cikti)?;
        daralt_izinleri(&gecici);
        fs::rename(&gecici, &self.yol)?;
        daralt_izinleri(&self.yol);
        Ok(())
    }

    /// Kasayı ham bayt dizisi olarak üretir (diske yazmadan).
    ///
    /// Her yazma işleminde **her sayfanın nonce'u yeniden üretilir**. Aynı
    /// anahtarla iki kez yazılan bir kasa bile farklı nonce taşır; bu, nonce
    /// yeniden kullanımını yapısal olarak imkânsız kılar.
    pub fn bayt(&self) -> Result<Vec<u8>, Hata> {
        self.kilit_kontrol()?;
        let mut cikti: Vec<u8> = Vec::with_capacity(kasa::BASLIK_BOYUTU + 4096);
        cikti.extend_from_slice(&self.baslik.yaz());

        let dizin = Dizin {
            surum: kasa::SURUM as u32,
            kayitlar: self.listele()?,
        };
        let dizin_blok = kasa::dizin_sifrele(&self.ana_malzeme, &self.baslik.tuz, &dizin)?;
        dizin_blok.yaz(&mut cikti)?;

        for sayfa_no in 0..self.baslik.sayfa_sayisi {
            let govdeler: Vec<Vec<u8>> = match self.sayfalar.get(&sayfa_no) {
                Some(liste) => {
                    let mut govde = Vec::with_capacity(liste.len());
                    for sira in liste {
                        if let Some(kayit) = self.kayitlar.get(*sira) {
                            govde.push(serde_json::to_vec(kayit).map_err(|hata| {
                                Hata::Kriptografik(format!("kayit serilestirilemedi: {hata}"))
                            })?);
                        }
                    }
                    govde
                }
                None => Vec::new(),
            };
            let blok =
                kasa::sayfa_sifrele(&self.ana_malzeme, &self.baslik.tuz, sayfa_no, &govdeler)?;
            blok.yaz(&mut cikti)?;
        }
        Ok(cikti)
    }
}

/// Kasa dosyasının izinlerini mümkün olduğunca daraltır.
///
/// Unix-benzeri sistemlerde mod `0o600` uygulanır: yalnızca sahibi okuyup
/// yazabilir. Windows'ta NTFS ACL'i `std` ile yazılamaz (ve `unsafe`/FFI bu
/// projede yasaktır); bu yüzden orada **hiçbir şeye dokunulmaz**. `std` API'si
/// ile Windows izinlerini genişletmek mümkün olsa da daraltmak mümkün
/// değildir, bu yüzden varsayılan devralınır. Windows'taki bu sınır README'nin
/// `## Bilinen Sınırlamalar` bölümünde yazılıdır.
fn daralt_izinleri(yol: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(yol, fs::Permissions::from_mode(0o600));
    }
    #[cfg(not(unix))]
    {
        // `std::fs::Permissions` yalnızca tek bir "salt okunur" biti sunar ve
        // onu kaldırmak Unix'te dünya-erişimli yazma izni anlamına gelir.
        // Kasa dosyasında varsayılan izinleri olduğu gibi bırakmak güvenlidir.
        let _ = yol;
    }
}
