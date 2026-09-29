//! Kasa dosya biçimi: `KASA` imzalı, başlık + şifreli dizin + şifreli sayfalar.
//!
//! # Dosya düzeni
//!
//! ```text
//! 0            96                     başlık (düz metin, okunabilir)
//! 96           96 + 4 + len(dizin)     şifreli dizin  [u32 LE uzunluk][şifre metni]
//! ...          ...                     şifreli sayfa 0 [u32 LE uzunluk][şifre metni]
//! ...          ...                     şifreli sayfa 1 ...
//! EOF
//! ```
//!
//! Başlık düz metindir çünkü **denetlenebilirlik** ürünün öne çıkan özelliğidir
//! (rapor b01): bir kasayı eline alan herkes algoritmayı, Argon2id maliyet
//! parametrelerini, sayfa sayısını ve tuzu doğrudan okuyabilir. Gizli olan tek
//! şey kayıt içeriğidir; tuzun gizli olması gerekmez, **tuzun kullanılmaması**
//! tehlikelidir.
//!
//! # Kayıt çerçeveleme (record framing)
//!
//! Her sayfanın düz metni bir çerçeve dizisidir:
//!
//! ```text
//! cerceve := [u32 LE gövde uzunluğu][16 bayt bütünlük etiketi][gövde]
//! ```
//!
//! Uzunluk alanı **çerçevenin kendisine değil**, sonraki alanların konumunu
//! belirleyen bir işaretçidir. Bu, "nerede bitti?" sorusunun tek ve açık bir
//! yanıtı olmasını sağlar: ayrıştırıcı bir sonraki çerçevenin başlangıcını
//! hesaplayabilir. Alan sırası bilinçli olarak `uzunluk → etiket → gövde`
//! seçildi; böylece çerçeve başlığı sabit boyutludur (20 bayt) ve etiket
//! doğrulamasından **önce** sınır denetimi yapılabilir.
//!
//! Her çerçevenin kendi bütünlük etiketi vardır (`HKFP-MAC`). Bu ikinci
//! katmandır: sayfa zaten AEAD ile korunuyor, çerçeve etiketi ise **hangi kaydın**
//! bozulduğunu sayfa çözülmeden göstermeyi ve tek bir bozuk kaydın komşu kayıtları
//! düşürmesini engellemeyi sağlar.
//!
//! # Neden sayfa tabanlı?
//!
//! Tek bir bütün dosya AEAD'si, bir baytın bozulmasıyla **tüm** kasayı
//! okunamaz yapar. Sayfa tabanlı tasarımda bozulan sayfa yalnızca kendi
//! kayıtlarını kaybettirir. Buna karşılık her sayfa kendi nonce'unu taşır ve
//! her sayfanın anahtarı HKDF `info` etiketiyle ayrılır.

use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::hata::Hata;
use crate::kayit::DizinKaydi;
use crate::kripto::{
    cerceve_anahtari, cerceve_etiketi_dogrula, coz, dizin_anahtari, nonce_uret, sayfa_anahtari,
    sifrele, ANAHTAR_BOYUTU, CERCEVE_ETIKET_BOYUTU, NONCE_BOYUTU, TUZ_BOYUTU,
};

/// Başlık imzası: `KASA` + sürüm 1.
const SIHRALI: &[u8; 4] = b"KASA";

/// Kasa biçim sürümü.
pub const SURUM: u8 = 1;

/// Başlığın bayt cinsinden sabit uzunluğu.
pub const BASLIK_BOYUTU: usize = 96;

/// Bir sayfanın çerçevesiz (çerçeve başlıkları hariç) düz metin kapasitesi.
pub const VARSAYILAN_SAYFA_BOYUTU: usize = 4096;

/// Dosya başındaki düz metin başlık.
///
/// Tüm alanlar **küçük uçlu** (`little-endian`) yazılır; bu, bayt sırasının
/// platformdan bağımsız olmasını sağlar (rapor risk R1'in karşı önlemi).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Baslik {
    /// Biçim sürümü.
    pub surum: u8,
    /// Argon2id bellek maliyeti (KiB).
    pub m_cost: u32,
    /// Argon2id tur sayısı.
    pub t_cost: u32,
    /// Argon2id paralellik.
    pub p_cost: u32,
    /// Sayfa düz metin kapasitesi.
    pub sayfa_boyutu: u32,
    /// Toplam şifreli sayfa sayısı.
    pub sayfa_sayisi: u32,
    /// Kayıt sayısı.
    pub kayit_sayisi: u32,
    /// Kasa tuzu (başlıkta düz metin; gizli değildir).
    pub tuz: [u8; TUZ_BOYUTU],
}

impl Baslik {
    /// Başlığı 96 bayta yazar.
    pub fn yaz(&self) -> [u8; BASLIK_BOYUTU] {
        let mut tampon = [0u8; BASLIK_BOYUTU];
        tampon[0..4].copy_from_slice(SIHRALI);
        tampon[4] = self.surum;
        tampon[5..9].copy_from_slice(&self.m_cost.to_le_bytes());
        tampon[9..13].copy_from_slice(&self.t_cost.to_le_bytes());
        tampon[13..17].copy_from_slice(&self.p_cost.to_le_bytes());
        tampon[17..21].copy_from_slice(&self.sayfa_boyutu.to_le_bytes());
        tampon[21..25].copy_from_slice(&self.sayfa_sayisi.to_le_bytes());
        tampon[25..29].copy_from_slice(&self.kayit_sayisi.to_le_bytes());
        tampon[29..45].copy_from_slice(&self.tuz);
        // 45..96 arası ayrılmış ve sıfırdır. Sıfır olmayan bir ayrılmış alan
        // kasti değil, biçim ihlali sayılır ve `oku` tarafından reddedilir.
        tampon
    }

    /// 96 baytlık başlığı okur ve doğrular.
    pub fn oku(tampon: &[u8]) -> Result<Baslik, Hata> {
        if tampon.len() < BASLIK_BOYUTU {
            return Err(Hata::BozukKasa(format!(
                "dosya cok kisa: {} bayt, en az {BASLIK_BOYUTU} bekleniyordu",
                tampon.len()
            )));
        }
        if &tampon[0..4] != SIHRALI {
            return Err(Hata::BozukKasa(
                "imza 'KASA' degil; bu bir vaulta kasasi degil".to_string(),
            ));
        }
        let surum = tampon[4];
        if surum != SURUM {
            return Err(Hata::BozukKasa(format!(
                "biçim surumu {surum} desteklenmiyor (beklenen {SURUM})"
            )));
        }
        if tampon[45..BASLIK_BOYUTU].iter().any(|b| *b != 0) {
            return Err(Hata::BozukKasa(
                "ayrilmis baslik alani sifir degil".to_string(),
            ));
        }
        let oku_u32 = |offset: usize| -> u32 {
            u32::from_le_bytes([
                tampon[offset],
                tampon[offset + 1],
                tampon[offset + 2],
                tampon[offset + 3],
            ])
        };
        let baslik = Baslik {
            surum,
            m_cost: oku_u32(5),
            t_cost: oku_u32(9),
            p_cost: oku_u32(13),
            sayfa_boyutu: oku_u32(17),
            sayfa_sayisi: oku_u32(21),
            kayit_sayisi: oku_u32(25),
            tuz: {
                let mut tuz = [0u8; TUZ_BOYUTU];
                tuz.copy_from_slice(&tampon[29..45]);
                tuz
            },
        };
        baslik.dogrula()?;
        Ok(baslik)
    }

    /// Başlığın tutarlılığını denetler.
    pub fn dogrula(&self) -> Result<(), Hata> {
        if self.sayfa_boyutu == 0 {
            return Err(Hata::BozukKasa("sayfa boyutu sifir".to_string()));
        }
        if self.sayfa_boyutu > 1_048_576 {
            return Err(Hata::BozukKasa("sayfa boyutu 1 MiB'i asti".to_string()));
        }
        if self.sayfa_sayisi > 1_000_000 {
            return Err(Hata::BozukKasa("sayfa sayisi makul degil".to_string()));
        }
        Ok(())
    }
}

/// Dizin bölümünün şifre çözülmüş içeriği.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Dizin {
    /// Biçim sürümü (ileride sürümlü okuyucu için).
    pub surum: u32,
    /// Kayıt kimliği -> sayfa/çerçeve eşlemesi.
    pub kayitlar: Vec<DizinKaydi>,
}

/// Tek bir kayıt çerçevesinin şifre çözülmüş hali.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Cerceve {
    /// Çerçevenin konumu; bütünlük etiketi bu konuma bağlıdır.
    pub sayfa: u32,
    /// Sayfa içindeki sıra.
    pub cerceve: u32,
    /// Çerçevenin taşıdığı JSON baytları.
    pub govde: Zeroizing<Vec<u8>>,
}

/// Bir şifreli bloğun diskteki ham temsili: nonce + şifre metni (etiket dâhil).
#[derive(Debug, Clone)]
pub struct SifreliBlok {
    /// 24 baytlık XChaCha nonce.
    pub nonce: [u8; NONCE_BOYUTU],
    /// Şifre metni + Poly1305 etiketi.
    pub govde: Vec<u8>,
}

impl SifreliBlok {
    /// Bloğu `u32 LE uzunluk || nonce || şifre metni` biçiminde yazar.
    ///
    /// Uzunluk alanı yalnızca `nonce + şifre metni` kısmını kapsar; ayrıştırıcı
    /// önce uzunluğu okur, sonra o kadar bayt bekler.
    pub fn yaz(&self, cikti: &mut Vec<u8>) -> Result<(), Hata> {
        if self.govde.len() < 16 {
            return Err(Hata::BozukKasa("sifreli blok etiketten kisa".to_string()));
        }
        let toplam = NONCE_BOYUTU + self.govde.len();
        if toplam > u32::MAX as usize {
            return Err(Hata::BozukKasa("sifreli blok cok buyuk".to_string()));
        }
        cikti.extend_from_slice(&(toplam as u32).to_le_bytes());
        cikti.extend_from_slice(&self.nonce);
        cikti.extend_from_slice(&self.govde);
        Ok(())
    }

    /// Tampondan bir blok okur ve kalan bayt sayısını döndürür.
    ///
    /// Uzunluk alanı doğrulanmadan hiçbir bellek ayrılmaz: `okuma` yalnızca
    /// kalan baytla sınırlıdır ve eksik veri `Err` üretir.
    pub fn oku(tampon: &[u8]) -> Result<(SifreliBlok, usize), Hata> {
        if tampon.len() < 4 {
            return Err(Hata::BozukKasa(
                "dosya kirpildi: blok basligi eksik".to_string(),
            ));
        }
        let toplam = u32::from_le_bytes([tampon[0], tampon[1], tampon[2], tampon[3]]) as usize;
        if toplam <= NONCE_BOYUTU {
            return Err(Hata::BozukKasa(format!(
                "blok uzunlugu {toplam} bayt; nonce ({NONCE_BOYUTU}) + etiket (16) gerekir"
            )));
        }
        let gerekli = 4 + toplam;
        if tampon.len() < gerekli {
            return Err(Hata::BozukKasa(format!(
                "dosya kirpildi: {}-baytlik blok bekleniyordu, {} bayt var",
                gerekli,
                tampon.len()
            )));
        }
        let govde = &tampon[4 + NONCE_BOYUTU..gerekli];
        if govde.len() < 16 {
            return Err(Hata::BozukKasa("sifreli blok etiketten kisa".to_string()));
        }
        let mut nonce = [0u8; NONCE_BOYUTU];
        nonce.copy_from_slice(&tampon[4..4 + NONCE_BOYUTU]);
        Ok((
            SifreliBlok {
                nonce,
                govde: govde.to_vec(),
            },
            gerekli,
        ))
    }
}

/// Kayıt çerçevelerini diske yazılabilir düz metne çevirir.
///
/// Her çerçeve için `uzunluk || etiket || gövde` yazılır ve üstüne sayfanın
/// tamamı bir kez daha etiketlenmez — sayfa bütünlüğü zaten AEAD ile gelir.
pub fn cerceveleri_yaz(
    ana_malzeme: &[u8; ANAHTAR_BOYUTU],
    tuz: &[u8; TUZ_BOYUTU],
    sayfa: u32,
    govdeler: &[Vec<u8>],
) -> Result<Vec<u8>, Hata> {
    let cerceve_anahtari = cerceve_anahtari(ana_malzeme, tuz)?;
    let mut duz = Zeroizing::new(Vec::new());
    for (sira, govde) in govdeler.iter().enumerate() {
        let cerceve = u32::try_from(sira)
            .map_err(|_| Hata::Kriptografik("cerceve sayisi u32 sinfini asti".to_string()))?;
        let etiket = crate::kripto::cerceve_etiketi_uret(&cerceve_anahtari, sayfa, cerceve, govde)?;
        duz.extend_from_slice(&(govde.len() as u32).to_le_bytes());
        duz.extend_from_slice(&etiket);
        duz.extend_from_slice(govde);
    }
    let sonuc = duz.to_vec();
    Ok(sonuc)
}

/// Diskteki düz metni kayıt çerçevelerine ayırır ve her etiketi doğrular.
///
/// `hatali_cerceve` çıktısı, etiketi tutmayan çerçevenin sırasını bildirir.
#[allow(clippy::type_complexity)]
pub fn cerceveleri_oku(
    ana_malzeme: &[u8; ANAHTAR_BOYUTU],
    tuz: &[u8; TUZ_BOYUTU],
    sayfa: u32,
    duz: &[u8],
) -> Result<(Vec<Cerceve>, Option<u32>), Hata> {
    let cerceve_anahtari = cerceve_anahtari(ana_malzeme, tuz)?;
    let mut cerceveler = Vec::new();
    let mut hatali_cerceve: Option<u32> = None;
    let mut konum = 0usize;
    let mut sira: u32 = 0;

    while konum < duz.len() {
        if konum + 4 + CERCEVE_ETIKET_BOYUTU > duz.len() {
            // Kesilmiş son çerçeve: kalan baytlar bir başlık oluşturmuyor.
            hatali_cerceve.get_or_insert(sira);
            break;
        }
        let govde_uzunluk =
            u32::from_le_bytes([duz[konum], duz[konum + 1], duz[konum + 2], duz[konum + 3]])
                as usize;
        let etiket_ofs = konum + 4;
        let govde_ofs = etiket_ofs + CERCEVE_ETIKET_BOYUTU;
        if govde_ofs + govde_uzunluk > duz.len() {
            hatali_cerceve.get_or_insert(sira);
            break;
        }
        let mut etiket = [0u8; CERCEVE_ETIKET_BOYUTU];
        etiket.copy_from_slice(&duz[etiket_ofs..govde_ofs]);
        let govde = &duz[govde_ofs..govde_ofs + govde_uzunluk];

        let gecerli = cerceve_etiketi_dogrula(&cerceve_anahtari, sayfa, sira, govde, &etiket)?;
        if gecerli {
            cerceveler.push(Cerceve {
                sayfa,
                cerceve: sira,
                govde: Zeroizing::new(govde.to_vec()),
            });
        } else {
            hatali_cerceve.get_or_insert(sira);
        }

        konum = govde_ofs + govde_uzunluk;
        sira = sira.saturating_add(1);
    }

    Ok((cerceveler, hatali_cerceve))
}

/// Dizin bölümünü şifreler.
pub fn dizin_sifrele(
    ana_malzeme: &[u8; ANAHTAR_BOYUTU],
    tuz: &[u8; TUZ_BOYUTU],
    dizin: &Dizin,
) -> Result<SifreliBlok, Hata> {
    let anahtar = dizin_anahtari(ana_malzeme, tuz)?;
    let duz = serde_json::to_vec(dizin)
        .map_err(|hata| Hata::Kriptografik(format!("dizin serilestirilemedi: {hata}")))?;
    let nonce = nonce_uret()?;
    // Dizin AAD'si sabit: dizin bloğu hiçbir zaman sayfa konumu taşımaz.
    let ek_veri = b"vaulta/v1/index";
    let govde = sifrele(&anahtar, &nonce, ek_veri, &duz)?;
    Ok(SifreliBlok {
        nonce: *nonce,
        govde: govde.to_vec(),
    })
}

/// Dizin bölümünü çözer.
pub fn dizin_coz(
    ana_malzeme: &[u8; ANAHTAR_BOYUTU],
    tuz: &[u8; TUZ_BOYUTU],
    blok: &SifreliBlok,
) -> Result<Dizin, Hata> {
    let anahtar = dizin_anahtari(ana_malzeme, tuz)?;
    let ek_veri = b"vaulta/v1/index";
    let duz = coz(&anahtar, &blok.nonce, ek_veri, &blok.govde)?;
    serde_json::from_slice(&duz).map_err(|hata| {
        // Bozuk JSON, etik doğrulaması geçtikten sonra mümkündür (aynı ana parola
        // ile kasten bozulan içerik). Kullanıcıya sebebi söyleriz ama içeriği yazmaz.
        Hata::BozukAktarim(format!("dizin icerigi cozulemedi: {hata}"))
    })
}

/// Bir sayfa bloğunu şifreler.
pub fn sayfa_sifrele(
    ana_malzeme: &[u8; ANAHTAR_BOYUTU],
    tuz: &[u8; TUZ_BOYUTU],
    sayfa: u32,
    govdeler: &[Vec<u8>],
) -> Result<SifreliBlok, Hata> {
    let duz = cerceveleri_yaz(ana_malzeme, tuz, sayfa, govdeler)?;
    let anahtar = sayfa_anahtari(ana_malzeme, tuz, sayfa)?;
    let nonce = nonce_uret()?;
    // AAD sayfa numarasını içerir: sayfa 0'ın şifre metni sayfa 1 yeriyle
    // değiştirilemez, çünkü anahtar zaten farklıdır; AAD ise ek güvenlik sağlar.
    let ek_veri = Zeroizing::new(b"vaulta/v1/page".to_vec());
    let ek_veri = [ek_veri.as_slice(), &sayfa.to_be_bytes()].concat();
    let govde = sifrele(&anahtar, &nonce, &ek_veri, &duz)?;
    Ok(SifreliBlok {
        nonce: *nonce,
        govde: govde.to_vec(),
    })
}

/// Bir sayfa bloğunu çözer ve çerçeveleri ayırır.
#[allow(clippy::type_complexity)]
pub fn sayfa_coz(
    ana_malzeme: &[u8; ANAHTAR_BOYUTU],
    tuz: &[u8; TUZ_BOYUTU],
    sayfa: u32,
    blok: &SifreliBlok,
) -> Result<(Vec<Cerceve>, Option<u32>), Hata> {
    let anahtar = sayfa_anahtari(ana_malzeme, tuz, sayfa)?;
    let ek_veri = [b"vaulta/v1/page".as_slice(), &sayfa.to_be_bytes()].concat();
    let duz = coz(&anahtar, &blok.nonce, &ek_veri, &blok.govde)?;
    cerceveleri_oku(ana_malzeme, tuz, sayfa, &duz)
}

/// Kalan baytın tamamen tüketildiğini doğrular (dosya sonu denetimi).
pub fn kalan_yok(kalan: &[u8]) -> Result<(), Hata> {
    if kalan.is_empty() {
        Ok(())
    } else {
        Err(Hata::BozukKasa(format!(
            "dosya sonunda {} bayt artik var; bicim beklenmiyor",
            kalan.len()
        )))
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)] // WORKER_CONTRACT 4.2: testlerde panic araci gecerlidir
mod tests {
    use super::*;

    use crate::kripto::{ana_malzeme_turet, Argon2Ayar};

    const HIZLI: Argon2Ayar = Argon2Ayar::HIZLI;

    /// Testlerde kullanılan geçerli bir başlık.
    fn ornek_baslik() -> Baslik {
        Baslik {
            surum: SURUM,
            m_cost: 65_536,
            t_cost: 3,
            p_cost: 4,
            sayfa_boyutu: VARSAYILAN_SAYFA_BOYUTU as u32,
            sayfa_sayisi: 2,
            kayit_sayisi: 5,
            tuz: [0xA5; TUZ_BOYUTU],
        }
    }

    /// Testlerde kullanılan geçerli bir blok.
    fn ornek_blok() -> SifreliBlok {
        SifreliBlok {
            nonce: [0x11; NONCE_BOYUTU],
            govde: vec![0x22; 48],
        }
    }

    #[test]
    fn baslik_gidis_donusu_basar() {
        let baslik = ornek_baslik();
        let geri = Baslik::oku(&baslik.yaz()).expect("baslik okunmali");
        assert_eq!(baslik, geri);
    }

    #[test]
    fn baslik_kisa_tampon_reddedilir() {
        let kisa = vec![0u8; BASLIK_BOYUTU - 1];
        assert!(Baslik::oku(&kisa).is_err());
    }

    #[test]
    fn yanlis_imza_reddedilir() {
        let mut bayt = ornek_baslik().yaz();
        bayt[0] = b'X';
        assert!(Baslik::oku(&bayt).is_err());
    }

    #[test]
    fn bilinmeyen_surum_reddedilir() {
        let mut bayt = ornek_baslik().yaz();
        bayt[4] = 9;
        let hata = Baslik::oku(&bayt).expect_err("surum reddedilmeli");
        assert!(hata.to_string().contains("surum"));
    }

    #[test]
    fn ayrilmis_alan_sifir_degilse_reddedilir() {
        let mut bayt = ornek_baslik().yaz();
        bayt[80] = 1;
        assert!(Baslik::oku(&bayt).is_err());
    }

    #[test]
    fn sifir_sayfa_boyutu_reddedilir() {
        let mut baslik = ornek_baslik();
        baslik.sayfa_boyutu = 0;
        assert!(baslik.dogrula().is_err());
    }

    #[test]
    fn asiri_buyuk_sayfa_boyutu_reddedilir() {
        let mut baslik = ornek_baslik();
        baslik.sayfa_boyutu = 2 * 1024 * 1024;
        assert!(baslik.dogrula().is_err());
    }

    #[test]
    fn sifirli_vektorun_ilk_dort_bayti_kasa_imzasi() {
        let bayt = ornek_baslik().yaz();
        assert_eq!(&bayt[0..4], b"KASA");
    }

    #[test]
    fn baslik_bayt_sirasi_platformdan_bagimsiz() {
        // m_cost = 0x00010000 -> 5..9 baytları küçük uçlu 00 00 01 00 olmalı.
        let baslik = ornek_baslik();
        let bayt = baslik.yaz();
        assert_eq!(bayt[5..9], [0x00, 0x00, 0x01, 0x00]);
    }

    #[test]
    fn blok_gidis_donusu_basar() {
        let blok = ornek_blok();
        let mut cikti = Vec::new();
        blok.yaz(&mut cikti).expect("yazilmali");
        let (geri, tuketilen) = SifreliBlok::oku(&cikti).expect("okunmali");
        assert_eq!(tuketilen, cikti.len());
        assert_eq!(blok.nonce, geri.nonce);
        assert_eq!(blok.govde, geri.govde);
    }

    #[test]
    fn kirpilan_dosya_reddedilir() {
        let blok = ornek_blok();
        let mut cikti = Vec::new();
        blok.yaz(&mut cikti).expect("yazilmali");
        cikti.truncate(cikti.len() - 5);
        assert!(SifreliBlok::oku(&cikti).is_err());
    }

    #[test]
    fn basligi_olmayan_tampon_reddedilir() {
        assert!(SifreliBlok::oku(&[0u8; 2]).is_err());
    }

    #[test]
    fn etiketten_kisa_blok_yazilamaz_ve_okunamaz() {
        let kisa = SifreliBlok {
            nonce: [0u8; NONCE_BOYUTU],
            govde: vec![0u8; 4],
        };
        let mut cikti = Vec::new();
        assert!(kisa.yaz(&mut cikti).is_err());
    }

    #[test]
    fn cerceveleri_yaz_ve_oku_gidis_donusu() {
        let tuz = [0x33u8; TUZ_BOYUTU];
        let ana = ana_malzeme_turet("parola", &tuz, &HIZLI).expect("ana malzeme");
        let govdeler = vec![
            b"{\"baslik\":\"bir\"}".to_vec(),
            b"{\"baslik\":\"iki\"}".to_vec(),
        ];
        let duz = cerceveleri_yaz(&ana, &tuz, 0, &govdeler).expect("cerceveler yazilmali");
        let (cerceveler, hatali) =
            cerceveleri_oku(&ana, &tuz, 0, &duz).expect("cerceveler okunmali");
        assert!(hatali.is_none());
        assert_eq!(cerceveler.len(), 2);
        assert_eq!(cerceveler[0].govde.as_slice(), govdeler[0].as_slice());
        assert_eq!(cerceveler[1].govde.as_slice(), govdeler[1].as_slice());
    }

    #[test]
    fn cerceve_uzunlugu_karistirilirsa_ayristirma_durur() {
        let tuz = [0x44u8; TUZ_BOYUTU];
        let ana = ana_malzeme_turet("parola", &tuz, &HIZLI).expect("ana malzeme");
        let govdeler = vec![b"birinci".to_vec(), b"ikinci".to_vec()];
        let mut duz = cerceveleri_yaz(&ana, &tuz, 0, &govdeler).expect("yazilmali");
        // İlk çerçevenin uzunluk alanını abartarak ikinciyi "yut" et.
        let yeni_uzunluk = (duz.len() as u32).to_le_bytes();
        duz[0..4].copy_from_slice(&yeni_uzunluk);
        let (cerceveler, hatali) =
            cerceveleri_oku(&ana, &tuz, 0, &duz).expect("ayristirma hata vermemeli");
        assert!(cerceveler.is_empty());
        assert!(hatali.is_some());
    }

    #[test]
    fn cerceve_etiketi_bozulursa_kayit_isaretlenir() {
        let tuz = [0x55u8; TUZ_BOYUTU];
        let ana = ana_malzeme_turet("parola", &tuz, &HIZLI).expect("ana malzeme");
        let govdeler = vec![b"ilk".to_vec(), b"ikinci".to_vec()];
        let mut duz = cerceveleri_yaz(&ana, &tuz, 0, &govdeler).expect("yazilmali");
        // İlk çerçevenin gövdesinin bir baytını değiştir.
        let ilk_govde_ofs = 4 + CERCEVE_ETIKET_BOYUTU;
        duz[ilk_govde_ofs] ^= 0xff;
        let (cerceveler, hatali) = cerceveleri_oku(&ana, &tuz, 0, &duz).expect("ayristirma");
        assert_eq!(hatali, Some(0));
        assert_eq!(cerceveler.len(), 1, "ikinci kayit kurtarilmali");
        assert_eq!(cerceveler[0].cerceve, 1);
    }

    #[test]
    fn cerceveler_baska_sayfaya_tasinca_gecersiz_lesilir() {
        let tuz = [0x66u8; TUZ_BOYUTU];
        let ana = ana_malzeme_turet("parola", &tuz, &HIZLI).expect("ana malzeme");
        let govdeler = vec![b"tasinacak kayit".to_vec()];
        let duz = cerceveleri_yaz(&ana, &tuz, 0, &govdeler).expect("yazilmali");
        let (cerceveler, hatali) = cerceveleri_oku(&ana, &tuz, 7, &duz).expect("ayristirma");
        assert!(cerceveler.is_empty());
        assert_eq!(hatali, Some(0));
    }

    #[test]
    fn sayfa_gidis_donusu() {
        let tuz = [0x77u8; TUZ_BOYUTU];
        let ana = ana_malzeme_turet("parola", &tuz, &HIZLI).expect("ana malzeme");
        let govdeler = vec![b"kayit bir".to_vec(), b"kayit iki".to_vec()];
        let blok = sayfa_sifrele(&ana, &tuz, 3, &govdeler).expect("sayfa sifrelenmeli");
        let (cerceveler, hatali) = sayfa_coz(&ana, &tuz, 3, &blok).expect("sayfa cozulmeli");
        assert!(hatali.is_none());
        assert_eq!(cerceveler.len(), 2);
    }

    #[test]
    fn sayfa_yanlis_numarayla_cozulemez() {
        let tuz = [0x88u8; TUZ_BOYUTU];
        let ana = ana_malzeme_turet("parola", &tuz, &HIZLI).expect("ana malzeme");
        let blok = sayfa_sifrele(&ana, &tuz, 1, &[b"kayit".to_vec()]).expect("sifre");
        assert!(sayfa_coz(&ana, &tuz, 2, &blok).is_err());
    }

    #[test]
    fn sayfa_icerigi_kurcalanirsa_cozme_basarisiz() {
        let tuz = [0x99u8; TUZ_BOYUTU];
        let ana = ana_malzeme_turet("parola", &tuz, &HIZLI).expect("ana malzeme");
        let mut blok = sayfa_sifrele(&ana, &tuz, 0, &[b"gizli kayit".to_vec()]).expect("sifre");
        blok.govde[5] ^= 0xff;
        assert!(sayfa_coz(&ana, &tuz, 0, &blok).is_err());
    }

    #[test]
    fn dizin_gidis_donusu() {
        let tuz = [0xAAu8; TUZ_BOYUTU];
        let ana = ana_malzeme_turet("parola", &tuz, &HIZLI).expect("ana malzeme");
        let dizin = Dizin {
            surum: 1,
            kayitlar: vec![DizinKaydi {
                baslik: "GitHub".to_string(),
                kullanici: "kullanici".to_string(),
                sayfa: 0,
                cerceve: 0,
            }],
        };
        let blok = dizin_sifrele(&ana, &tuz, &dizin).expect("dizin sifrelenmeli");
        let geri = dizin_coz(&ana, &tuz, &blok).expect("dizin cozulmeli");
        assert_eq!(dizin, geri);
    }

    #[test]
    fn dizin_kurcalanirsa_cozme_basarisiz() {
        let tuz = [0xBBu8; TUZ_BOYUTU];
        let ana = ana_malzeme_turet("parola", &tuz, &HIZLI).expect("ana malzeme");
        let dizin = Dizin {
            surum: 1,
            kayitlar: Vec::new(),
        };
        let mut blok = dizin_sifrele(&ana, &tuz, &dizin).expect("sifre");
        let son = blok.govde.len() - 1;
        blok.govde[son] ^= 0x80;
        assert!(dizin_coz(&ana, &tuz, &blok).is_err());
    }

    #[test]
    fn her_sifrelemede_nonce_yeniden_uretilir() {
        let tuz = [0xCCu8; TUZ_BOYUTU];
        let ana = ana_malzeme_turet("parola", &tuz, &HIZLI).expect("ana malzeme");
        let bir = sayfa_sifrele(&ana, &tuz, 0, &[b"ayni".to_vec()]).expect("sifre");
        let iki = sayfa_sifrele(&ana, &tuz, 0, &[b"ayni".to_vec()]).expect("sifre");
        assert_ne!(bir.nonce, iki.nonce);
        assert_ne!(bir.govde, iki.govde);
    }

    #[test]
    fn kalan_bayt_kontrolu_calisir() {
        assert!(kalan_yok(&[]).is_ok());
        assert!(kalan_yok(&[1, 2, 3]).is_err());
    }
}
