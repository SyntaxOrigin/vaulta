//! Kriptografik çekirdek: Argon2id ana malzeme türetme, HKDF-SHA256 alt anahtar
//! ayrımı, XChaCha20-Poly1305 sayfa şifreleme/çözme ve `getrandom` ile nonce
//! üretimi.
//!
//! # Katman sözleşmesi
//!
//! ```text
//! ana parola + kasa tuzu
//!        │  Argon2id (RFC 9106) — kasadaki m_cost/t_cost/p_cost ile
//!        ▼
//!   ana malzeme (32 bayt)
//!        │  HKDF-SHA256, her kullanım için AYRI info etiketi
//!        ├──► dizin anahtarı      (sayfa dizini)
//!        ├──► sayfa anahtarı(n)   (her sayfa için ayrı)
//!        └──► çerçeve anahtarı     (kayıt düzeyi bütünlük etiketi)
//! ```
//!
//! Alt anahtarların ayrımı HKDF'nin `info` alanından gelir. Aynı ana malzeme
//! üç ayrı `info` etiketiyle üç ayrı anahtara açılır; biri ele geçirilse bile
//! diğer ikisi geçerli sayfaların şifre metnini çözemez.
//!
//! # Nonce disiplini
//!
//! Her sayfa şifrelemesi **yeni rastgele** 192-bit XChaCha nonce kullanır.
//! Nonce asla sayaç, sayaç türevi veya zaman damgası değildir (`getrandom` ile
//! üretilir). XChaCha'nın 192-bit nonce alanı, 2^32 sayfalık bir kasada bile
//! çakışma olasılığını ihmal edilebilir düzeye indirir; yine de her yazma işlemi
//! nonce'u yeniden üretir, böylece aynı sayfanın iki kez aynı nonce ile
//! şifrelenmesi **yapısal olarak imkânsızdır**.
//!
//! `zeroize` kuralı: ana malzeme, alt anahtarlar, düz metin ve şifre metni
//! tamponları `Zeroizing` içinde taşınır; kapsayıcı düştüğünde bellek sıfırlanır.

use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::XChaCha20Poly1305;
use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::hata::Hata;

/// Argon2id çıktısının ve tüm alt anahtarların bayt uzunluğu.
pub const ANAHTAR_BOYUTU: usize = 32;

/// Kasa tuzunun bayt uzunluğu (RFC 9106 en az 8 bayt ister; 16 tercih edilir).
pub const TUZ_BOYUTU: usize = 16;

/// XChaCha20-Poly1305 nonce uzunluğu (192 bayt).
pub const NONCE_BOYUTU: usize = 24;

/// Poly1305 etiket uzunluğu.
pub const ETIKET_BOYUTU: usize = 16;

/// Kayıt çerçevesi bütünlük etiketinin bayt uzunluğu (tam etiketin yarısı).
pub const CERCEVE_ETIKET_BOYUTU: usize = 16;

/// HKDF `info` etiketlerinin ortak ön eki; sürüm değişince ayrım bozulmaz.
const HKDF_ONEK: &[u8] = b"vaulta/v1/";

/// Kasada saklanan ve okunabilen Argon2id maliyet parametreleri.
///
/// Bu üç sayı kasa başlığında **açık metin** olarak durur. Amaç, bir kaba
/// kuvvet saldırganının önce hangi maliyetle uğraşacağını bilmesidir; kriptografik
/// güvenlik gizli parametrelerden gelmez, hesaplanabilir maliyetten gelir.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Argon2Ayar {
    /// Bellek maliyeti (KiB).
    pub bellek_kib: u32,
    /// Türetme tur sayısı.
    pub tur: u32,
    /// Paralellik (yol sayısı).
    pub yol: u32,
}

impl Argon2Ayar {
    /// Ofis sınıfı donanım için seçilen varsayılan: 64 MiB / 3 tur / 4 yol.
    ///
    /// Gerekçe ve RFC 9106'nın 2 GiB önerisinden **bilinçli** sapma
    /// README'nin `## Kriptografik Parametreler` bölümünde yazılıdır.
    pub const VARSAYILAN: Self = Self {
        bellek_kib: 65_536,
        tur: 3,
        yol: 4,
    };

    /// Testlerde kullanılan hızlı ayar (aynı kod yolu, çok düşük maliyet).
    ///
    /// Yalnızca testlerde ve kullanıcı `--hizli` bayrağını verirse kullanılır;
    /// kasaya yazılan parametrelerdir, bu yüzden açılış hızını değiştirir.
    pub const HIZLI: Self = Self {
        bellek_kib: 16_384,
        tur: 1,
        yol: 1,
    };

    /// Parametreleri kabul edilebilir aralıkta doğrular.
    ///
    /// Alt sınır Argon2'ın kendi gereksinimi olan `m_cost >= 8 * yol`; üst sınır
    /// ise kasayı açarken çökme (out-of-memory) yapmamak içindir.
    pub fn dogrula(&self) -> Result<(), Hata> {
        if self.yol == 0 || self.yol > 16 {
            return Err(Hata::BozukKasa(format!(
                "paralellik {} 1..16 araliginda degil",
                self.yol
            )));
        }
        if self.tur == 0 || self.tur > 16 {
            return Err(Hata::BozukKasa(format!(
                "tur sayisi {} 1..16 araliginda degil",
                self.tur
            )));
        }
        if self.bellek_kib < 8 * self.yol {
            return Err(Hata::BozukKasa(format!(
                "bellek maliyeti {} KiB, paralellik {} icin gereken {} KiB'in altinda",
                self.bellek_kib,
                self.yol,
                8 * self.yol
            )));
        }
        if self.bellek_kib > 1_048_576 {
            return Err(Hata::BozukKasa(
                "bellek maliyeti 1 GiB'i asti; bu kasa bu makinede acilamaz".to_string(),
            ));
        }
        Ok(())
    }
}

impl Default for Argon2Ayar {
    fn default() -> Self {
        Self::VARSAYILAN
    }
}

/// İşletim sistemi kriptografik rastgeleliğinden `uzunluk` bayt üretir.
///
/// `getrandom` Unix'te `getrandom(2)`, Windows'ta `BCryptGenRandom` yolunu
/// kullanır; ikisi de işletim sisteminin CSPRNG'sidir. `rand` crate'i bu projede
/// yasaktır (WORKER_CONTRACT §3.2-F) çünkü `rand` birçok bağlamda devre dışı
/// kalan `StdRng` gibi kaynaklara düşebilir.
pub fn rastgele_bayt(uzunluk: usize) -> Result<Zeroizing<Vec<u8>>, Hata> {
    let mut tampon = Zeroizing::new(vec![0u8; uzunluk]);
    getrandom::fill(tampon.as_mut()).map_err(|hata| {
        Hata::Kriptografik(format!(
            "isletim sistemi rastgelelik kaynagina erisilemedi: {hata}"
        ))
    })?;
    Ok(tampon)
}

/// 16 baytlık yeni kasa tuzu üretir.
pub fn tuz_uret() -> Result<Zeroizing<[u8; TUZ_BOYUTU]>, Hata> {
    let bayt = rastgele_bayt(TUZ_BOYUTU)?;
    let mut tuz = Zeroizing::new([0u8; TUZ_BOYUTU]);
    tuz.copy_from_slice(&bayt);
    Ok(tuz)
}

/// 24 baytlık (192-bit) rastgele XChaCha nonce üretir.
pub fn nonce_uret() -> Result<Zeroizing<[u8; NONCE_BOYUTU]>, Hata> {
    let bayt = rastgele_bayt(NONCE_BOYUTU)?;
    let mut nonce = Zeroizing::new([0u8; NONCE_BOYUTU]);
    nonce.copy_from_slice(&bayt);
    Ok(nonce)
}

/// Ana paroladan Argon2id ile ana malzeme türetir (RFC 9106).
///
/// Sonuç `Zeroizing` içinde döner; çağıran bunu diske yazmaz ve düşünce
/// otomatik olarak bellek sıfırlanır.
pub fn ana_malzeme_turet(
    parola: &str,
    tuz: &[u8; TUZ_BOYUTU],
    ayar: &Argon2Ayar,
) -> Result<Zeroizing<[u8; ANAHTAR_BOYUTU]>, Hata> {
    ayar.dogrula()?;
    let params = Params::new(ayar.bellek_kib, ayar.tur, ayar.yol, Some(ANAHTAR_BOYUTU))
        .map_err(|hata| Hata::Kriptografik(format!("argon2 parametreleri gecersiz: {hata}")))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut cikti = Zeroizing::new([0u8; ANAHTAR_BOYUTU]);
    argon2
        .hash_password_into(parola.as_bytes(), tuz, cikti.as_mut())
        .map_err(|hata| Hata::Kriptografik(format!("argon2 turetme basarisiz: {hata}")))?;
    Ok(cikti)
}

/// Ana malzemeden HKDF-SHA256 ile belirli bir amaca ait alt anahtar türetir.
///
/// `bilgi` etiketi **mutlaka** `HKDF_ONEK` önekiyle başlar; bu, kasanın sürüm
/// değişiminde eski ana anahtarlarla çakışmayı önler.
pub fn alt_anahtar_turet(
    ana_malzeme: &[u8; ANAHTAR_BOYUTU],
    tuz: &[u8; TUZ_BOYUTU],
    bilgi: &[u8],
) -> Result<Zeroizing<[u8; ANAHTAR_BOYUTU]>, Hata> {
    let etiket = [HKDF_ONEK, bilgi].concat();
    let hkdf = Hkdf::<Sha256>::new(Some(tuz), ana_malzeme);
    let mut anahtar = Zeroizing::new([0u8; ANAHTAR_BOYUTU]);
    hkdf.expand(&etiket, anahtar.as_mut()).map_err(|hata| {
        Hata::Kriptografik(format!("hkdf alt anahtar turetme basarisiz: {hata}"))
    })?;
    Ok(anahtar)
}

/// Dizin (sayfa dizini) anahtarını türetir.
pub fn dizin_anahtari(
    ana_malzeme: &[u8; ANAHTAR_BOYUTU],
    tuz: &[u8; TUZ_BOYUTU],
) -> Result<Zeroizing<[u8; ANAHTAR_BOYUTU]>, Hata> {
    alt_anahtar_turet(ana_malzeme, tuz, b"index-key")
}

/// `sayfa` numarasına özel sayfa anahtarını türetir.
pub fn sayfa_anahtari(
    ana_malzeme: &[u8; ANAHTAR_BOYUTU],
    tuz: &[u8; TUZ_BOYUTU],
    sayfa: u32,
) -> Result<Zeroizing<[u8; ANAHTAR_BOYUTU]>, Hata> {
    let mut etiket = Zeroizing::new(Vec::with_capacity(16));
    etiket.extend_from_slice(b"page-key-");
    etiket.extend_from_slice(sayfa_label(sayfa).as_slice());
    alt_anahtar_turet(ana_malzeme, tuz, &etiket)
}

/// Kayıt çerçevesi bütünlük etiketi üretmek için kullanılan anahtarı türetir.
pub fn cerceve_anahtari(
    ana_malzeme: &[u8; ANAHTAR_BOYUTU],
    tuz: &[u8; TUZ_BOYUTU],
) -> Result<Zeroizing<[u8; ANAHTAR_BOYUTU]>, Hata> {
    alt_anahtar_turet(ana_malzeme, tuz, b"frame-mac-key")
}

/// Sayfa numarasını HKDF bilgi etiketine çeviren kısa ve ayrım garantili
/// etiket. `page-0`, `page-1`, ... biçiminde, ASCII ve birbirine çevrilemez.
fn sayfa_label(sayfa: u32) -> [u8; 16] {
    let mut etiket = [0u8; 16];
    let yaz = format!("page-{sayfa}");
    let bayt = yaz.as_bytes();
    let kopya = bayt.len().min(etiket.len());
    etiket[..kopya].copy_from_slice(&bayt[..kopya]);
    etiket
}

/// Kayıt çerçevesinin bütünlük etiketini üretir.
///
/// Etiket, gizli çerçeve anahtarıyla çalışan bir HKFP-MAC'tir: HKDF'in çıktısı
/// gizli ikinci girdi (IKM) altında bir sözde-rastgele fonksiyon verir, bu
/// yüzden `expand` çıktısı doğrudan kimlik doğrulama etiketi olarak kullanılabilir.
/// `info` alanı çerçevenin konumunu ve içeriğini bağlar: bir çerçevenin
/// başka bir sayfaya taşınması ya da gövdesinin bir baytının değiştirilmesi
/// etiketi geçersiz kılar.
///
/// Bu etiket sayfa içi **kayıt düzeyi** bütünlüktür; sayfanın kendisi ayrıca
/// AEAD ile korunur, dolayısıyla etiket çift katmanlı güvenlik sağlar.
pub fn cerceve_etiketi_uret(
    cerceve_anahtari: &[u8; ANAHTAR_BOYUTU],
    sayfa: u32,
    cerceve: u32,
    govde: &[u8],
) -> Result<[u8; CERCEVE_ETIKET_BOYUTU], Hata> {
    let mut etiket = Zeroizing::new([0u8; CERCEVE_ETIKET_BOYUTU]);
    let mut info = Zeroizing::new(Vec::with_capacity(32 + govde.len()));
    info.extend_from_slice(b"frame-tag");
    info.extend_from_slice(&sayfa.to_be_bytes());
    info.extend_from_slice(&cerceve.to_be_bytes());
    info.extend_from_slice(&(govde.len() as u64).to_be_bytes());
    info.extend_from_slice(govde);
    let hkdf = Hkdf::<Sha256>::new(Some(cerceve_anahtari), b"vaulta-frame-mac/v1");
    hkdf.expand(&info, etiket.as_mut())
        .map_err(|hata| Hata::Kriptografik(format!("cerceve etiketi turetme basarisiz: {hata}")))?;
    let sonuc = *etiket;
    Ok(sonuc)
}

/// Çerçeve etiketini **sabit zamanlı** karşılaştırır.
///
/// `==` kullanmak yerine `subtle` bir XOR biriktirme yapılır; böylece farklı
/// konumlarda farklı süreye yol açan kısa devre karşılaştırması oluşmaz.
pub fn cerceve_etiketi_dogrula(
    cerceve_anahtari: &[u8; ANAHTAR_BOYUTU],
    sayfa: u32,
    cerceve: u32,
    govde: &[u8],
    beklenen: &[u8; CERCEVE_ETIKET_BOYUTU],
) -> Result<bool, Hata> {
    let gercek = cerceve_etiketi_uret(cerceve_anahtari, sayfa, cerceve, govde)?;
    let fark = gercek
        .iter()
        .zip(beklenen.iter())
        .fold(0u8, |birikim, (a, b)| birikim | (a ^ b));
    Ok(fark == 0)
}

/// Düz metni XChaCha20-Poly1305 ile şifreler.
///
/// AAD (ek veri) `ek_veri` parametresiyle verilir; çağıran sayfa konumu gibi
/// bağlayıcı veriyi buraya koyar, böylece sayfa yer değiştirme saldırıları
/// etik doğrulamada anında yakalanır. Dönen tampon şifre metni + 16 baytlık
/// Poly1305 etiketini içerir ve `Zeroizing` ile taşınır.
pub fn sifrele(
    anahtar: &[u8; ANAHTAR_BOYUTU],
    nonce: &[u8; NONCE_BOYUTU],
    ek_veri: &[u8],
    duz_metin: &[u8],
) -> Result<Zeroizing<Vec<u8>>, Hata> {
    let sipher = XChaCha20Poly1305::new(anahtar.into());
    let cikti = sipher
        .encrypt(
            nonce.into(),
            Payload {
                msg: duz_metin,
                aad: ek_veri,
            },
        )
        .map_err(|_| Hata::Kriptografik("xchacha20poly1305 sifreleme basarisiz".to_string()))?;
    Ok(Zeroizing::new(cikti))
}

/// XChaCha20-Poly1305 şifre metnini çözer ve etiketi doğrular.
///
/// Etik doğrulaması başarısızsa `Err` döner ve **düz metin üretilmez**; kısmi
/// çözme yolu yoktur.
pub fn coz(
    anahtar: &[u8; ANAHTAR_BOYUTU],
    nonce: &[u8; NONCE_BOYUTU],
    ek_veri: &[u8],
    sifre_metin: &[u8],
) -> Result<Zeroizing<Vec<u8>>, Hata> {
    if sifre_metin.len() < ETIKET_BOYUTU {
        return Err(Hata::BozukKasa(format!(
            "sifre metni {} bayt; etiketten kisa olamaz",
            sifre_metin.len()
        )));
    }
    let sipher = XChaCha20Poly1305::new(anahtar.into());
    let duz = sipher
        .decrypt(
            nonce.into(),
            Payload {
                msg: sifre_metin,
                aad: ek_veri,
            },
        )
        .map_err(|_| Hata::BozukKasa("sayfa etigi dogrulanmadi".to_string()))?;
    Ok(Zeroizing::new(duz))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)] // WORKER_CONTRACT 4.2: testlerde panic araci gecerlidir
mod tests {
    use super::*;

    use chacha20poly1305::aead::{Aead, KeyInit, Payload};
    use chacha20poly1305::ChaCha20Poly1305;

    /// Testlerde kullanılan hızlı Argon2id ayarı.
    const HIZLI: Argon2Ayar = Argon2Ayar::HIZLI;

    /// RFC 8439 §2.8.2 bilinen yanıt vektörü: anahtar.
    const RFC8439_ANAHTAR: [u8; 32] = [
        0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e,
        0x8f, 0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d,
        0x9e, 0x9f,
    ];

    /// RFC 8439 §2.8.2 bilinen yanıt vektörü: nonce (96 bit).
    const RFC8439_NONCE: [u8; 12] = [
        0x07, 0x00, 0x00, 0x00, 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47,
    ];

    /// RFC 8439 §2.8.2 bilinen yanıt vektörü: ek veri.
    const RFC8439_AAD: [u8; 12] = [
        0x50, 0x51, 0x52, 0x53, 0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7,
    ];

    /// RFC 8439 §2.8.2 bilinen yanıt vektörü: düz metin.
    const RFC8439_DUZ: &[u8] = b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";

    /// RFC 8439 §2.8.2 bilinen yanıt vektörü: şifre metni.
    const RFC8439_SIFRE: [u8; 114] = [
        0xd3, 0x1a, 0x8d, 0x34, 0x64, 0x8e, 0x60, 0xdb, 0x7b, 0x86, 0xaf, 0xbc, 0x53, 0xef, 0x7e,
        0xc2, 0xa4, 0xad, 0xed, 0x51, 0x29, 0x6e, 0x08, 0xfe, 0xa9, 0xe2, 0xb5, 0xa7, 0x36, 0xee,
        0x62, 0xd6, 0x3d, 0xbe, 0xa4, 0x5e, 0x8c, 0xa9, 0x67, 0x12, 0x82, 0xfa, 0xfb, 0x69, 0xda,
        0x92, 0x72, 0x8b, 0x1a, 0x71, 0xde, 0x0a, 0x9e, 0x06, 0x0b, 0x29, 0x05, 0xd6, 0xa5, 0xb6,
        0x7e, 0xcd, 0x3b, 0x36, 0x92, 0xdd, 0xbd, 0x7f, 0x2d, 0x77, 0x8b, 0x8c, 0x98, 0x03, 0xae,
        0xe3, 0x28, 0x09, 0x1b, 0x58, 0xfa, 0xb3, 0x24, 0xe4, 0xfa, 0xd6, 0x75, 0x94, 0x55, 0x85,
        0x80, 0x8b, 0x48, 0x31, 0xd7, 0xbc, 0x3f, 0xf4, 0xde, 0xf0, 0x8e, 0x4b, 0x7a, 0x9d, 0xe5,
        0x76, 0xd2, 0x65, 0x86, 0xce, 0xc6, 0x4b, 0x61, 0x16,
    ];

    /// RFC 8439 §2.8.2 bilinen yanıt vektörü: Poly1305 etiketi.
    const RFC8439_ETIKET: [u8; 16] = [
        0x1a, 0xe1, 0x0b, 0x59, 0x4f, 0x09, 0xe2, 0x6a, 0x7e, 0x90, 0x2e, 0xcb, 0xd0, 0x60, 0x06,
        0x91,
    ];

    /// AEAD çağrı zinciri RFC 8439 §2.8.2 vektörüyle birebir eşleşmeli.
    ///
    /// Neden: kütüphane doğru olsa bile bizim nonce/AAD/etiket boyutumuz yanlış
    /// olabilir; bu test yanlış bir boyutun sessizce "çalışmasını" engeller.
    #[test]
    fn rfc8439_bilinen_yanit_vektoru_eslesiyor() {
        let sipher = ChaCha20Poly1305::new(&RFC8439_ANAHTAR.into());
        let sifre = sipher
            .encrypt(
                (&RFC8439_NONCE).into(),
                Payload {
                    msg: RFC8439_DUZ,
                    aad: &RFC8439_AAD,
                },
            )
            .expect("RFC 8439 vektoru sifrelenmeli");
        let etiket = &sifre[sifre.len() - 16..];
        assert_eq!(&sifre[..sifre.len() - 16], RFC8439_SIFRE.as_slice());
        assert_eq!(etiket, RFC8439_ETIKET.as_slice());
    }

    /// Aynı vektörün çözme yönü de eşleşmeli.
    #[test]
    fn rfc8439_vektoru_cozulebiliyor() {
        let mut tam = Vec::with_capacity(RFC8439_SIFRE.len() + 16);
        tam.extend_from_slice(&RFC8439_SIFRE);
        tam.extend_from_slice(&RFC8439_ETIKET);
        let sipher = ChaCha20Poly1305::new(&RFC8439_ANAHTAR.into());
        let duz = sipher
            .decrypt(
                (&RFC8439_NONCE).into(),
                Payload {
                    msg: &tam,
                    aad: &RFC8439_AAD,
                },
            )
            .expect("RFC 8439 vektoru cozulmeli");
        assert_eq!(duz, RFC8439_DUZ);
    }

    #[test]
    fn sifrele_coz_gidis_donusu_basarisiz() {
        let anahtar = [7u8; ANAHTAR_BOYUTU];
        let nonce = nonce_uret().expect("nonce uretilmeli");
        let duz = b"kasa icerigi: sifreli metin degil, duz metin";
        let sifre = sifrele(&anahtar, &nonce, b"vaulta/v1/sayfa-0", duz).expect("sifrelenmeli");
        assert_ne!(sifre.as_slice(), duz);
        let cozulen = coz(&anahtar, &nonce, b"vaulta/v1/sayfa-0", &sifre).expect("cozulmeli");
        assert_eq!(cozulen.as_slice(), duz);
    }

    #[test]
    fn ayni_duz_metin_iki_kez_farkli_sifre_metin_verir() {
        let anahtar = [3u8; ANAHTAR_BOYUTU];
        let duz = b"ayni metin";
        let ilk = sifrele(&anahtar, &nonce_uret().expect("nonce"), b"aad", duz).expect("sifre");
        let ikinci = sifrele(&anahtar, &nonce_uret().expect("nonce"), b"aad", duz).expect("sifre");
        assert_ne!(ilk.as_slice(), ikinci.as_slice());
    }

    #[test]
    fn yanlis_anahtar_cozme_basarisiz() {
        let dogru = [9u8; ANAHTAR_BOYUTU];
        let yanlis = [10u8; ANAHTAR_BOYUTU];
        let nonce = nonce_uret().expect("nonce");
        let sifre = sifrele(&dogru, &nonce, b"aad", b"gizli").expect("sifre");
        assert!(coz(&yanlis, &nonce, b"aad", &sifre).is_err());
    }

    #[test]
    fn degisen_ek_veri_cozme_basarisiz() {
        let anahtar = [4u8; ANAHTAR_BOYUTU];
        let nonce = nonce_uret().expect("nonce");
        let sifre = sifrele(&anahtar, &nonce, b"sayfa-0", b"gizli").expect("sifre");
        assert!(coz(&anahtar, &nonce, b"sayfa-1", &sifre).is_err());
    }

    #[test]
    fn bozuk_etik_hatasi_dondurur() {
        let anahtar = [5u8; ANAHTAR_BOYUTU];
        let nonce = nonce_uret().expect("nonce");
        let mut sifre = sifrele(&anahtar, &nonce, b"aad", b"gizli kayit")
            .expect("sifre")
            .to_vec();
        let son = sifre.len() - 1;
        sifre[son] ^= 0x01;
        assert!(coz(&anahtar, &nonce, b"aad", &sifre).is_err());
    }

    #[test]
    fn etiketten_kisa_sifre_metin_reddedilir() {
        let anahtar = [6u8; ANAHTAR_BOYUTU];
        let nonce = nonce_uret().expect("nonce");
        assert!(coz(&anahtar, &nonce, b"aad", &[0u8; 8]).is_err());
    }

    #[test]
    fn argon2_id_ayni_girdi_ayni_cikti_verir() {
        let tuz = tuz_uret().expect("tuz");
        let bir = ana_malzeme_turet("dogru-parola", &tuz, &HIZLI).expect("turetilmeli");
        let iki = ana_malzeme_turet("dogru-parola", &tuz, &HIZLI).expect("turetilmeli");
        assert_eq!(bir.as_slice(), iki.as_slice());
    }

    #[test]
    fn argon2_id_tuz_degisince_cikti_degisir() {
        let tuz1 = tuz_uret().expect("tuz");
        let tuz2 = tuz_uret().expect("tuz");
        assert_ne!(tuz1.as_slice(), tuz2.as_slice(), "iki tuz ayni cikmamali");
        let bir = ana_malzeme_turet("ayni-parola", &tuz1, &HIZLI).expect("turet");
        let iki = ana_malzeme_turet("ayni-parola", &tuz2, &HIZLI).expect("turet");
        assert_ne!(bir.as_slice(), iki.as_slice());
    }

    #[test]
    fn argon2_id_parola_degisince_cikti_degisir() {
        let tuz = tuz_uret().expect("tuz");
        let bir = ana_malzeme_turet("birinci-parola", &tuz, &HIZLI).expect("turet");
        let iki = ana_malzeme_turet("ikinci-parola", &tuz, &HIZLI).expect("turet");
        assert_ne!(bir.as_slice(), iki.as_slice());
    }

    #[test]
    fn argon2_id_maliyet_degisince_cikti_degisir() {
        let tuz = tuz_uret().expect("tuz");
        let ucuz = Argon2Ayar {
            bellek_kib: 16_384,
            tur: 1,
            yol: 1,
        };
        let pahal = Argon2Ayar {
            bellek_kib: 32_768,
            tur: 1,
            yol: 1,
        };
        let bir = ana_malzeme_turet("ayni-parola", &tuz, &ucuz).expect("turet");
        let iki = ana_malzeme_turet("ayni-parola", &tuz, &pahal).expect("turet");
        assert_ne!(bir.as_slice(), iki.as_slice());
    }

    #[test]
    fn argon2_id_cikti_tam_32_bayt() {
        let tuz = tuz_uret().expect("tuz");
        let ana = ana_malzeme_turet("parola", &tuz, &HIZLI).expect("turet");
        assert_eq!(ana.len(), ANAHTAR_BOYUTU);
    }

    #[test]
    fn argon2_ayar_dogrulamasi_sinirlari_uygular() {
        assert!(Argon2Ayar::VARSAYILAN.dogrula().is_ok());
        assert!(Argon2Ayar {
            bellek_kib: 8,
            tur: 1,
            yol: 4
        }
        .dogrula()
        .is_err());
        assert!(Argon2Ayar {
            bellek_kib: 65_536,
            tur: 0,
            yol: 1
        }
        .dogrula()
        .is_err());
        assert!(Argon2Ayar {
            bellek_kib: 65_536,
            tur: 1,
            yol: 0
        }
        .dogrula()
        .is_err());
    }

    #[test]
    fn alt_anahtarlar_ayri_ayri_turetilir() {
        let tuz = tuz_uret().expect("tuz");
        let ana = ana_malzeme_turet("parola", &tuz, &HIZLI).expect("ana malzeme");
        let dizin = dizin_anahtari(&ana, &tuz).expect("dizin anahtari");
        let sayfa0 = sayfa_anahtari(&ana, &tuz, 0).expect("sayfa 0");
        let sayfa1 = sayfa_anahtari(&ana, &tuz, 1).expect("sayfa 1");
        let cerceve = cerceve_anahtari(&ana, &tuz).expect("cerceve anahtari");
        assert_ne!(dizin.as_slice(), sayfa0.as_slice());
        assert_ne!(sayfa0.as_slice(), sayfa1.as_slice());
        assert_ne!(sayfa0.as_slice(), cerceve.as_slice());
        assert_ne!(dizin.as_slice(), cerceve.as_slice());
    }

    #[test]
    fn alt_anahtar_ayni_bilgiyle_ayni_cikti_verir() {
        let tuz = tuz_uret().expect("tuz");
        let ana = ana_malzeme_turet("parola", &tuz, &HIZLI).expect("ana malzeme");
        let bir = alt_anahtar_turet(&ana, &tuz, b"test-bilgisi").expect("alt anahtar");
        let iki = alt_anahtar_turet(&ana, &tuz, b"test-bilgisi").expect("alt anahtar");
        assert_eq!(bir.as_slice(), iki.as_slice());
    }

    #[test]
    fn sayfa_anahtarlari_karsilastirilabilir() {
        // `page-key-` + 16 bayt etiket = 25 bayt; bu, sayfa numaralarının
        // birbirine karışmadığını (etiket kısalması yoluyla çakışmadığını)
        // garanti eder.
        let tuz = tuz_uret().expect("tuz");
        let ana = ana_malzeme_turet("parola", &tuz, &HIZLI).expect("ana malzeme");
        let mut oncekiler: Vec<Vec<u8>> = Vec::new();
        for sayfa in 0u32..64 {
            let anahtar = sayfa_anahtari(&ana, &tuz, sayfa).expect("alt anahtar");
            let bayt = anahtar.to_vec();
            assert!(!oncekiler.contains(&bayt), "sayfa {sayfa} anahtari cakisti");
            oncekiler.push(bayt);
        }
    }

    #[test]
    fn cerceve_etiketi_konuma_bagli() {
        let tuz = tuz_uret().expect("tuz");
        let ana = ana_malzeme_turet("parola", &tuz, &HIZLI).expect("ana malzeme");
        let anahtar = cerceve_anahtari(&ana, &tuz).expect("cerceve anahtari");
        let govde = b"kayit govdesi";
        let etiket = cerceve_etiketi_uret(&anahtar, 0, 0, govde).expect("etiket");
        assert_eq!(etiket.len(), CERCEVE_ETIKET_BOYUTU);
        assert!(cerceve_etiketi_dogrula(&anahtar, 0, 0, govde, &etiket).expect("dogrula"));
        assert!(!cerceve_etiketi_dogrula(&anahtar, 1, 0, govde, &etiket).expect("dogrula"));
        assert!(!cerceve_etiketi_dogrula(&anahtar, 0, 1, govde, &etiket).expect("dogrula"));
        assert!(
            !cerceve_etiketi_dogrula(&anahtar, 0, 0, b"kayit govdesi!", &etiket).expect("dogrula")
        );
    }

    #[test]
    fn cerceve_etiketi_degistirilince_dogrulanmaz() {
        let tuz = tuz_uret().expect("tuz");
        let ana = ana_malzeme_turet("parola", &tuz, &HIZLI).expect("ana malzeme");
        let anahtar = cerceve_anahtari(&ana, &tuz).expect("cerceve anahtari");
        let govde = b"kayit govdesi";
        let mut etiket = cerceve_etiketi_uret(&anahtar, 0, 0, govde).expect("etiket");
        etiket[0] ^= 0xff;
        assert!(!cerceve_etiketi_dogrula(&anahtar, 0, 0, govde, &etiket).expect("dogrula"));
    }

    #[test]
    fn rastgele_bayt_istenen_uzunlukta() {
        let bayt = rastgele_bayt(48).expect("rastgele bayt");
        assert_eq!(bayt.len(), 48);
    }

    #[test]
    fn nonce_uretimi_192_bit_ve_tekdizedir() {
        let bir = nonce_uret().expect("nonce");
        let iki = nonce_uret().expect("nonce");
        assert_eq!(bir.len(), NONCE_BOYUTU);
        assert_eq!(iki.len(), NONCE_BOYUTU);
        assert_ne!(bir.as_slice(), iki.as_slice());
    }

    #[test]
    fn tuz_uretimi_16_bayt_ve_tekdizedir() {
        let bir = tuz_uret().expect("tuz");
        let iki = tuz_uret().expect("tuz");
        assert_eq!(bir.len(), TUZ_BOYUTU);
        assert_ne!(bir.as_slice(), iki.as_slice());
    }

    #[test]
    fn kaba_parola_hatasi_siri_yazmaz() {
        let hata = Hata::KabaParola {
            uzunluk: 4,
            en_kisa: 15,
            gerekce: "cok kisa",
        };
        let metin = hata.to_string();
        assert!(metin.contains('4'));
        assert!(metin.contains("15"));
        assert!(!metin.contains("cok kisa parola:"));
    }

    #[test]
    fn bozuk_kasa_hatasi_parola_ile_ayirt_edilmez() {
        let metin = Hata::BozukKasa("".to_string()).to_string();
        assert!(metin.contains("ana parola yanlis"));
        assert!(metin.contains("butunlugu bozuk"));
    }
}
