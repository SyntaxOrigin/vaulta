//! Hata tipi ve nedenleri.
//!
//! Bu modül kasaya ilişkin tüm hataları tek bir [`Hata`] enum'unda toplar.
//! Modülün sorumluluğu hatanın *ne olduğunu* taşımaktır; hangi durumda
//! üretileceği `kripto`, `kasa`, `kayit`, `parola` ve `depo` modüllerinin işidir.
//!
//! # Sır sızdırmama kuralı
//!
//! Hiçbir `Display` metni parola, anahtar, şifre metni veya kayıt içeriği
//! içermez. `Hata::BozukKasa` bilerek "parola yanlış" ile "etik doğrulanamadı"
//! ayrımını **yapmaz**: ikisi kriptografik olarak ayırt edilemez ve ayrım
//! yapılması kaba kuvvet saldırganına hız ipucu verir. `Kurcalama` yalnızca
//! **doğrulanmış** etiket üzerinden, yani parolanın doğru olduğu bilinen bir
//! noktadan sonra üretilir; o sırada kaydın hangi sayfada olduğu güvenle
//! raporlanabilir.

use std::error::Error;
use std::fmt;
use std::io;

/// `vaulta` çekirdeğinin ürettiği tüm hataları kapsayan tip.
///
/// `Display` uygulaması elle yazılmıştır; `thiserror` gibi bir bağımlılık bu
/// projede yasaktır (WORKER_CONTRACT §3.2).
#[derive(Debug)]
#[non_exhaustive]
pub enum Hata {
    /// Dosya sistemi işlemi başarısız oldu.
    Io(io::Error),
    /// Kasa dosyasının başlığı, dizini veya bir sayfası okunamadı.
    ///
    /// Bu varyant **parola yanlışlığını da kapsar** ve mesajı bunu açıkça
    /// ayırt etmez. Neden metni yalnızca biçimsel ayrıntı içerir (ör. "başlık
    /// çok kısa"), asla girdi değerini yansıtmaz.
    BozukKasa(String),
    /// Bir sayfanın Poly1305 etiketi doğrulanamadı.
    ///
    /// Üretildiği an parolanın doğru olduğu kanıtlanmıştır çünkü sayfa
    /// çözülmeden etik doğrulanamaz; bu yüzden kaydın konumu güvenle
    /// raporlanabilir.
    BozukSayfa {
        /// Etiketi doğrulanamayan sayfanın sırası (0 tabanlı).
        sayfa: u32,
        /// Sayfa içinde etiketi tutmayan çerçevenin sırası.
        cerceve: u32,
    },
    /// Ana parola NIST SP 800-63B denetiminden geçemedi.
    ///
    /// Parolanın kendisi **asla** hata nesnesine girmez; yalnızca red gerekçesi
    /// ve gereken en az uzunluk raporlanır.
    KabaParola {
        /// Parolanın karakter sayısı.
        uzunluk: usize,
        /// Bu denetimde gereken en az uzunluk.
        en_kisa: usize,
        /// Red gerekçesi (`NIST SP 800-63B` paragraf numarasıyla).
        gerekce: &'static str,
    },
    /// Kayıt alanı sınırı aştı veya boştu.
    GecersizAlan {
        /// Alanın adı (`baslik`, `kullanici`, `parola`, `adres`, `not`).
        alan: &'static str,
        /// Sınırı aşma nedeni.
        gerekce: String,
    },
    /// Aynı başlıklı kayıt zaten var.
    YinelenenBaslik(String),
    /// Verilen başlıkla eşleşen kayıt bulunamadı.
    ///
    /// `baslik` **kullanıcının aradığı** metindir, kasa içeriği değildir;
    /// hata mesajında güvenle gösterilebilir.
    KayitYok {
        /// Aranan başlık.
        baslik: String,
    },
    /// Kasa zaten var; `init` üzerine yazmayı reddeder.
    VarOluyor(String),
    /// Kullanıcı girdisi geçersiz (komut satırı argümanı, bozuk sayı vb.).
    BozukArguman(String),
    /// Kriptografik işlem (türetme, şifreleme, çözme) başarısız oldu.
    Kriptografik(String),
    /// Dışa/içe aktarma belgesi okunamadı ya da doğrulanamadı.
    BozukAktarim(String),
    /// İşlem kullanıcı tarafından iptal edildi.
    Iptal,
}

impl fmt::Display for Hata {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Hata::Io(hata) => write!(f, "dosya sistemi hatasi: {hata}"),
            Hata::BozukKasa(detay) => {
                if detay.is_empty() {
                    write!(f, "ana parola yanlis veya kasa butunlugu bozuk")
                } else {
                    write!(f, "ana parola yanlis veya kasa butunlugu bozuk ({detay})")
                }
            }
            Hata::BozukSayfa { sayfa, cerceve } => write!(
                f,
                "sayfa #{sayfa} cerceve #{cerceve} etigi dogrulanmadi; kayit kurtarilamaz"
            ),
            Hata::KabaParola {
                uzunluk,
                en_kisa,
                gerekce,
            } => write!(
                f,
                "ana parola reddedildi: {uzunluk} karakter, gereken en az {en_kisa} ({gerekce})"
            ),
            Hata::GecersizAlan { alan, gerekce } => write!(f, "gecersiz alan '{alan}': {gerekce}"),
            Hata::YinelenenBaslik(baslik) => write!(f, "bu baslikta kayit zaten var: '{baslik}'"),
            Hata::KayitYok { baslik } => write!(f, "kayit bulunamadi (baslik: '{baslik}')"),
            Hata::VarOluyor(yol) => write!(f, "'{yol}' zaten var; kasa olusturma ustune yazmaz"),
            Hata::BozukArguman(detay) => write!(f, "gecersiz arguman: {detay}"),
            Hata::Kriptografik(detay) => write!(f, "kriptografik hata: {detay}"),
            Hata::BozukAktarim(detay) => write!(f, "aktarma belgesi hatali: {detay}"),
            Hata::Iptal => write!(f, "islem kullanici tarafindan iptal edildi"),
        }
    }
}

impl Error for Hata {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Hata::Io(hata) => Some(hata),
            _ => None,
        }
    }
}

impl From<io::Error> for Hata {
    fn from(hata: io::Error) -> Self {
        Hata::Io(hata)
    }
}
