//! Kayıt veri modeli ve alan doğrulama kuralları.
//!
//! Bir kayıt beş metin alanından oluşur ve JSON olarak saklanır. Alan sınırları
//! burada tanımlanır çünkü hem dışa aktarma hem de sayfa çerçeveleme aynı
//! kurallara uyar; iki yerde ayrı doğrulama yapmak kural kaybına yol açar.
//!
//! # Alan sınırları neden var?
//!
//! Kasa tek dosyada yaşar ve tüm kayıtlar belleğe yüklenir. Sınırsız bir alan,
//! tek bir kayıtla kasanın tamamını belleğe sıkıştırma (decompression bomb)
//! saldırısına açık hale getirir. Sınırlar ayrıca çerçeve uzunluğu alanının
//! `u32` sınırında kalmasını garanti eder.

use serde::{Deserialize, Serialize};

use crate::hata::Hata;

/// Başlık alanının izin verilen azami karakter sayısı.
pub const EN_UZUN_BASLIK: usize = 256;

/// Kullanıcı adı alanının izin verilen azami karakter sayısı.
pub const EN_UZUN_KULLANICI: usize = 256;

/// Parola alanının izin verilen azami karakter sayısı.
pub const EN_UZUN_PAROLA: usize = 4096;

/// Adres (URL) alanının izin verilen azami karakter sayısı.
pub const EN_UZUN_ADRES: usize = 2048;

/// Not alanının izin verilen azami karakter sayısı.
pub const EN_UZUN_NOT: usize = 8192;

/// Kasa içindeki tek bir kimlik bilgisi kaydı.
///
/// Alan adları Türkçedir ama değerler tamamen Unicode'dur; `serde_json` bunu
/// doğru taşır (emoji ve surrogate çiftleri dahil). Alan sınırları **karakter**
/// sayısıyla ölçülür, bayt değil — böylece bir Türkçe başlık, ASCII karşılığıyla
/// aynı hakkı alır.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Kayit {
    /// Kullanıcının verdiği ad; kasada benzersizdir.
    pub baslik: String,
    /// Kullanıcı adı veya e-posta.
    pub kullanici: String,
    /// Asıl sır.
    pub parola: String,
    /// İsteğe bağlı adres / URL.
    pub adres: String,
    /// Serbest metin not.
    pub not: String,
}

impl Kayit {
    /// Alanları sınırlarına göre doğrular ve temizlenmiş bir kayıt döner.
    ///
    /// Başlık ve kullanıcı adının baş/son boşlukları temizlenir; parola ve not
    /// **temizlenmez** — baştaki ve sondaki boşluk parolanın parçası olabilir.
    pub fn dogrula(&self) -> Result<Kayit, Hata> {
        let baslik = self.baslik.trim();
        if baslik.is_empty() {
            return Err(Hata::GecersizAlan {
                alan: "baslik",
                gerekce: "bos olamaz".to_string(),
            });
        }
        if karakter_sayisi(&self.baslik) > EN_UZUN_BASLIK {
            return Err(Hata::GecersizAlan {
                alan: "baslik",
                gerekce: format!("en fazla {EN_UZUN_BASLIK} karakter olabilir"),
            });
        }
        if karakter_sayisi(&self.kullanici) > EN_UZUN_KULLANICI {
            return Err(Hata::GecersizAlan {
                alan: "kullanici",
                gerekce: format!("en fazla {EN_UZUN_KULLANICI} karakter olabilir"),
            });
        }
        if karakter_sayisi(&self.parola) > EN_UZUN_PAROLA {
            return Err(Hata::GecersizAlan {
                alan: "parola",
                gerekce: format!("en fazla {EN_UZUN_PAROLA} karakter olabilir"),
            });
        }
        if karakter_sayisi(&self.adres) > EN_UZUN_ADRES {
            return Err(Hata::GecersizAlan {
                alan: "adres",
                gerekce: format!("en fazla {EN_UZUN_ADRES} karakter olabilir"),
            });
        }
        if karakter_sayisi(&self.not) > EN_UZUN_NOT {
            return Err(Hata::GecersizAlan {
                alan: "not",
                gerekce: format!("en fazla {EN_UZUN_NOT} karakter olabilir"),
            });
        }
        if self.parola.contains('\u{0}') {
            return Err(Hata::GecersizAlan {
                alan: "parola",
                gerekce: "NUL karakteri iceremez".to_string(),
            });
        }
        Ok(Kayit {
            baslik: baslik.to_string(),
            kullanici: self.kullanici.clone(),
            parola: self.parola.clone(),
            adres: self.adres.trim().to_string(),
            not: self.not.clone(),
        })
    }
}

/// Bir dizgi içindeki Unicode karakter sayısı (bayt değil).
pub fn karakter_sayisi(metin: &str) -> usize {
    metin.chars().count()
}

/// Dizin kaydı: kasanın hangi kaydı hangi sayfada tuttuğunu söyler.
///
/// Parola **burada tutulmaz**; dizin yalnızca kimlik, başlık ve konum bilgisi
/// taşır. Böylece `list` komutu sayfaları çözmeden çalışır.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DizinKaydi {
    /// Kullanıcının verdiği benzersiz başlık.
    pub baslik: String,
    /// Kullanıcı adı (listede gösterilir, gizli değildir).
    pub kullanici: String,
    /// Kaydın bulunduğu sayfanın sırası.
    pub sayfa: u32,
    /// Kaydın sayfa içindeki çerçeve sırası.
    pub cerceve: u32,
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)] // WORKER_CONTRACT 4.2: testlerde panic araci gecerlidir
mod tests {
    use super::*;

    /// Testlerde kullanılan geçerli bir kayıt.
    fn ornek() -> Kayit {
        Kayit {
            baslik: "GitHub".to_string(),
            kullanici: "kullanici@example.com".to_string(),
            parola: "dogru-parola".to_string(),
            adres: "https://example.com".to_string(),
            not: "not".to_string(),
        }
    }

    #[test]
    fn gecerli_kayit_dogrulanir() {
        let temiz = ornek().dogrula().expect("gecerli kayit");
        assert_eq!(temiz.baslik, "GitHub");
        assert_eq!(temiz.adres, "https://example.com");
    }

    #[test]
    fn baslik_temizlenir_ve_bosluk_reddedilir() {
        let mut kayit = ornek();
        kayit.baslik = "   ".to_string();
        assert!(kayit.dogrula().is_err());
        kayit.baslik = "  GitHub  ".to_string();
        assert_eq!(kayit.dogrula().expect("gecerli").baslik, "GitHub");
    }

    #[test]
    fn parola_bastaki_sonki_boslugu_korunur() {
        let mut kayit = ornek();
        kayit.parola = "  girli bosluklu  ".to_string();
        let temiz = kayit.dogrula().expect("gecerli");
        assert_eq!(temiz.parola, "  girli bosluklu  ");
    }

    #[test]
    fn cok_uzun_baslik_reddedilir() {
        let mut kayit = ornek();
        kayit.baslik = "a".repeat(EN_UZUN_BASLIK + 1);
        assert!(kayit.dogrula().is_err());
    }

    #[test]
    fn tam_sinirdaki_baslik_kabul_edilir() {
        let mut kayit = ornek();
        kayit.baslik = "a".repeat(EN_UZUN_BASLIK);
        assert!(kayit.dogrula().is_ok());
    }

    #[test]
    fn cok_uzun_adres_reddedilir() {
        let mut kayit = ornek();
        kayit.adres = "https://".to_string() + &"a".repeat(EN_UZUN_ADRES);
        assert!(kayit.dogrula().is_err());
    }

    #[test]
    fn cok_uzun_not_reddedilir() {
        let mut kayit = ornek();
        kayit.not = "n".repeat(EN_UZUN_NOT + 1);
        assert!(kayit.dogrula().is_err());
    }

    #[test]
    fn cok_uzun_parola_reddedilir() {
        let mut kayit = ornek();
        kayit.parola = "p".repeat(EN_UZUN_PAROLA + 1);
        assert!(kayit.dogrula().is_err());
    }

    #[test]
    fn cok_uzun_kullanici_reddedilir() {
        let mut kayit = ornek();
        kayit.kullanici = "k".repeat(EN_UZUN_KULLANICI + 1);
        assert!(kayit.dogrula().is_err());
    }

    #[test]
    fn unicode_baslik_karakter_sayisiyla_olculur() {
        let mut kayit = ornek();
        // 200 emoji = 200 karakter ama 800 bayt. Bayt sınırı (256) aşılmış
        // olurdu; kabul edilmesi ölçütün bayt değil karakter olduğunu kanıtlar.
        kayit.baslik = "\u{1F512}".repeat(200);
        assert!(kayit.baslik.len() > EN_UZUN_BASLIK);
        assert!(kayit.dogrula().is_ok());
        kayit.baslik = "\u{1F512}".repeat(EN_UZUN_BASLIK + 1);
        assert!(kayit.dogrula().is_err());
    }

    #[test]
    fn turkce_ve_birlestirilmis_harfler_korunur() {
        let mut kayit = ornek();
        kayit.baslik = "ÇğİÖŞÜ çğıöşü İstanbul".to_string();
        kayit.kullanici = "ışık@ornek.com".to_string();
        let temiz = kayit.dogrula().expect("unicode gecerli");
        assert_eq!(temiz.baslik, kayit.baslik);
        assert_eq!(temiz.kullanici, kayit.kullanici);
    }

    #[test]
    fn sifir_uzunlukta_parola_kabul_edilir() {
        let mut kayit = ornek();
        kayit.parola = String::new();
        let temiz = kayit.dogrula().expect("bos parola gecerli bir alandir");
        assert_eq!(temiz.parola, "");
    }

    #[test]
    fn nul_karakteri_parolada_reddedilir() {
        let mut kayit = ornek();
        kayit.parola = "sifir\0sonu".to_string();
        assert!(kayit.dogrula().is_err());
    }

    #[test]
    fn json_gidis_donusu_korur() {
        let kayit = ornek();
        let metin = serde_json::to_string(&kayit).expect("serilestir");
        let geri: Kayit = serde_json::from_str(&metin).expect("ayristir");
        assert_eq!(kayit, geri);
    }

    #[test]
    fn json_unicode_karakterleri_korur() {
        let kayit = Kayit {
            baslik: "Şifre Kasası 🔐".to_string(),
            kullanici: "kullanıcı".to_string(),
            parola: "gizli-şifre".to_string(),
            adres: "https://örnek.com".to_string(),
            not: "not: çğıöşü".to_string(),
        };
        let metin = serde_json::to_string(&kayit).expect("serilestir");
        let geri: Kayit = serde_json::from_str(&metin).expect("ayristir");
        assert_eq!(kayit, geri);
    }

    #[test]
    fn karakter_sayisi_byte_degil_karakter_sayar() {
        assert_eq!(karakter_sayisi("abc"), 3);
        assert_eq!(karakter_sayisi("çğı"), 3);
        assert_eq!(karakter_sayisi("🔐🔐"), 2);
    }
}
