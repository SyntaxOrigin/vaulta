//! Şifreli olmayan JSON dışa/içe aktarma ve **doğrulamalı** aktarma.
//!
//! # Neden şifresiz JSON?
//!
//! Rapor, şifreli dışa aktarmayı v1'e ertelemiştir (MANIFEST kart 16, "Ertelenen").
//! MVP'de aktarma bilinçli olarak **şifresiz** JSON'dur ve bunun iki sonucu
//! vardır:
//!
//! 1. Bu dosya bir kasadan daha az güvenlidir. Taşınmadan önce ayrı bir
//!    yöntemle (ör. ayrı bir şifreli diske kopyalayarak) korunmalıdır.
//! 2. `export-verified` komutu, dışa aktarılan dosyayı **yeniden okuyup** her
//!    alanı kasa içeriğiyle karşılaştırır ve yalnızca hepsi tutarsa başarı
//!    bildirir. Böylece "yazdım ama okunmuyor" hatası yakalanır.
//!
//! Aktarma belgesi parolaları içerir; bu yüzden `export-verified` çıktısı
//! asla parolayı ekrana basmaz, yalnızca alan sayısını ve tutarlılık sonucunu
//! raporlar.

use std::fs;
use std::path::Path;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::depo::Oturum;
use crate::hata::Hata;
use crate::kayit::Kayit;

/// Aktarma belgesinin biçim sürümü.
pub const AKTARIM_SURUMU: u32 = 1;

/// Dışa aktarılan JSON belgesinin şeması.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Aktarim {
    /// Biçim sürümü.
    pub bicim: u32,
    /// Üreten uygulamanın adı.
    pub ureten: String,
    /// Kasadaki Argon2id bellek maliyeti (KiB) — yalnızca bilgi amaçlı.
    pub argon2_bellek_kib: u32,
    /// Kasadaki kayıt sayısı.
    pub kayit_sayisi: usize,
    /// Dışa aktarılan kayıtlar.
    pub kayitlar: Vec<Kayit>,
}

impl Aktarim {
    /// Oturumdaki tüm kayıtlarla bir aktarma belgesi oluşturur.
    pub fn oturumden(oturum: &Oturum) -> Result<Aktarim, Hata> {
        let mut kayitlar = Vec::with_capacity(oturum.kayit_sayisi());
        for sira in 0..oturum.kayit_sayisi() {
            kayitlar.push(oturum.sirayla_bul(sira)?);
        }
        Ok(Aktarim {
            bicim: AKTARIM_SURUMU,
            ureten: concat!("vaulta ", env!("CARGO_PKG_VERSION")).to_string(),
            argon2_bellek_kib: oturum.baslik().m_cost,
            kayit_sayisi: kayitlar.len(),
            kayitlar,
        })
    }

    /// Belgeyi JSON olarak okur.
    ///
    /// Bozuk JSON, eksik alan veya sürüm uyuşmazlığı `BozukAktarim` üretir;
    /// ayrıştırıcı **sessizce** varsayılan doldurmaz.
    pub fn oku(yol: &Path) -> Result<Aktarim, Hata> {
        let ham = fs::read_to_string(yol)?;
        Aktarim::coz(&ham)
    }

    /// JSON metninden belgeyi çözer.
    pub fn coz(metin: &str) -> Result<Aktarim, Hata> {
        let belge: Aktarim = serde_json::from_str(metin)
            .map_err(|hata| Hata::BozukAktarim(format!("JSON ayristirilemedi: {hata}")))?;
        if belge.bicim != AKTARIM_SURUMU {
            return Err(Hata::BozukAktarim(format!(
                "aktarma bicimi {} desteklenmiyor (beklenen {AKTARIM_SURUMU})",
                belge.bicim
            )));
        }
        if belge.kayit_sayisi != belge.kayitlar.len() {
            return Err(Hata::BozukAktarim(format!(
                "belge {} kayit diyor, {} kayit iceriyor",
                belge.kayit_sayisi,
                belge.kayitlar.len()
            )));
        }
        for (sira, kayit) in belge.kayitlar.iter().enumerate() {
            kayit.dogrula().map_err(|hata| {
                Hata::BozukAktarim(format!("belgedeki {sira}. kayit gecersiz: {hata}"))
            })?;
        }
        Ok(belge)
    }

    /// Belgeyi JSON olarak diske yazar.
    pub fn yaz(&self, yol: &Path) -> Result<(), Hata> {
        let metin = serde_json::to_string_pretty(self)
            .map_err(|hata| Hata::BozukAktarim(format!("JSON uretilemedi: {hata}")))?;
        fs::write(yol, metin)?;
        Ok(())
    }

    /// Belgenin içerik özetini (SHA-256) döndürür.
    ///
    /// Özet **parola içermez**; yalnızca alanların serileştirilmiş hâlinden
    /// türetilir ve doğrulama raporunda kullanılır.
    pub fn ozet(&self) -> [u8; 32] {
        let mut karma = Sha256::new();
        karma.update(self.bicim.to_le_bytes());
        for kayit in &self.kayitlar {
            karma.update(kayit.baslik.as_bytes());
            karma.update(b"\x1f");
            karma.update(kayit.kullanici.as_bytes());
            karma.update(b"\x1f");
            karma.update(kayit.parola.as_bytes());
            karma.update(b"\x1f");
            karma.update(kayit.adres.as_bytes());
            karma.update(b"\x1f");
            karma.update(kayit.not.as_bytes());
            karma.update(b"\x1e");
        }
        let sonuc = karma.finalize();
        let mut dizi = [0u8; 32];
        dizi.copy_from_slice(&sonuc);
        dizi
    }
}

/// Dışa aktarma doğrulama sonucu.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DogrulamaRaporu {
    /// Belgede bulunan kayıt sayısı.
    pub kayit_sayisi: usize,
    /// Alan bazında karşılaştırılan alan sayısı.
    pub alan_sayisi: usize,
    /// Kasa ile belge arasında farklı olan alanların listesi.
    ///
    /// Boşse aktarma birebir tutarlıdır. Girdi **parola içermez**, yalnızca
    /// başlık ve alan adı taşır.
    pub farklar: Vec<String>,
    /// Belgenin SHA-256 içerik özeti (hex).
    pub ozet: String,
}

impl DogrulamaRaporu {
    /// Rapor başarılı mı?
    pub fn basarili_mi(&self) -> bool {
        self.farklar.is_empty()
    }
}

/// Kasa içeriğini JSON olarak dışa aktarır ve **hemen geri okuyarak doğrular**.
///
/// Doğrulama iki katmanlıdır:
///
/// 1. Yazılan dosya yeniden okunur ve JSON olarak ayrıştırılır (biçim kontrolü).
/// 2. Her kaydın her alanı kasadaki çözülmüş kayıtla karşılaştırılır (içerik
///    kontrolü). Fark varsa `farklar` dolu döner ve komut başarısız çıkar.
pub fn disa_aktar_ve_dogrula(oturum: &Oturum, yol: &Path) -> Result<DogrulamaRaporu, Hata> {
    let belge = Aktarim::oturumden(oturum)?;
    belge.yaz(yol)?;

    let okunan = Aktarim::oku(yol)?;
    let mut farklar = Vec::new();
    let mut alan_sayisi = 0usize;

    if okunan.kayitlar.len() != belge.kayitlar.len() {
        farklar.push(format!(
            "kayit sayisi degisti: yazilan {} okunan {}",
            belge.kayitlar.len(),
            okunan.kayitlar.len()
        ));
    }
    for (sira, (yazilan, gelen)) in belge
        .kayitlar
        .iter()
        .zip(okunan.kayitlar.iter())
        .enumerate()
    {
        for alan in ALANLAR {
            alan_sayisi += 1;
            let a = alan_degistir(yazilan, alan);
            let b = alan_degistir(gelen, alan);
            if a != b {
                farklar.push(format!(
                    "{sira}. kayit '{}' alan '{alan}' farkli",
                    yazilan.baslik
                ));
            }
        }
    }

    Ok(DogrulamaRaporu {
        kayit_sayisi: okunan.kayitlar.len(),
        alan_sayisi,
        farklar,
        ozet: hex(&okunan.ozet()),
    })
}

/// Aktarım belgesindeki alan adları.
pub const ALANLAR: [&str; 5] = ["baslik", "kullanici", "parola", "adres", "not"];

/// Bir kaydın belirtilen alanını döndürür.
fn alan_degistir<'a>(kayit: &'a Kayit, alan: &str) -> &'a str {
    match alan {
        "baslik" => &kayit.baslik,
        "kullanici" => &kayit.kullanici,
        "parola" => &kayit.parola,
        "adres" => &kayit.adres,
        _ => &kayit.not,
    }
}

/// Bayt dizisini küçük harfli hex'e çevirir.
pub fn hex(bayt: &[u8]) -> String {
    bayt.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)] // WORKER_CONTRACT 4.2: testlerde panic araci gecerlidir
mod tests {
    use super::*;

    /// Testlerde kullanılan geçerli bir kayıt.
    fn ornek_kayit(baslik: &str) -> Kayit {
        Kayit {
            baslik: baslik.to_string(),
            kullanici: format!("{baslik}@example.com"),
            parola: format!("{baslik}-gizli-parola"),
            adres: format!("https://{baslik}.example.com"),
            not: format!("{baslik} notu"),
        }
    }

    #[test]
    fn aktarim_belgesi_json_gidis_donusu() {
        let belge = Aktarim {
            bicim: AKTARIM_SURUMU,
            ureten: "test".to_string(),
            argon2_bellek_kib: 65_536,
            kayit_sayisi: 2,
            kayitlar: vec![ornek_kayit("bir"), ornek_kayit("iki")],
        };
        let metin = serde_json::to_string(&belge).expect("serilestir");
        let geri = Aktarim::coz(&metin).expect("ayristir");
        assert_eq!(belge, geri);
    }

    #[test]
    fn bozuk_json_reddedilir() {
        let hata = Aktarim::coz("{ bu json degil").expect_err("bozuk json reddedilmeli");
        assert!(hata.to_string().contains("JSON"));
    }

    #[test]
    fn eksik_alan_olan_json_reddedilir() {
        let metin = r#"{"bicim":1,"ureten":"test","argon2_bellek_kib":65536,"kayit_sayisi":0}"#;
        assert!(Aktarim::coz(metin).is_err());
    }

    #[test]
    fn desteklenmeyen_bicim_reddedilir() {
        let metin =
            r#"{"bicim":99,"ureten":"t","argon2_bellek_kib":1,"kayit_sayisi":0,"kayitlar":[]}"#;
        let hata = Aktarim::coz(metin).expect_err("bicim reddedilmeli");
        assert!(hata.to_string().contains("bicimi"));
    }

    #[test]
    fn kayit_sayisi_uyusmazligi_reddedilir() {
        let metin =
            r#"{"bicim":1,"ureten":"t","argon2_bellek_kib":1,"kayit_sayisi":3,"kayitlar":[]}"#;
        let hata = Aktarim::coz(metin).expect_err("sayi uyusmazligi reddedilmeli");
        assert!(hata.to_string().contains("kayit"));
    }

    #[test]
    fn bos_baslikli_kayit_reddedilir() {
        let metin = r#"{"bicim":1,"ureten":"t","argon2_bellek_kib":1,"kayit_sayisi":1,
            "kayitlar":[{"baslik":"  ","kullanici":"","parola":"","adres":"","not":""}]}"#;
        assert!(Aktarim::coz(metin).is_err());
    }

    #[test]
    fn ozet_icerik_degisince_degisir() {
        let bir = Aktarim {
            bicim: AKTARIM_SURUMU,
            ureten: "test".to_string(),
            argon2_bellek_kib: 1,
            kayit_sayisi: 1,
            kayitlar: vec![ornek_kayit("bir")],
        };
        let mut iki = bir.clone();
        iki.kayitlar[0].parola = "degistirildi".to_string();
        assert_ne!(bir.ozet(), iki.ozet());
    }

    #[test]
    fn ozet_ayni_icerik_icin_ayni() {
        let bir = Aktarim {
            bicim: AKTARIM_SURUMU,
            ureten: "test".to_string(),
            argon2_bellek_kib: 1,
            kayit_sayisi: 1,
            kayitlar: vec![ornek_kayit("bir")],
        };
        let iki = bir.clone();
        assert_eq!(bir.ozet(), iki.ozet());
    }

    #[test]
    fn alan_listesi_bes_alan_tutar() {
        assert_eq!(ALANLAR.len(), 5);
        for alan in ALANLAR {
            let kayit = ornek_kayit("x");
            assert!(!alan_degistir(&kayit, alan).is_empty());
        }
    }

    #[test]
    fn hex_kucuk_harfli_uretir() {
        assert_eq!(hex(&[0x00, 0x0f, 0xff]), "000fff");
    }

    #[test]
    fn dogrulama_raporu_basarili_durumu() {
        let rapor = DogrulamaRaporu {
            kayit_sayisi: 3,
            alan_sayisi: 15,
            farklar: Vec::new(),
            ozet: "abc".to_string(),
        };
        assert!(rapor.basarili_mi());
    }

    #[test]
    fn dogrulama_raporu_farkli_durumu() {
        let rapor = DogrulamaRaporu {
            kayit_sayisi: 3,
            alan_sayisi: 15,
            farklar: vec!["0. kayit parola farkli".to_string()],
            ozet: "abc".to_string(),
        };
        assert!(!rapor.basarili_mi());
    }
}
