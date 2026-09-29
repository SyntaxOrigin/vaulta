//! Entegrasyon testleri için ortak yardımcılar.
//!
//! `tempfile` crate'i bağımlılık politikası gereği yasaktır
//! (WORKER_CONTRACT §3.2), bu yüzden geçici dizin üretimi ve temizliği kendi
//! kodumuzla yapılır. Benzersizlik `std::process::id()`, etiket ve bir atomik
//! sayaç üçlüsünden türetilir; rastgelelik crate'i kullanılmaz ve testler
//! birbirinden bağımsızdır.
//!
//! `Drop` içinden hata döndürülemediği için temizlik hatası `let _ =` ile
//! bilinçli olarak yutulur; bu, sözleşmenin "sessiz yutma" yasağına yegdir
//! (WORKER_CONTRACT §5.3) ve README'de belgelenmiştir.

#![allow(dead_code)]

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use vaulta::kayit::Kayit;
use vaulta::kripto::Argon2Ayar;

/// Testlerde kullanılan hızlı Argon2id parametreleri.
///
/// Varsayılan (64 MiB / 3 tur / 4 yol) her çağrıda yüzlerce milisaniye sürer
/// ve yüzlerce testi gereksiz uzatır. Buradaki değerler `Argon2Ayar::dogrula`
/// sınırları içindedir; kriptografik parametrelerin kasa başlığına doğru
/// taşındığı ayrıca test edilir.
pub const HIZLI_ARON2: Argon2Ayar = Argon2Ayar::HIZLI;

/// Testlerde kullanılan geçerli ana parola (kaba parola denetiminden geçer).
pub const ANA_PAROLA: &str = "bu-ciddi-bir-ana-parola-2026";

static SAYAC: AtomicU64 = AtomicU64::new(0);

/// Drop ile temizlenen geçici dizin kapsayıcısı.
pub struct GeciciDizin {
    yol: PathBuf,
}

impl GeciciDizin {
    /// `std::env::temp_dir()` altında benzersiz bir dizin oluşturur.
    pub fn yeni(etiket: &str) -> GeciciDizin {
        let sira = SAYAC.fetch_add(1, Ordering::Relaxed);
        let kok = std::env::temp_dir().join(format!(
            "vaulta-test-{etiket}-{}-{sira}",
            std::process::id()
        ));
        // Aynı etiketle ikinci kez açılırsa eski içerik önce silinir.
        let _ = fs::remove_dir_all(&kok);
        fs::create_dir_all(&kok).expect("gecici dizin olusturulamadi");
        GeciciDizin { yol: kok }
    }

    /// Dizinin tam yolu.
    pub fn yol(&self) -> &Path {
        &self.yol
    }

    /// Alt dosya yolu.
    pub fn birles(&self, ad: &str) -> PathBuf {
        self.yol.join(ad)
    }

    /// Alt dosyayı oluşturup içeriğini yazar.
    pub fn yaz(&self, ad: &str, icerik: &[u8]) -> PathBuf {
        let yol = self.birles(ad);
        fs::write(&yol, icerik).expect("dosya yazilamadi");
        yol
    }

    /// Var olan dosyanın baytlarını okur.
    pub fn oku(&self, ad: &str) -> Vec<u8> {
        fs::read(self.birles(ad)).expect("dosya okunamadi")
    }
}

impl Drop for GeciciDizin {
    fn drop(&mut self) {
        // Temizlik başarısız olsa da testi düşürmemeli; `let _ =` bilinçlidir.
        let _ = fs::remove_dir_all(&self.yol);
    }
}

/// Test verisi üretir: `tohum` değerine göre tekrarlanabilir (deterministik) baytlar.
pub fn veri(bayt: usize, tohum: u8) -> Vec<u8> {
    (0..bayt)
        .map(|i| tohum.wrapping_add((i % 251) as u8))
        .collect()
}

/// Bayt dizisini hex'e çevirir (hata mesajlarında kullanılır).
pub fn hex(bayt: &[u8]) -> String {
    bayt.iter().map(|b| format!("{b:02x}")).collect()
}

/// Testlerde kullanılan geçerli bir kayıt üretir.
pub fn kayit(baslik: &str) -> Kayit {
    Kayit {
        baslik: baslik.to_string(),
        kullanici: format!("{baslik}@example.com"),
        parola: format!("{baslik}-gizli-sir"),
        adres: format!("https://{baslik}.example.com"),
        not: format!("{baslik} notu"),
    }
}
