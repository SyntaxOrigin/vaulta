//! Güvenlik sözleşmesi testleri: ağ yüzeyinin yokluğu, `zeroize` davranışı,
//! sır sızdırmama ve biçim bütünlüğü.
//!
//! Bu dosya "rapor b10 tehdit modelindeki azaltma maddeleri gerçekten uygulanıyor mu?"
//! sorusuna yanıt verir. Testler kaynak kodu **derleme zamanında** gömerek okur
//! (`include_str!`), böylece çalışma anında dosya sistemine bağımlılık olmaz.

mod yardimci;

use std::fs;

use vaulta::hata::Hata;
use vaulta::kripto::Argon2Ayar;
use vaulta::Oturum;

use yardimci::{kayit as ornek_kayit, GeciciDizin, ANA_PAROLA, HIZLI_ARON2};

/// Kaynak dosyaların tamamı. `include_str!` derleme zamanında gömüldüğü için
/// test, çalışma anında disk okumaz ve yol bağımsızdır.
const KAYNAKLAR: &[(&str, &str)] = &[
    ("lib.rs", include_str!("../src/lib.rs")),
    ("main.rs", include_str!("../src/main.rs")),
    ("hata.rs", include_str!("../src/hata.rs")),
    ("kasa.rs", include_str!("../src/kasa.rs")),
    ("kayit.rs", include_str!("../src/kayit.rs")),
    ("kripto.rs", include_str!("../src/kripto.rs")),
    ("parola.rs", include_str!("../src/parola.rs")),
    ("depo.rs", include_str!("../src/depo.rs")),
    ("aktarim.rs", include_str!("../src/aktarim.rs")),
];

/// Bir kaynak dosyadan `//` ile başlayan yorum satırlarını ayıklar.
///
/// Neden: yorumlarında "ağ yığını hiç çağrılmaz" diye **sembol adı yazan**
/// modüller vardır; denetim kod üzerinde yapılmalıdır, sözcük üzerinde değil.
/// Yan etki: `https://` gibi dizgi sabitlerinin kalanı da atılır, bu yüzden
/// denetim biraz daha gevşektir — ama gevşe yön güvenli yöndür, çünkü
/// `tokio::`, `std::net` gibi **yol** biçimli semboller yorum satırlarında
/// görünmez.
fn yorumlari_at(kaynak: &str) -> String {
    kaynak
        .lines()
        .map(|satir| match satir.find("//") {
            Some(konum) => &satir[..konum],
            None => satir,
        })
        .collect::<Vec<&str>>()
        .join("\n")
}

#[test]
fn kaynakta_ag_yuzeyi_yoktur() {
    // Rapordan gelen kural: "ağ yığını hiç çağrılmaz". Kasa hiçbir ağ
    // yığını çağırmıyorsa, bu sembollerin hiçbiri kaynak **kodunda** geçmemeli.
    const YASAK: &[&str] = &[
        "std::net",
        "TcpStream",
        "TcpListener",
        "UdpSocket",
        "UnixStream",
        "reqwest",
        "ureq",
        "hyper",
        "tokio",
        "curl",
        "openssl",
        "rustls",
        "websocket",
        "dns",
    ];
    for (ad, kaynak) in KAYNAKLAR {
        let kod = yorumlari_at(kaynak);
        for sembol in YASAK {
            assert!(
                !kod.contains(sembol),
                "{ad} icinde ag yuzeyi bulundu: {sembol}"
            );
        }
    }
}

#[test]
fn kaynakta_zararli_agac_konumlar_yoktur() {
    const YASAK: &[&str] = &[
        "rand::",
        "use rand",
        "notify::",
        "walkdir::",
        "chrono::",
        "OffsetDateTime",
        "tokio::",
        "async_std::",
        "egui::",
        "winit::",
        "unsafe {",
    ];
    for (ad, kaynak) in KAYNAKLAR {
        let kod = yorumlari_at(kaynak);
        for sembol in YASAK {
            assert!(
                !kod.contains(sembol),
                "{ad} icinde yasakli bagimlilik: {sembol}"
            );
        }
    }
}

#[test]
fn kendi_kodumuzda_unsafe_kullanilmaz() {
    // `forbid(unsafe_code)` derleyici seviyesinde zorlar; bu test, ilke
    // kuralının kaynak metninde de bozulmadığını doğrular.
    let lib = KAYNAKLAR[0].1;
    assert!(lib.contains("#![forbid(unsafe_code)]"));
    let main = KAYNAKLAR[1].1;
    assert!(main.contains("#![forbid(unsafe_code)]"));
    for (ad, kaynak) in KAYNAKLAR {
        assert!(!kaynak.contains("unsafe fn"), "{ad} icinde unsafe fn var");
    }
}

#[test]
fn uretim_kodunda_panic_yoktur() {
    // `#[cfg(test)]` blokları hariç: onlar testlerdir, üretim yolu değildir.
    for (ad, kaynak) in KAYNAKLAR {
        let uretim = yorumlari_at(kaynak)
            .split("#[cfg(test)]")
            .next()
            .unwrap_or("")
            .to_string();
        for yasak in ["unwrap()", "expect(", "panic!("] {
            assert!(
                !uretim.contains(yasak),
                "{ad} uretim kodunda '{yasak}' bulundu"
            );
        }
    }
}

#[test]
fn oturum_debug_iktisi_sir_icermez() {
    let dizin = GeciciDizin::yeni("debug-sizdirma");
    let yol = dizin.birles("kasa.kasa");

    let mut oturum = Oturum::olustur(&yol, ANA_PAROLA, HIZLI_ARON2).expect("olusturulmali");
    oturum
        .ekle(&vaulta::Kayit {
            baslik: "GitHub".to_string(),
            kullanici: "kullanici@example.com".to_string(),
            parola: "cok-gizli-sifre".to_string(),
            adres: "https://example.com".to_string(),
            not: "gizli-not".to_string(),
        })
        .expect("eklenmeli");

    let metin = format!("{oturum:?}");
    assert!(metin.contains("Oturum"));
    assert!(!metin.contains("cok-gizli-sifre"));
    assert!(!metin.contains("kullanici@example.com"));
    assert!(!metin.contains("gizli-not"));
    assert!(!metin.contains(ANA_PAROLA));
    assert!(!metin.contains(&vaulta::aktarim::hex(&oturum.tuz())));
}

#[test]
fn zeroize_kullanimi_belgelenmistir() {
    let kripto = KAYNAKLAR
        .iter()
        .find(|(ad, _)| *ad == "kripto.rs")
        .map(|(_, kaynak)| *kaynak)
        .unwrap_or("");
    assert!(
        kripto.contains("Zeroizing"),
        "kripto.rs Zeroizing kullanmali"
    );
    let depo = KAYNAKLAR
        .iter()
        .find(|(ad, _)| *ad == "depo.rs")
        .map(|(_, kaynak)| *kaynak)
        .unwrap_or("");
    assert!(depo.contains("zeroize"), "depo.rs zeroize kullanmali");
    assert!(
        depo.contains("fn kilit(&mut self)"),
        "depo.rs kilit sunmali"
    );
}

#[test]
fn kilit_anahtar_bellegini_sifirlar() {
    let dizin = GeciciDizin::yeni("zeroize");
    let yol = dizin.birles("kasa.kasa");

    let mut oturum = Oturum::olustur(&yol, ANA_PAROLA, HIZLI_ARON2).expect("olusturulmali");
    oturum.ekle(&ornek_kayit("GitHub")).expect("eklenmeli");
    assert!(oturum.bellek_hazir_mi());

    // Yazma işlemi de anahtarı kullanır; kilit bunu bozmaz.
    oturum.kaydet().expect("yazilmali");
    assert!(oturum.bellek_hazir_mi());

    oturum.kilit();
    assert!(!oturum.bellek_hazir_mi(), "kilit bellegi sifirlamali");

    // Kilitli oturum yeniden yazamaz ve sıfırlanan anahtarla şifreleyemez.
    assert!(matches!(oturum.kaydet(), Err(Hata::Iptal)));
    assert!(matches!(
        oturum.ana_parola_degistir("yeni-ana-parola-2026", HIZLI_ARON2),
        Err(Hata::Iptal)
    ));

    // Dosya hala saglam.
    let yeniden = Oturum::ac(&yol, ANA_PAROLA).expect("acilmali");
    assert!(yeniden.bul("GitHub").is_ok());
}

#[test]
fn ana_parola_degisikligi_eskiden_farkli_tuz_uretir() {
    let dizin = GeciciDizin::yeni("rotasyon-tuz");
    let yol = dizin.birles("kasa.kasa");

    let mut oturum = Oturum::olustur(&yol, ANA_PAROLA, HIZLI_ARON2).expect("olusturulmali");
    oturum.ekle(&ornek_kayit("GitHub")).expect("eklenmeli");
    let ilk_tuz = oturum.tuz();

    for _ in 0..4 {
        oturum
            .ana_parola_degistir("her-seferinde-farkli-ana-parola", HIZLI_ARON2)
            .expect("degistirilmeli");
        assert_ne!(oturum.tuz(), ilk_tuz, "her rotasyonda yeni tuz uretilmeli");
    }
    oturum.kilit();

    let kontrol = Oturum::ac(&yol, "her-seferinde-farkli-ana-parola").expect("acilmali");
    assert_eq!(
        kontrol.bul("GitHub").expect("bulunmali").parola,
        "GitHub-gizli-sir"
    );
}

#[test]
fn gecersiz_argon2_ayari_kasayi_acmaz() {
    let dizin = GeciciDizin::yeni("gecersiz-ayar");
    let yol = dizin.birles("kasa.kasa");

    // m_cost < 8 * p_cost: Argon2'in kendi gereksinimi.
    let gecersiz = Argon2Ayar {
        bellek_kib: 8,
        tur: 1,
        yol: 4,
    };
    assert!(Oturum::olustur(&yol, ANA_PAROLA, gecersiz).is_err());
    assert!(!yol.exists());
}

#[test]
fn dosya_bicimi_kendi_kendini_denetler() {
    let dizin = GeciciDizin::yeni("bicim-deneti");
    let yol = dizin.birles("kasa.kasa");

    let mut oturum = Oturum::olustur(&yol, ANA_PAROLA, HIZLI_ARON2).expect("olusturulmali");
    for ad in ["bir", "iki", "uc"] {
        oturum.ekle(&ornek_kayit(ad)).expect("eklenmeli");
    }
    oturum.kilit();

    let ham = fs::read(&yol).expect("okunmali");
    assert_eq!(&ham[0..4], b"KASA");
    assert_eq!(ham[4], vaulta::KASA_SURUMU as u8);
    // Ayrılmış alanlar sıfırdır.
    assert!(ham[45..vaulta::kasa::BASLIK_BOYUTU].iter().all(|b| *b == 0));

    // Kayıt parolaları düz metin olarak dosyada bulunmamalı.
    let metin = String::from_utf8_lossy(&ham);
    for sır in ["bir-gizli-sir", "iki-gizli-sir", "uc-gizli-sir", "GitHub"] {
        assert!(
            !metin.contains(sır),
            "dosyada '{sır}' duz metin olarak bulundu"
        );
    }

    // Ana parola da dosyada olmamalı.
    assert!(!metin.contains(ANA_PAROLA));
}

#[test]
fn her_yazimda_nonce_degisir() {
    let dizin = GeciciDizin::yeni("nonce-degisimi");
    let yol = dizin.birles("kasa.kasa");

    let mut oturum = Oturum::olustur(&yol, ANA_PAROLA, HIZLI_ARON2).expect("olusturulmali");
    oturum.ekle(&ornek_kayit("GitHub")).expect("eklenmeli");

    let ofset = vaulta::kasa::BASLIK_BOYUTU + 4;
    let once = fs::read(&yol).expect("okunmali")[ofset..ofset + vaulta::NONCE_BOYUTU].to_vec();
    oturum.kaydet().expect("yazilmali");
    let sonra = fs::read(&yol).expect("okunmali")[ofset..ofset + vaulta::NONCE_BOYUTU].to_vec();
    assert_ne!(once, sonra, "her yazimda nonce yeniden uretilmeli");
}

#[test]
fn disa_aktarilan_belge_ayri_dosyada_saklanir_ve_dogrulanir() {
    let dizin = GeciciDizin::yeni("aktarim-dogrulama");
    let yol = dizin.birles("kasa.kasa");
    let cikti = dizin.birles("export.json");

    let mut oturum = Oturum::olustur(&yol, ANA_PAROLA, HIZLI_ARON2).expect("olusturulmali");
    for ad in ["bir", "iki"] {
        oturum.ekle(&ornek_kayit(ad)).expect("eklenmeli");
    }

    let rapor = vaulta::disa_aktar_ve_dogrula(&oturum, &cikti).expect("aktarilmali");
    assert!(rapor.basarili_mi());
    // Doğrulama raporunda parola bulunmaz.
    let rapor_metin = format!("{rapor:?}");
    assert!(!rapor_metin.contains("bir-gizli-sir"));
    assert!(!rapor_metin.contains("iki-gizli-sir"));
}
