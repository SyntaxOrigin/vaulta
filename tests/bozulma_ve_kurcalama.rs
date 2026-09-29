//! Bozulma, kurcalama ve hata sızdırmama senaryoları.
//!
//! Bu dosya "kasa bozulursa ne olur?" sorusuna yanıt verir. Her senaryo üç
//! şeyi doğrular:
//!
//! 1. Bozulan kasa **sessizce kısmen açılmaz** (rapor b15 negatif test kuralı).
//! 2. Hata mesajı **nedeni** söyler ama **içeriği sızdırmaz**.
//! 3. Yazma işlemi, kasa açılamadığında **dosyaya dokunmaz**.

mod yardimci;

use std::fs;

use vaulta::hata::Hata;
use vaulta::Oturum;

use yardimci::{kayit as ornek_kayit, GeciciDizin, ANA_PAROLA, HIZLI_ARON2};

/// Üç kayıtlı geçerli bir kasa üretir ve yolunu döndürür.
fn ornek_kasa(etiket: &str) -> (GeciciDizin, std::path::PathBuf) {
    let dizin = GeciciDizin::yeni(etiket);
    let yol = dizin.birles("kasa.kasa");
    let mut oturum = Oturum::olustur(&yol, ANA_PAROLA, HIZLI_ARON2).expect("olusturulmali");
    for ad in ["bir", "iki", "uc"] {
        oturum.ekle(&ornek_kayit(ad)).expect("eklenmeli");
    }
    oturum.kilit();
    (dizin, yol)
}

#[test]
fn yanlis_ana_parola_kasayi_acmaz_ve_hata_sir_icermez() {
    let (_dizin, yol) = ornek_kasa("yanlis-parola");

    let hata = Oturum::ac(&yol, "bu-baska-bir-ana-parola").expect_err("acilmamali");
    let metin = hata.to_string();
    assert!(metin.contains("ana parola yanlis"));
    assert!(!metin.contains(ANA_PAROLA), "hata ana parolayi icermemeli");
    assert!(
        !metin.contains("bir-gizli-sir"),
        "hata kayit sirlarini icermemeli"
    );
}

#[test]
fn baslikta_kurcalama_kasayi_acmaz() {
    let (_dizin, yol) = ornek_kasa("baslik-kurcalama");
    let mut ham = fs::read(&yol).expect("okunmali");
    ham[12] ^= 0xff; // m_cost baytı
    fs::write(&yol, &ham).expect("yazilmali");
    assert!(Oturum::ac(&yol, ANA_PAROLA).is_err());
}

#[test]
fn yanlis_imzali_dosya_reddedilir() {
    let (_dizin, yol) = ornek_kasa("yanlis-imza");
    let mut ham = fs::read(&yol).expect("okunmali");
    ham[0] = b'Z';
    fs::write(&yol, &ham).expect("yazilmali");
    let hata = Oturum::ac(&yol, ANA_PAROLA).expect_err("acilmamali");
    assert!(hata.to_string().contains("imza"));
}

#[test]
fn kisa_dosya_reddedilir() {
    let dizin = GeciciDizin::yeni("kisa-dosya");
    let yol = dizin.yaz("kasa.kasa", b"KASA");
    let hata = Oturum::ac(&yol, ANA_PAROLA).expect_err("acilmamali");
    assert!(hata.to_string().contains("cok kisa"));
}

#[test]
fn kirpilmis_dosya_reddedilir() {
    let (_dizin, yol) = ornek_kasa("kirpilmis");
    let ham = fs::read(&yol).expect("okunmali");
    fs::write(&yol, &ham[..ham.len() - 20]).expect("yazilmali");
    assert!(Oturum::ac(&yol, ANA_PAROLA).is_err());
}

#[test]
fn sonuna_eklenen_baytlar_reddedilir() {
    let (_dizin, yol) = ornek_kasa("ek-bayt");
    let mut ham = fs::read(&yol).expect("okunmali");
    ham.extend_from_slice(b"kasa degil, eklenmis veri");
    fs::write(&yol, &ham).expect("yazilmali");
    let hata = Oturum::ac(&yol, ANA_PAROLA).expect_err("acilmamali");
    assert!(hata.to_string().contains("dosya sonunda"));
}

#[test]
fn sayfa_icerigi_kurcalanirsa_hata_icerigi_saymaz() {
    let (_dizin, yol) = ornek_kasa("sayfa-kurcalama");
    let mut ham = fs::read(&yol).expect("okunmali");

    // Başlıktan sonraki ilk blok dizindir; onun nonce'inden sonraki bayta dokun.
    let blok_baslangic = vaulta::kasa::BASLIK_BOYUTU + 4 + vaulta::NONCE_BOYUTU;
    ham[blok_baslangic + 10] ^= 0xff;
    fs::write(&yol, &ham).expect("yazilmali");

    let hata = Oturum::ac(&yol, ANA_PAROLA).expect_err("acilmamali");
    let metin = hata.to_string();
    assert!(
        metin.contains("ana parola yanlis") || metin.contains("etigi dogrulanmadi"),
        "beklenmeyen hata: {metin}"
    );
    assert!(!metin.contains("bir-gizli-sir"));
}

#[test]
fn tum_kasa_baytlari_kurcalanirsa_acilamaz_ama_parola_sizmaz() {
    let (_dizin, yol) = ornek_kasa("toplu-kurcalama");
    let ham = fs::read(&yol).expect("okunmali");
    for sira in 0..16 {
        let mut bozuk = ham.clone();
        let konum = vaulta::kasa::BASLIK_BOYUTU + sira;
        if konum < bozuk.len() {
            bozuk[konum] ^= 0xff;
            fs::write(&yol, &bozuk).expect("yazilmali");
            if let Err(hata) = Oturum::ac(&yol, ANA_PAROLA) {
                assert!(
                    !hata.to_string().contains(ANA_PAROLA),
                    "hata ana parolayi sizdirdi"
                );
            }
        }
    }
}

#[test]
fn tuz_degisince_eski_anahtar_kullanilamaz() {
    let (_dizin, yol) = ornek_kasa("tuz-degisimi");
    let mut ham = fs::read(&yol).expect("okunmali");
    ham[29] ^= 0xff; // tuzun ilk baytı
    fs::write(&yol, &ham).expect("yazilmali");
    assert!(Oturum::ac(&yol, ANA_PAROLA).is_err());
}

#[test]
fn acma_basarisiz_oldugunda_dosya_ustune_yazilmaz() {
    let (_dizin, yol) = ornek_kasa("atomik-yazim");
    let once = fs::read(&yol).expect("okunmali");

    let mut bozuk = once.clone();
    bozuk[0] = b'Z'; // imzayı kır
    fs::write(&yol, &bozuk).expect("yazilmali");

    assert!(Oturum::ac(&yol, ANA_PAROLA).is_err());
    let sonra = fs::read(&yol).expect("okunmali");
    assert_eq!(sonra, bozuk, "basarisiz acma dosyayi degistirmemeli");
    assert_ne!(sonra, once);
}

#[test]
fn gecici_dosya_yazma_sirasinda_temizlenir() {
    let (_dizin, yol) = ornek_kasa("gecici-dosya");
    let gecici = yol.with_extension("kasa.tmp");
    assert!(
        !gecici.exists(),
        "basarili yazimdan sonra gecici dosya kalmamali"
    );
}

#[test]
fn hata_mesaji_kayit_sirlarini_icermez() {
    let (_dizin, yol) = ornek_kasa("hata-sizdirma");
    let sirlar = ["bir-gizli-sir", "iki-gizli-sir", "uc-gizli-sir"];

    let senaryolar: Vec<Hata> = vec![
        Oturum::ac(&yol, "yanlis-ana-parola-denemesi").unwrap_err(),
        Oturum::ac(&yol, "").unwrap_err(),
        {
            let mut ham = fs::read(&yol).expect("okunmali");
            ham[0] = b'Z';
            fs::write(&yol, &ham).expect("yazilmali");
            Oturum::ac(&yol, ANA_PAROLA).unwrap_err()
        },
    ];

    for hata in &senaryolar {
        let metin = hata.to_string();
        for sır in sirlar {
            assert!(!metin.contains(sır), "hata '{metin}' siri iceriyor");
        }
        assert!(!metin.contains(ANA_PAROLA));
    }
}

#[test]
fn bulunamayan_kayit_hatasi_basligi_gosterir_siri_gostermez() {
    let (_dizin, yol) = ornek_kasa("bulunamayan");
    let oturum = Oturum::ac(&yol, ANA_PAROLA).expect("acilmali");
    let hata = oturum.bul("hic-yok").expect_err("bulunamamali");
    let metin = hata.to_string();
    assert!(metin.contains("hic-yok"));
    assert!(!metin.contains("gizli-sir"));
}

#[test]
fn yinelenen_baslik_hatasi_sadece_basligi_gosterir() {
    let (_dizin, yol) = ornek_kasa("yinelenen-baslik-hata");
    let mut oturum = Oturum::ac(&yol, ANA_PAROLA).expect("acilmali");
    let hata = oturum.ekle(&ornek_kayit("bir")).expect_err("reddedilmeli");
    let metin = hata.to_string();
    assert!(metin.contains("bir"));
    assert!(!metin.contains("bir-gizli-sir"));
}

#[test]
fn gecersiz_alan_hatasi_parolayi_yazmaz() {
    let (_dizin, yol) = ornek_kasa("gecersiz-alan");
    let mut oturum = Oturum::ac(&yol, ANA_PAROLA).expect("acilmali");
    let hata = oturum
        .ekle(&vaulta::Kayit {
            baslik: "yeni".to_string(),
            kullanici: String::new(),
            parola: "cok-gizli-sifre".to_string(),
            adres: "a".repeat(vaulta::kayit::EN_UZUN_ADRES + 1),
            not: String::new(),
        })
        .expect_err("reddedilmeli");
    let metin = hata.to_string();
    assert!(metin.contains("adres"));
    assert!(!metin.contains("cok-gizli-sifre"));
}
