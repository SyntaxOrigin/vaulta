//! Uçtan uca kasa yaşam döngüsü testleri.
//!
//! Bu dosya "bir kullanıcı ne yaparsa kasa tutarlı mı kalır?" sorusuna yanıt
//! verir: oluşturma, ekleme, listeleme, okuma, silme, ana parola değiştirme,
//! yeniden paketleme, kilitleme ve dışa/içe aktarma.
//!
//! Tüm testler `std::env::temp_dir()` altında kendi dizinlerini açar; hiçbiri
//! ağa çıkmaz, `SystemTime`'ı kararda kullanmaz ve birbirinin dosyasına
//! güvenmez.

mod yardimci;

use std::fs;

use vaulta::aktarim::{disa_aktar_ve_dogrula, Aktarim};
use vaulta::hata::Hata;
use vaulta::kayit::Kayit;
use vaulta::kripto::Argon2Ayar;
use vaulta::Oturum;

use yardimci::{kayit as ornek_kayit, GeciciDizin, ANA_PAROLA, HIZLI_ARON2};

#[test]
fn bos_kasaya_ilk_kayit_eklenir_ve_okunur() {
    let dizin = GeciciDizin::yeni("bos-kasa");
    let yol = dizin.birles("kasa.kasa");

    let mut oturum = Oturum::olustur(&yol, ANA_PAROLA, HIZLI_ARON2).expect("kasa olusturulmali");
    assert_eq!(oturum.kayit_sayisi(), 0);
    assert!(oturum.listele().expect("liste").is_empty());

    oturum.ekle(&ornek_kayit("GitHub")).expect("eklenmeli");
    assert_eq!(oturum.kayit_sayisi(), 1);
    oturum.kilit();

    let yeniden = Oturum::ac(&yol, ANA_PAROLA).expect("kasa acilmali");
    let bulunan = yeniden.bul("GitHub").expect("kayit bulunmali");
    assert_eq!(bulunan.parola, "GitHub-gizli-sir");
    assert_eq!(bulunan.adres, "https://GitHub.example.com");
}

#[test]
fn dolu_kasa_listelenir_ve_sira_korunur() {
    let dizin = GeciciDizin::yeni("dolu-kasa");
    let yol = dizin.birles("kasa.kasa");

    let mut oturum = Oturum::olustur(&yol, ANA_PAROLA, HIZLI_ARON2).expect("olusturulmali");
    for ad in ["alpha", "beta", "gamma", "delta", "epsilon"] {
        oturum.ekle(&ornek_kayit(ad)).expect("eklenmeli");
    }
    oturum.kilit();

    let yeniden = Oturum::ac(&yol, ANA_PAROLA).expect("acilmali");
    let liste = yeniden.listele().expect("liste");
    assert_eq!(liste.len(), 5);
    let basliklar: Vec<&str> = liste.iter().map(|k| k.baslik.as_str()).collect();
    assert_eq!(basliklar, ["alpha", "beta", "gamma", "delta", "epsilon"]);
}

#[test]
fn olmayan_kayit_arama_hata_dondurur() {
    let dizin = GeciciDizin::yeni("olmayan-kayit");
    let yol = dizin.birles("kasa.kasa");

    let mut oturum = Oturum::olustur(&yol, ANA_PAROLA, HIZLI_ARON2).expect("olusturulmali");
    oturum.ekle(&ornek_kayit("GitHub")).expect("eklenmeli");
    oturum.kilit();

    let yeniden = Oturum::ac(&yol, ANA_PAROLA).expect("acilmali");
    assert!(yeniden.bul("olmayan-baslik").is_err());
    assert!(yeniden.sirayla_bul(99).is_err());
}

#[test]
fn ayni_baslik_iki_kez_eklenemez() {
    let dizin = GeciciDizin::yeni("yinelenen-baslik");
    let yol = dizin.birles("kasa.kasa");

    let mut oturum = Oturum::olustur(&yol, ANA_PAROLA, HIZLI_ARON2).expect("olusturulmali");
    oturum.ekle(&ornek_kayit("GitHub")).expect("eklenmeli");
    let hata = oturum
        .ekle(&ornek_kayit("GitHub"))
        .expect_err("yinelenen baslik reddedilmeli");
    assert!(matches!(hata, Hata::YinelenenBaslik(_)));
    assert_eq!(oturum.kayit_sayisi(), 1);
}

#[test]
fn kayit_silinir_ve_kalanlar_kayar() {
    let dizin = GeciciDizin::yeni("kayit-silme");
    let yol = dizin.birles("kasa.kasa");

    let mut oturum = Oturum::olustur(&yol, ANA_PAROLA, HIZLI_ARON2).expect("olusturulmali");
    for ad in ["bir", "iki", "uc", "dort"] {
        oturum.ekle(&ornek_kayit(ad)).expect("eklenmeli");
    }
    oturum.sil("iki").expect("silinmeli");
    assert_eq!(oturum.kayit_sayisi(), 3);
    oturum.kilit();

    let yeniden = Oturum::ac(&yol, ANA_PAROLA).expect("acilmali");
    assert!(yeniden.bul("iki").is_err());
    assert!(yeniden.bul("bir").is_ok());
    assert!(yeniden.bul("uc").is_ok());
    assert!(yeniden.bul("dort").is_ok());
}

#[test]
fn olmayan_kayit_silme_hata_dondurur() {
    let dizin = GeciciDizin::yeni("olmayan-silme");
    let yol = dizin.birles("kasa.kasa");

    let mut oturum = Oturum::olustur(&yol, ANA_PAROLA, HIZLI_ARON2).expect("olusturulmali");
    oturum.ekle(&ornek_kayit("tek")).expect("eklenmeli");
    assert!(oturum.sil("olmayan").is_err());
    assert_eq!(oturum.kayit_sayisi(), 1);
}

#[test]
fn basliklara_gore_arama_buyuk_kucuk_harf_duyarsizdir() {
    let dizin = GeciciDizin::yeni("baslik-arama");
    let yol = dizin.birles("kasa.kasa");

    let mut oturum = Oturum::olustur(&yol, ANA_PAROLA, HIZLI_ARON2).expect("olusturulmali");
    oturum.ekle(&ornek_kayit("GitHub")).expect("eklenmeli");
    assert!(oturum.bul("  github  ").is_ok());
    assert!(oturum.sil("GITHUB").is_ok());
}

#[test]
fn kurulum_tekrarlari_ayni_dosyayi_ustune_yazmaz() {
    let dizin = GeciciDizin::yeni("kurulum-tekrari");
    let yol = dizin.birles("kasa.kasa");

    let mut oturum = Oturum::olustur(&yol, ANA_PAROLA, HIZLI_ARON2).expect("olusturulmali");
    oturum.ekle(&ornek_kayit("GitHub")).expect("eklenmeli");
    oturum.kilit();
    let ilk_boyut = fs::metadata(&yol).expect("olcüm").len();

    let hata = Oturum::olustur(&yol, ANA_PAROLA, HIZLI_ARON2).expect_err("ustune yazmamali");
    assert!(matches!(hata, Hata::VarOluyor(_)));
    assert_eq!(
        fs::metadata(&yol).expect("olcüm").len(),
        ilk_boyut,
        "ikinci kurulum dosyayi degistirmemeli"
    );

    // İçerik korunmuş olmalı.
    let yeniden = Oturum::ac(&yol, ANA_PAROLA).expect("acilmali");
    assert!(yeniden.bul("GitHub").is_ok());
}

#[test]
fn iki_kasa_ayri_tuz_ve_ayri_icerik_tutar() {
    let dizin = GeciciDizin::yeni("iki-kasa");
    let bir = dizin.birles("bir.kasa");
    let iki = dizin.birles("iki.kasa");

    let mut a = Oturum::olustur(&bir, ANA_PAROLA, HIZLI_ARON2).expect("olusturulmali");
    let mut b = Oturum::olustur(&iki, ANA_PAROLA, HIZLI_ARON2).expect("olusturulmali");
    a.ekle(&ornek_kayit("GitHub")).expect("eklenmeli");
    b.ekle(&ornek_kayit("GitLab")).expect("eklenmeli");
    a.kilit();
    b.kilit();

    assert_ne!(a.tuz(), b.tuz(), "iki kasa ayni tuzu kullanmamali");
    let ham_a = fs::read(&bir).expect("okunmali");
    let ham_b = fs::read(&iki).expect("okunmali");
    assert_ne!(
        ham_a, ham_b,
        "ayni kayitlar bile farkli sifre metni uretmeli"
    );

    let ac_a = Oturum::ac(&bir, ANA_PAROLA).expect("acilmali");
    assert!(ac_a.bul("GitHub").is_ok());
    assert!(ac_a.bul("GitLab").is_err());
}

#[test]
fn ana_parola_degisince_tum_kayitlar_yeniden_sifrelenir() {
    let dizin = GeciciDizin::yeni("ana-parola-degistirme");
    let yol = dizin.birles("kasa.kasa");
    let yeni_parola = "baska-bir-ana-parola-2026-ekstra";

    let mut oturum = Oturum::olustur(&yol, ANA_PAROLA, HIZLI_ARON2).expect("olusturulmali");
    for ad in ["bir", "iki", "uc"] {
        oturum.ekle(&ornek_kayit(ad)).expect("eklenmeli");
    }
    let eski_tuz = oturum.tuz();
    let eski_ham = fs::read(&yol).expect("okunmali");

    oturum
        .ana_parola_degistir(yeni_parola, HIZLI_ARON2)
        .expect("degistirilmeli");
    oturum.kilit();

    let yeni_ham = fs::read(&yol).expect("okunmali");
    assert_ne!(eski_ham, yeni_ham, "tum baytlar yeniden yazilmali");

    let yeni = Oturum::ac(&yol, yeni_parola).expect("yeni parola ile acilmali");
    assert_ne!(yeni.tuz(), eski_tuz, "degisiklikte yeni tuz uretilmeli");
    assert_eq!(yeni.kayit_sayisi(), 3);
    for ad in ["bir", "iki", "uc"] {
        let bulunan = yeni.bul(ad).expect("kayit kurtarilmali");
        assert_eq!(bulunan.parola, format!("{ad}-gizli-sir"));
    }

    // Eski parola artık calismamali.
    assert!(Oturum::ac(&yol, ANA_PAROLA).is_err());
}

#[test]
fn ana_parola_degisikligi_kayit_icerigini_bozmaz() {
    let dizin = GeciciDizin::yeni("parola-rotasyonu");
    let yol = dizin.birles("kasa.kasa");

    let ozel = Kayit {
        baslik: "Unicode 🔐 Başlık".to_string(),
        kullanici: "kullanıcı@örnek.com".to_string(),
        parola: "şifre-çğıöşü-😀-değer".to_string(),
        adres: "https://örnek.com/yol".to_string(),
        not: "çok\nsatırlı\nnot".to_string(),
    };
    let bekle = ozel.clone();

    let mut oturum = Oturum::olustur(&yol, ANA_PAROLA, HIZLI_ARON2).expect("olusturulmali");
    oturum.ekle(&ozel).expect("eklenmeli");
    oturum
        .ana_parola_degistir("yeni-ana-parola-2026-guclu", HIZLI_ARON2)
        .expect("degistirilmeli");
    oturum.kilit();

    let yeniden = Oturum::ac(&yol, "yeni-ana-parola-2026-guclu").expect("acilmali");
    let bulunan = yeniden
        .bul("Unicode 🔐 Başlık")
        .expect("unicode baslikla bulunmali");
    assert_eq!(bulunan, bekle);
}

#[test]
fn sifir_uzunlukta_parola_kaydedilir_ve_geri_okunur() {
    let dizin = GeciciDizin::yeni("bos-parola");
    let yol = dizin.birles("kasa.kasa");

    let kayit = Kayit {
        baslik: "sadece-uygulama".to_string(),
        kullanici: String::new(),
        parola: String::new(),
        adres: String::new(),
        not: String::new(),
    };

    let mut oturum = Oturum::olustur(&yol, ANA_PAROLA, HIZLI_ARON2).expect("olusturulmali");
    oturum.ekle(&kayit).expect("bos parola eklenmeli");
    oturum.kilit();

    let yeniden = Oturum::ac(&yol, ANA_PAROLA).expect("acilmali");
    let bulunan = yeniden.bul("sadece-uygulama").expect("bulunmali");
    assert_eq!(bulunan.parola, "");
    assert_eq!(bulunan.kullanici, "");
}

#[test]
fn uzun_unicode_not_alani_korunur() {
    let dizin = GeciciDizin::yeni("uzun-not");
    let yol = dizin.birles("kasa.kasa");

    let not: String = "çğıöşü".repeat(1000);
    let kayit = Kayit {
        baslik: "uzun-not".to_string(),
        kullanici: String::new(),
        parola: "gizli".to_string(),
        adres: String::new(),
        not: not.clone(),
    };
    let bekle = not;

    let mut oturum = Oturum::olustur(&yol, ANA_PAROLA, HIZLI_ARON2).expect("olusturulmali");
    oturum.ekle(&kayit).expect("eklenmeli");
    oturum.kilit();

    let yeniden = Oturum::ac(&yol, ANA_PAROLA).expect("acilmali");
    assert_eq!(yeniden.bul("uzun-not").expect("bulunmali").not, bekle);
}

#[test]
fn cok_uzun_baslik_reddedilir_ve_kasa_bozulmaz() {
    let dizin = GeciciDizin::yeni("uzun-baslik");
    let yol = dizin.birles("kasa.kasa");

    let mut oturum = Oturum::olustur(&yol, ANA_PAROLA, HIZLI_ARON2).expect("olusturulmali");
    oturum.ekle(&ornek_kayit("sağlam")).expect("eklenmeli");

    let cok_uzun = Kayit {
        baslik: "x".repeat(vaulta::kayit::EN_UZUN_BASLIK + 1),
        kullanici: String::new(),
        parola: String::new(),
        adres: String::new(),
        not: String::new(),
    };
    assert!(oturum.ekle(&cok_uzun).is_err());
    assert_eq!(oturum.kayit_sayisi(), 1);
    oturum.kilit();

    let yeniden = Oturum::ac(&yol, ANA_PAROLA).expect("kasa saglam kalmali");
    assert!(yeniden.bul("sağlam").is_ok());
}

#[test]
fn bos_baslik_reddedilir() {
    let dizin = GeciciDizin::yeni("bos-baslik");
    let yol = dizin.birles("kasa.kasa");

    let mut oturum = Oturum::olustur(&yol, ANA_PAROLA, HIZLI_ARON2).expect("olusturulmali");
    let bos = Kayit {
        baslik: "   ".to_string(),
        kullanici: "k".to_string(),
        parola: "p".to_string(),
        adres: String::new(),
        not: String::new(),
    };
    assert!(oturum.ekle(&bos).is_err());
}

#[test]
fn kaba_ana_parola_ile_kasa_olusturulmaz() {
    let dizin = GeciciDizin::yeni("kaba-parola");
    let yol = dizin.birles("kasa.kasa");

    let hata = Oturum::olustur(&yol, "123456", HIZLI_ARON2).expect_err("kaba parola reddedilmeli");
    assert!(matches!(hata, Hata::KabaParola { .. }));
    assert!(!yol.exists(), "kaba parolayla dosya olusmamali");
}

#[test]
fn kisa_oturum_anahtari_kilit_sonrasi_sifirlanir() {
    let dizin = GeciciDizin::yeni("kisa-oturum");
    let yol = dizin.birles("kasa.kasa");

    let mut oturum = Oturum::olustur(&yol, ANA_PAROLA, HIZLI_ARON2).expect("olusturulmali");
    oturum.ekle(&ornek_kayit("GitHub")).expect("eklenmeli");
    assert!(
        oturum.bellek_hazir_mi(),
        "acik oturumda anahtar bellekte olmali"
    );
    assert!(oturum.bul("GitHub").is_ok());

    oturum.kilit();

    assert!(
        !oturum.bellek_hazir_mi(),
        "kilit sonrasi bellek sifirlanmali"
    );
    assert!(
        oturum.listele().is_err(),
        "kilitli oturum islem kabul etmemeli"
    );
    assert!(oturum.bul("GitHub").is_err());
    assert!(oturum.ekle(&ornek_kayit("yeni")).is_err());
    assert!(oturum.sil("GitHub").is_err());
    assert!(oturum.kaydet().is_err());

    // Kilit idempotenttir.
    oturum.kilit();
    assert!(!oturum.bellek_hazir_mi());
}

#[test]
fn disa_aktarma_ve_geri_okuma_dogrulamasi() {
    let dizin = GeciciDizin::yeni("disa-aktarma");
    let yol = dizin.birles("kasa.kasa");
    let cikti = dizin.birles("export.json");

    let mut oturum = Oturum::olustur(&yol, ANA_PAROLA, HIZLI_ARON2).expect("olusturulmali");
    for ad in ["bir", "iki", "uc"] {
        oturum.ekle(&ornek_kayit(ad)).expect("eklenmeli");
    }

    let rapor = disa_aktar_ve_dogrula(&oturum, &cikti).expect("aktarilmali");
    assert!(rapor.basarili_mi(), "farklar: {:?}", rapor.farklar);
    assert_eq!(rapor.kayit_sayisi, 3);
    assert_eq!(rapor.alan_sayisi, 15, "3 kayit x 5 alan");
    assert_eq!(rapor.ozet.len(), 64, "sha256 hex 64 karakter");

    // Belge yeniden okunduğunda aynı içerik ve aynı özet çıkmalı.
    let belge = Aktarim::oku(&cikti).expect("okunmali");
    assert_eq!(belge.bicim, vaulta::KASA_SURUMU);
    assert_eq!(belge.kayitlar.len(), 3);
    assert_eq!(vaulta::aktarim::hex(&belge.ozet()), rapor.ozet);
    for (beklenen, gercek) in belge
        .kayitlar
        .iter()
        .zip((0..3).map(|i| oturum.sirayla_bul(i).expect("kayit")))
    {
        assert_eq!(beklenen, &gercek);
    }
}

#[test]
fn disa_aktarilan_belge_ic_aktarma_icin_gecerlidir() {
    let dizin = GeciciDizin::yeni("ice-aktarma");
    let yol = dizin.birles("kasa.kasa");
    let cikti = dizin.birles("export.json");

    let mut oturum = Oturum::olustur(&yol, ANA_PAROLA, HIZLI_ARON2).expect("olusturulmali");
    oturum.ekle(&ornek_kayit("kaynak")).expect("eklenmeli");
    disa_aktar_ve_dogrula(&oturum, &cikti).expect("aktarilmali");

    // Belge ikinci bir kasaya ice aktarilir ve alanlar korunur.
    let yeniden_yol = dizin.birles("hedef.kasa");
    let mut hedef = Oturum::olustur(&yeniden_yol, ANA_PAROLA, HIZLI_ARON2).expect("olusturulmali");
    let belge = Aktarim::oku(&cikti).expect("belge okunmali");
    for kayit in &belge.kayitlar {
        hedef.ekle(kayit).expect("ice aktarilmali");
    }
    hedef.kilit();

    let kontrol = Oturum::ac(&yeniden_yol, ANA_PAROLA).expect("acilmali");
    assert_eq!(
        kontrol.bul("kaynak").expect("bulunmali").parola,
        "kaynak-gizli-sir"
    );
}

#[test]
fn bozuk_aktarma_json_reddedilir() {
    let dizin = GeciciDizin::yeni("bozuk-json");
    let bozuk = dizin.yaz("bozuk.json", b"{ \"bicim\": 1, bu json degil");

    let hata = Aktarim::oku(&bozuk).expect_err("bozuk json reddedilmeli");
    assert!(matches!(hata, Hata::BozukAktarim(_)));
}

#[test]
fn bos_kasa_disa_aktarmasi_gecerli_belgedir() {
    let dizin = GeciciDizin::yeni("bos-aktarma");
    let yol = dizin.birles("kasa.kasa");
    let cikti = dizin.birles("export.json");

    let oturum = Oturum::olustur(&yol, ANA_PAROLA, HIZLI_ARON2).expect("olusturulmali");
    let rapor = disa_aktar_ve_dogrula(&oturum, &cikti).expect("aktarilmali");
    assert!(rapor.basarili_mi());
    assert_eq!(rapor.kayit_sayisi, 0);
    assert_eq!(rapor.alan_sayisi, 0);
}

#[test]
fn cok_kayitli_kasa_sayfalara_bolunur_ve_sirayla_geri_okunur() {
    let dizin = GeciciDizin::yeni("cok-kayit");
    let yol = dizin.birles("kasa.kasa");

    let mut oturum = Oturum::olustur(&yol, ANA_PAROLA, HIZLI_ARON2).expect("olusturulmali");
    for sira in 0..60 {
        oturum
            .ekle(&ornek_kayit(&format!("kayit-{sira:02}")))
            .expect("eklenmeli");
    }
    oturum.kilit();

    let yeniden = Oturum::ac(&yol, ANA_PAROLA).expect("acilmali");
    assert_eq!(yeniden.kayit_sayisi(), 60);
    for sira in 0..60 {
        let baslik = format!("kayit-{sira:02}");
        assert_eq!(
            yeniden.bul(&baslik).expect("bulunmali").parola,
            format!("{baslik}-gizli-sir")
        );
    }
}

#[test]
fn sayfa_boyutu_kayitlari_birden_fazla_sayfaya_dagitir() {
    let dizin = GeciciDizin::yeni("sayfa-dagilimi");
    let yol = dizin.birles("kasa.kasa");

    let mut oturum = Oturum::olustur(&yol, ANA_PAROLA, HIZLI_ARON2).expect("olusturulmali");
    for sira in 0..40 {
        oturum
            .ekle(&Kayit {
                baslik: format!("k-{sira:02}"),
                kullanici: String::new(),
                parola: "p".repeat(512),
                adres: String::new(),
                not: String::new(),
            })
            .expect("eklenmeli");
    }
    oturum.kilit();

    let yeniden = Oturum::ac(&yol, ANA_PAROLA).expect("acilmali");
    assert_eq!(yeniden.kayit_sayisi(), 40);
    // Her kayıt ≈ 583 bayt JSON + 20 bayt çerçeve başlığı ≈ 603 bayt.
    // 4096 / 603 = 6 kayıt/sayfa; 40 / 6 = 7 sayfa.
    assert_eq!(yeniden.baslik().sayfa_sayisi, 7);
    let liste = yeniden.listele().expect("liste");
    // Dizindeki konumlar tek sayfada kalmamali.
    let sayfalar: std::collections::BTreeSet<u32> = liste.iter().map(|k| k.sayfa).collect();
    assert_eq!(sayfalar.len(), 7);
}

#[test]
fn silme_sonrasi_bos_sayfalar_kaybolur() {
    let dizin = GeciciDizin::yeni("bos-sayfa");
    let yol = dizin.birles("kasa.kasa");

    let mut oturum = Oturum::olustur(&yol, ANA_PAROLA, HIZLI_ARON2).expect("olusturulmali");
    for sira in 0..40 {
        oturum
            .ekle(&Kayit {
                baslik: format!("k-{sira:02}"),
                kullanici: String::new(),
                parola: "p".repeat(512),
                adres: String::new(),
                not: String::new(),
            })
            .expect("eklenmeli");
    }
    let oncesi = oturum.baslik().sayfa_sayisi;
    for sira in 0..40 {
        oturum.sil(&format!("k-{sira:02}")).expect("silinmeli");
    }
    let sonrasi = oturum.baslik().sayfa_sayisi;
    oturum.kilit();

    assert_eq!(oncesi, 7);
    assert_eq!(sonrasi, 0, "tum sayfalar bosaldiginda silinmeli");
    // Boş kasa yalnızca başlık + boş dizin bloğundan ibarettir.
    assert!(fs::metadata(&yol).expect("olcüm").len() < 200);
}

#[test]
fn baslik_dosyadan_okunabilir_ve_okunur_kalir() {
    let dizin = GeciciDizin::yeni("baslik-okunabilir");
    let yol = dizin.birles("kasa.kasa");

    let ayar = Argon2Ayar {
        bellek_kib: 32_768,
        tur: 2,
        yol: 2,
    };
    let mut oturum = Oturum::olustur(&yol, ANA_PAROLA, ayar).expect("olusturulmali");
    oturum.kilit();

    let ham = fs::read(&yol).expect("okunmali");
    let baslik = vaulta::Baslik::oku(&ham[..vaulta::kasa::BASLIK_BOYUTU]).expect("baslik okunmali");
    assert_eq!(&ham[0..4], b"KASA");
    assert_eq!(baslik.m_cost, 32_768);
    assert_eq!(baslik.t_cost, 2);
    assert_eq!(baslik.p_cost, 2);
    assert_eq!(baslik.kayit_sayisi, 0);
    assert_eq!(baslik.tuz.len(), 16);
    // Tuz dosyada duz metin; gizli olan kayit icerigidir.
    assert!(ham[29..45].iter().any(|b| *b != 0));
}
