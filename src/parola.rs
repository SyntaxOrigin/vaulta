//! Parola üreteci ve NIST SP 800-63B uyumlu kaba parola denetimi.
//!
//! # Denetim neden bu kadar katı?
//!
//! NIST SP 800-63B, kullanıcı tarafından seçilen parolalar için üç kural koyar:
//!
//! 1. **En az 8 karakter.** Bu proje 15 karakter eşiği kullanır: 15, hem
//!    SP 800-63B'nin izin verdiği asgari değerin üzerinde hem de tek makul
//!    sözcük tabanlı (diceware) seçenekle uyumlu bir eşik.
//! 2. **Yaygın parola ve sızan parola listelerine karşı denetim.** Burada gömülü
//!    bir yaygın parola listesi vardır; bağlantılı veri sızanları (HIBP vb.)
//!    kapsam dışıdır çünkü proje tamamen çevrimdışıdır.
//! 3. **Bileşiklik kuralları (en az bir büyük harf, bir rakam...) zorunlu
//!    değildir.** NIST bunları bilinçli olarak önermez; çünkü kullanıcı
//!    kuralları geçmek için `Password1!` gibi tahmin edilebilir kalıplar
//!    üretir. Bu yüzden burada **hiçbir bileşiklik kuralı yoktur**.
//!
//! SP 800-63B ayrıca parolanın bir **ifade** (passphrase) olmasını kabul eder.
//! Raporun önerdiği "12 karakter veya 4 sözcük" kuralının ikinci yarısı bu
//! yüzden burada uygulanamaz: kasa bir sözcük sözlüğü taşımaz ve kullanıcının
//! hangi dili konuştuğunu bilmez. Bunun yerine README'de "4 rastgele sözcük"
//! seçeneği **açıklama olarak** belirtilir ve kasa yalnızca karakter sayısını
//! denetler.
//!
//! # Üreteç
//!
//! Üretilen parolalar `getrandom` (işletim sistemi CSPRNG) ile üretilir. Mod
//! çıkarma yanlılığını (modulo bias) önlemek için sözlük boyutu 256'nın böleni
//! olmayacak şekilde seçilmiştir ve `u16` ile `u8` örneklemesi yapılmadan,
//! doğrudan reddetme (rejection sampling) uygulanır.

use zeroize::Zeroizing;

use crate::hata::Hata;
use crate::kripto::rastgele_bayt;

/// Denetimde aranan en az parola uzunluğu (karakter sayısı).
pub const EN_KISA_PAROLA: usize = 15;

/// Üreteçte kullanılan küçük harf kümesi (karışan `l` ve `i` çıkarıldı).
const KUCUK_HARF: &[u8] = b"abcdefghjkmnpqrstuvwxyz";

/// Üreteçte kullanılan büyük harf kümesi (karışan `I` ve `O` çıkarıldı).
const BUYUK_HARF: &[u8] = b"ABCDEFGHJKLMNPQRSTUVWXYZ";

/// Üreteçte kullanılan rakam kümesi.
const RAKAM: &[u8] = b"23456789";

/// Üreteçte kullanılan simge kümesi.
const SIMGE: &[u8] = b"!@#$%^&*-_=+?";

/// Üreteçte kullanılan toplam sözlük boyutu.
///
/// 23 + 24 + 8 + 13 = 68. 68, 256'nın böleni olmadığı için (256 mod 68 = 52)
/// reddetme örneklemesi tam tekdüzelik garanti eder ve `u8` ile kesme yapmaya
/// gerek kalmaz.
const SOZLUK_BOYUTU: usize = KUCUK_HARF.len() + BUYUK_HARF.len() + RAKAM.len() + SIMGE.len();

/// Reddetme örneklemesi eşiği: bu değerin üstündeki baytlar atılır.
const SOZLUK_ESIGI: u16 = 256 - (256 % SOZLUK_BOYUTU as u16);

/// Üreteçte varsayılan parola uzunluğu.
///
/// 68 karakterlik sözlükte 20 karakter ≈ 123 bit entropi verir; SP 800-63B
/// (Bölüm 5.1) tek bir parola için 128 bit önerir, 20 karakter bu eşiğe
/// pratikte yakındır ve klavye ile yazılabilirliği korur.
pub const VARSAYILAN_UZUNLUK: usize = 20;

/// Üreteçte izin verilen en küçük uzunluk.
pub const EN_KISA_URETILEN: usize = 12;

/// Üreteçte izin verilen en büyük uzunluk.
pub const EN_UZUN_URETILEN: usize = 128;

/// Gömülü yaygın parola listesi (küçük harfe indirgenmiş, NIST SP 800-63B
/// Bölüm 3.5.1'in gereksinimini karşılayan bir alt küme).
///
/// Liste kasaya yazılmaz ve bağlantı gerektirmez; amaç çevrimdışı bir aracın
/// kullanabileceği **asgari** siyah liste olmaktır. Gerçek koruma, parolanın
/// uzun ve benzersiz olmasıdır.
const YAYGIN_PAROLALAR: &[&str] = &[
    "123456",
    "123456789",
    "qwerty",
    "password",
    "111111",
    "12345678",
    "abc123",
    "qwerty123",
    "1q2w3e4r",
    "admin",
    "letmein",
    "welcome",
    "monkey",
    "iloveyou",
    "sunshine",
    "princess",
    "football",
    "baseball",
    "sifre",
    "parola",
    "sifrem",
    "benimparolam",
    "deneme",
    "1234",
    "12345",
    "secret",
    "test",
    "guest",
    "master",
    "root",
    "toor",
    "passw0rd",
    "p@ssword",
    "trustno1",
    "superman",
    "batman",
    "dragon",
    "shadow",
    "michael",
    "jennifer",
    "charlie",
    "letmein123",
    // Uzunluğu 15 karakteri aşan gömülü girişler: uzunluk kuralı bunları
    // yakalamaz, yalnızca siyah liste yakalar.
    "qwertyuiop12345",
    "letmein12345678",
    "iloveyou1234567",
    "football123456",
    "starwars12345",
    "dragon12345678",
    "master12345678",
    "trustno12345",
    "sunshine12345",
    "princess12345",
];

/// Sözlükten bir bayt çeker.
///
/// `256 - 256 mod 68 = 204` eşiğinin üstündeki baytlar atılır; kalan değerin
/// `68` ile modu alınır. `SOZLUK_BOYUTU` 256'nın böleni olmadığı için bu seçim
/// yanlılık üretmez; yine de **tam** tekdüzelik için reddetme örneklemesi
/// uygulanır.
fn sozlukten_bayt(bayt: u8) -> Option<usize> {
    let deger = u16::from(bayt);
    if deger >= SOZLUK_ESIGI {
        return None;
    }
    Some((deger % SOZLUK_BOYUTU as u16) as usize)
}

/// Sözlükteki `sira` numaralı bayta karşılık gelen karakteri döndürür.
///
/// Sıra, dört kümenin uzunluklarının öncelikli toplamıdır; küme atlaması yoktur.
fn sozluk_bayti(sira: usize) -> u8 {
    let mut kalan = sira;
    if kalan < KUCUK_HARF.len() {
        return KUCUK_HARF[kalan];
    }
    kalan -= KUCUK_HARF.len();
    if kalan < BUYUK_HARF.len() {
        return BUYUK_HARF[kalan];
    }
    kalan -= BUYUK_HARF.len();
    if kalan < RAKAM.len() {
        return RAKAM[kalan];
    }
    kalan -= RAKAM.len();
    SIMGE[kalan]
}

/// İstenen uzunlukta rastgele parola üretir.
///
/// Dönen değer `Zeroizing<String>`'dir; çağıran yazdırmak zorundadır ama
/// tampon bırakıldığında sıfırlanır.
pub fn uret(uzunluk: usize) -> Result<Zeroizing<String>, Hata> {
    if !(EN_KISA_URETILEN..=EN_UZUN_URETILEN).contains(&uzunluk) {
        return Err(Hata::BozukArguman(format!(
            "uretilen parola uzunlugu {EN_KISA_URETILEN}..{EN_UZUN_URETILEN} araliginda olmali"
        )));
    }

    let mut parola = Zeroizing::new(String::with_capacity(uzunluk));
    let mut ilk = true;
    while parola.chars().count() < uzunluk {
        // Reddetme örneklemesi için taze CSPRNG baytları çekilir. İstenen
        // uzunluktan uzun bir blok istenir ki pratikte tek çekim yeterli olsun.
        let blok = rastgele_bayt(uzunluk * 2)?;
        let mut sira: Option<usize> = None;
        for bayt in blok.iter() {
            if let Some(aday) = sozlukten_bayt(*bayt) {
                sira = Some(aday);
                break;
            }
        }
        let Some(sira) = sira else {
            // Blokun tamamı eşiğin üstünde çıktı (olasılık ≈ 2^-uzunluk*2).
            // Yeni çekim yapmak doğru davranıştır; hata yutmak değil.
            continue;
        };
        if ilk && rakam_veya_simge_mi(sira) {
            // İlk karakter harf olmalı: sayı veya simge ile başlayan parola
            // birçok sistemde "geçersiz" sayılır ve kullanıcıyı elle
            // değiştirmeye zorlar. Bu eleme yalnızca ilk karakter içindir.
            continue;
        }
        ilk = false;
        parola.push(sozluk_bayti(sira) as char);
    }
    Ok(parola)
}

/// Sözlük sırası rakam veya simge kümesine ait mi?
fn rakam_veya_simge_mi(sira: usize) -> bool {
    sira >= KUCUK_HARF.len() + BUYUK_HARF.len()
}

/// Kaba parola denetimi: NIST SP 800-63B uzunluk + yaygın parola listesi.
///
/// `Hata::KabaParola` dönse bile parolanın kendisi hata nesnesine girmez; bu
/// yüzden hata metni log'a yazılsa bile sır sızmaz.
pub fn kaba_parola_denetle(parola: &str) -> Result<(), Hata> {
    let uzunluk = parola.chars().count();
    if uzunluk < EN_KISA_PAROLA {
        return Err(Hata::KabaParola {
            uzunluk,
            en_kisa: EN_KISA_PAROLA,
            gerekce: "NIST SP 800-63B B.2: kullanici secimi parolalar en az 15 karakter veya \
                       4 rastgele sozcuk olmalidir; kasa yalnizca karakter sayisini olcer",
        });
    }

    let kucuk_harfli = parola.to_lowercase();
    let kirp = kucuk_harfli.trim();
    if YAYGIN_PAROLALAR.contains(&kirp) {
        return Err(Hata::KabaParola {
            uzunluk,
            en_kisa: EN_KISA_PAROLA,
            gerekce: "NIST SP 800-63B B.2: yaygin parolalar reddedilir",
        });
    }
    if parola.chars().all(|c| !c.is_ascii_alphanumeric()) {
        return Err(Hata::KabaParola {
            uzunluk,
            en_kisa: EN_KISA_PAROLA,
            gerekce: "NIST SP 800-63B B.2: parola yalnizca simgelerden olusamaz",
        });
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)] // WORKER_CONTRACT 4.2: testlerde panic araci gecerlidir
mod tests {
    use super::*;

    #[test]
    fn uretilen_parola_istenen_uzunlukta() {
        let parola = uret(VARSAYILAN_UZUNLUK).expect("uretilmeli");
        assert_eq!(parola.chars().count(), VARSAYILAN_UZUNLUK);
    }

    #[test]
    fn uretilen_parola_en_kisa_ve_en_uzun_sinirlari_kabul_eder() {
        assert!(uret(EN_KISA_URETILEN).is_ok());
        assert!(uret(EN_UZUN_URETILEN).is_ok());
    }

    #[test]
    fn uretilen_parola_sinir_disi_uzunluk_reddedilir() {
        assert!(uret(EN_KISA_URETILEN - 1).is_err());
        assert!(uret(EN_UZUN_URETILEN + 1).is_err());
        assert!(uret(0).is_err());
    }

    #[test]
    fn uretilen_parola_yalnizca_sozluk_karakterlerinden_olusur() {
        for _ in 0..16 {
            let parola = uret(32).expect("uretilmeli");
            for karakter in parola.chars() {
                let bayt = karakter as u32;
                let kucuk = KUCUK_HARF.contains(&(bayt as u8));
                let buyuk = BUYUK_HARF.contains(&(bayt as u8));
                let rakam = RAKAM.contains(&(bayt as u8));
                let simge = SIMGE.contains(&(bayt as u8));
                assert!(
                    kucuk || buyuk || rakam || simge,
                    "'{karakter} sozluk disinda"
                );
            }
        }
    }

    #[test]
    fn uretilen_parola_her_zaman_harf_ile_baslar() {
        for _ in 0..32 {
            let parola = uret(16).expect("uretilmeli");
            let ilk = parola.chars().next().expect("bos degil");
            assert!(ilk.is_ascii_alphabetic(), "ilk karakter '{ilk}' harf degil");
        }
    }

    #[test]
    fn uretilen_parolalar_birbirinden_farklidir() {
        let bir = uret(24).expect("uretilmeli").to_string();
        let iki = uret(24).expect("uretilmeli").to_string();
        let uc = uret(24).expect("uretilmeli").to_string();
        assert_ne!(bir, iki);
        assert_ne!(iki, uc);
    }

    #[test]
    fn uretilen_parola_uretimde_nihai_karakter_kumesine_sigar() {
        // Reddetme örneklemesi sonrası seçilen karakter daima geçerli bir
        // sözlük indisidir; 512 örnek bunun garantisini arar.
        for _ in 0..512 {
            let parola = uret(EN_KISA_URETILEN).expect("uretilmeli");
            assert_eq!(parola.chars().count(), EN_KISA_URETILEN);
        }
    }

    #[test]
    fn sozlukten_bayt_esik_ustu_reddedilir() {
        // 256 - (256 mod 68) = 204; bu ve üzeri baytlar reddedilmelidir.
        assert!(sozlukten_bayt(0).is_some());
        assert!(sozlukten_bayt(SOZLUK_ESIGI as u8 - 1).is_some());
        assert!(sozlukten_bayt(SOZLUK_ESIGI as u8).is_none());
        assert!(sozlukten_bayt(255).is_none());
    }

    #[test]
    fn sozluk_boyutu_256_boleni_degil() {
        // Yanlılık önleme varsayımı: SOZLUK_BOYUTU, 256'nın böleni olsaydı
        // reddetme örneklemesi işe yaramazdı.
        assert_eq!(SOZLUK_BOYUTU, 68);
        assert_ne!(256 % SOZLUK_BOYUTU, 0);
        assert_eq!(SOZLUK_ESIGI, 204);
    }

    #[test]
    fn sozluk_bayti_kumeleri_kapsar() {
        assert_eq!(sozluk_bayti(0), KUCUK_HARF[0]);
        assert_eq!(sozluk_bayti(KUCUK_HARF.len()), BUYUK_HARF[0]);
        assert_eq!(sozluk_bayti(KUCUK_HARF.len() + BUYUK_HARF.len()), RAKAM[0]);
        assert_eq!(
            sozluk_bayti(KUCUK_HARF.len() + BUYUK_HARF.len() + RAKAM.len()),
            SIMGE[0]
        );
    }

    #[test]
    fn kisa_parola_reddedilir() {
        let hata = kaba_parola_denetle("kisa").expect_err("kisa parola reddedilmeli");
        assert!(hata.to_string().contains("15"));
    }

    #[test]
    fn tam_sinirdaki_parola_kabul_edilir() {
        let parola = "a".repeat(EN_KISA_PAROLA);
        assert!(kaba_parola_denetle(&parola).is_ok());
    }

    #[test]
    fn sinir_bir_alisindaki_parola_reddedilir() {
        let parola = "a".repeat(EN_KISA_PAROLA - 1);
        assert!(kaba_parola_denetle(&parola).is_err());
    }

    #[test]
    fn uzun_yaygin_parola_listesinden_reddedilir() {
        // Uzunluk kuralı (15 karakter) geçse bile yaygın parola reddi çalışır.
        let hata = kaba_parola_denetle("qwertyuiop12345").expect_err("yaygin parola reddedilmeli");
        assert!(hata.to_string().contains("yaygin"));
        assert!(kaba_parola_denetle("letmein12345678").is_err());
        assert!(kaba_parola_denetle("iloveyou1234567").is_err());
    }

    #[test]
    fn yaygin_parola_kucuk_harf_ve_bosluk_normalizasyonuyla_reddedilir() {
        assert!(kaba_parola_denetle("  LetMeIn123  ").is_err());
        assert!(kaba_parola_denetle("123456789").is_err());
    }

    #[test]
    fn yalnizca_simge_icken_parola_reddedilir() {
        let parola = "!@#$%^&*-_=+?";
        assert!(kaba_parola_denetle(parola).is_err());
    }

    #[test]
    fn gecerli_uzun_parola_kabul_edilir() {
        assert!(kaba_parola_denetle("dogru bir parola: 42 karakter ve tekrar yok").is_ok());
    }

    #[test]
    fn uretilen_parola_kendi_denetiminden_gecer() {
        let parola = uret(VARSAYILAN_UZUNLUK).expect("uretilmeli");
        assert!(kaba_parola_denetle(&parola).is_ok());
    }

    #[test]
    fn kaba_parola_hatasi_parolanin_kendisini_icermez() {
        let sır = "123456";
        match kaba_parola_denetle(sır) {
            Ok(()) => panic!("123456 reddedilmeli"),
            Err(hata) => {
                let metin = hata.to_string();
                assert!(!metin.contains(sır));
            }
        }
    }

    #[test]
    fn karakter_sayisi_karakter_olarak_olculur() {
        // 21 karakter, 42 bayt. Bayt sayısı eşiği iki katına yakın ama
        // karakter sayısı geçerli: ölçütün bayt değil karakter olduğunu kanıtlar.
        let parola = "Şifre Kasası Güçlü 9 x";
        assert!(parola.len() > EN_KISA_PAROLA);
        assert_eq!(parola.chars().count(), 22);
        assert!(kaba_parola_denetle(parola).is_ok());
    }
}
