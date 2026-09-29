//! `vaulta` komut satırı arayüzü.
//!
//! Bu dosya yalnızca çekirdeği sarar: argüman ayrıştırma, parola okuma, çıktı
//! biçimlendirme ve hata kodu. Kriptografik mantığın tamamı `vaulta`
//! kütüphanesinde (`src/lib.rs`) yazar ve orada test edilir.
//!
//! # Sır girişi
//!
//! Ana parola **asla** komut satırı argümanı olarak kabul edilmez; orada kabuk
//! geçmişinde ve işlem listesinde görünür. İki kanal vardır:
//!
//! 1. `--ana-parola-stdin`: stdin'in ilk satırı.
//! 2. `VAULTA_ANA_PAROLA` ortam değişkeni (betikler için).
//!
//! Kaydedilecek kayıt parolası için `--parola <deger>` (konfor) veya
//! `--parola-stdin` (güvenli) seçenekleri vardır.
//!
//! # Çıkış kodu
//!
//! | Kod | Anlam |
//! |---|---|
//! | 0 | başarılı |
//! | 1 | hata (hata metni stderr'e yazılır) |
//! | 2 | kullanım hatası (`clap`) |

#![forbid(unsafe_code)]

use std::env;
use std::io::{self, Read, Write};
use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use serde::Serialize;
use zeroize::Zeroizing;

use vaulta::aktarim::disa_aktar_ve_dogrula;
use vaulta::hata::Hata;
use vaulta::kayit::Kayit;
use vaulta::kripto::Argon2Ayar;
use vaulta::parola::{self, VARSAYILAN_UZUNLUK};
use vaulta::Oturum;

/// Ana parolanın ortam değişkeninde aranacağı ad.
const ANA_PAROLA_DEGISKENI: &str = "VAULTA_ANA_PAROLA";

/// `vaulta` — tamamen çevrimdışı, tek dosya parola kasası.
#[derive(Debug, Parser)]
#[command(
    name = "vaulta",
    version,
    about = "Argon2id ve XChaCha20-Poly1305 ile sifreli, tek dosya, cevrimdisi parola kasasi.",
    long_about = None,
    disable_help_subcommand = true
)]
struct KomutSatiri {
    #[command(subcommand)]
    alt_komut: AltKomut,
}

#[derive(Debug, Subcommand)]
enum AltKomut {
    /// Yeni bir kasa dosyasi olusturur.
    #[command(name = "init")]
    Init {
        /// Olusturulacak kasa dosyasi.
        #[arg(value_name = "KASA")]
        kasa: PathBuf,
        /// Ana parola stdin'in ilk satirindadir.
        #[arg(long)]
        ana_parola_stdin: bool,
        /// Test/deneme icin Argon2id maliyeti 16 MiB / 1 tur / 1 yola iner.
        ///
        /// Gercek bir kasa icin kullanmayin: kaba kuvvet direncini 64 kat azaltir.
        #[arg(long)]
        hizli: bool,
    },
    /// Kasaya yeni bir kayit ekler.
    #[command(name = "add")]
    Ekle {
        /// Kasa dosyasi.
        #[arg(value_name = "KASA")]
        kasa: PathBuf,
        /// Ana parola stdin'in ilk satirindadir.
        #[arg(long)]
        ana_parola_stdin: bool,
        /// Kaydin basligi (kasada benzersiz olmali).
        #[arg(long, value_name = "METIN")]
        baslik: String,
        /// Kaydin siri. Bos birakilabilir.
        #[arg(long, value_name = "METIN", default_value = "")]
        parola: String,
        /// Kayit siri stdin'in sonraki satirindadir.
        #[arg(long, conflicts_with = "parola")]
        parola_stdin: bool,
        /// Istege bagli kullanici adi veya e-posta.
        #[arg(long, value_name = "METIN", default_value = "")]
        kullanici: String,
        /// Istege bagli adres / URL.
        #[arg(long, value_name = "METIN", default_value = "")]
        adres: String,
        /// Istege bagli serbest metin not.
        #[arg(long, value_name = "METIN", default_value = "")]
        not: String,
    },
    /// Kasadaki kayitlari listeler (parolalar cozulmez).
    #[command(name = "list")]
    Liste {
        /// Kasa dosyasi.
        #[arg(value_name = "KASA")]
        kasa: PathBuf,
        /// Ana parola stdin'in ilk satirindadir.
        #[arg(long)]
        ana_parola_stdin: bool,
        /// Makine-okunur JSON yazar.
        #[arg(long)]
        json: bool,
    },
    /// Tek bir kaydi gosterir; parola varsayilan olarak maskelenir.
    #[command(name = "get")]
    Get {
        /// Kasa dosyasi.
        #[arg(value_name = "KASA")]
        kasa: PathBuf,
        /// Ana parola stdin'in ilk satirindadir.
        #[arg(long)]
        ana_parola_stdin: bool,
        /// Aranacak baslik.
        #[arg(long, value_name = "METIN")]
        baslik: String,
        /// Parolayi duz metin olarak gosterir.
        #[arg(long)]
        goster_sir: bool,
    },
    /// Basliga gore kaydi siler.
    #[command(name = "remove")]
    Sil {
        /// Kasa dosyasi.
        #[arg(value_name = "KASA")]
        kasa: PathBuf,
        /// Ana parola stdin'in ilk satirindadir.
        #[arg(long)]
        ana_parola_stdin: bool,
        /// Silinecek kaydin basligi.
        #[arg(long, value_name = "METIN")]
        baslik: String,
    },
    /// Ana parolayi degistirir ve tum kayitlari yeniden seifreler.
    #[command(name = "change-master")]
    ChangeMaster {
        /// Kasa dosyasi.
        #[arg(value_name = "KASA")]
        kasa: PathBuf,
        /// Eski ana parola stdin'in ilk satirindadir.
        #[arg(long)]
        ana_parola_stdin: bool,
        /// Yeni ana parola stdin'in ikinci satirindadir (zorunlu).
        #[arg(long, required = true)]
        yeni_parola_stdin: bool,
        /// Yeni Argon2id maliyeti 16 MiB / 1 tur / 1 yola iner.
        #[arg(long)]
        hizli: bool,
    },
    /// Tum kayitlari JSON olarak disa aktarir ve **hemen geri okuyarak dogrular**.
    #[command(name = "export-verified")]
    ExportVerified {
        /// Kasa dosyasi.
        #[arg(value_name = "KASA")]
        kasa: PathBuf,
        /// Ana parola stdin'in ilk satirindadir.
        #[arg(long)]
        ana_parola_stdin: bool,
        /// Yazilacak JSON dosyasi.
        #[arg(long, value_name = "DOSYA")]
        cikti: PathBuf,
    },
    /// Kasa basligini okur; ana parola **gerekmez**.
    ///
    /// Baslik duz metindir: algoritma kimligi, Argon2id maliyet parametreleri,
    /// tuz ve sayfalar bu komutla disaridan dogrulanabilir.
    #[command(name = "info")]
    Info {
        /// Kasa dosyasi.
        #[arg(value_name = "KASA")]
        kasa: PathBuf,
    },
    /// Isletim sistemi rastgeleliginden parola uretir.
    #[command(name = "uret")]
    Uret {
        /// Uretilen parolanin uzunlugu (varsayilan 20).
        #[arg(long, value_name = "SAYI", default_value_t = VARSAYILAN_UZUNLUK)]
        uzunluk: usize,
    },
    /// Parolayi NIST SP 800-63B kurallarina gore dener; sifri ekrana basmaz.
    #[command(name = "denetle")]
    Denetle {
        /// Denenecek parola stdin'in ilk satirindadir.
        #[arg(long)]
        parola_stdin: bool,
    },
}

/// `liste --json` çıktısının şeması.
#[derive(Debug, Serialize)]
struct ListeCiktisi {
    /// Baslikta okunan surum.
    surum: u32,
    /// Argon2id bellek maliyeti (KiB).
    argon2_bellek_kib: u32,
    /// Kayit sayisi.
    kayit_sayisi: usize,
    /// Kayit ozetleri (parola icermez).
    kayitlar: Vec<KayitOzeti>,
}

/// `liste --json` icindeki tek kayit ozeti.
#[derive(Debug, Serialize)]
struct KayitOzeti {
    /// Baslik.
    baslik: String,
    /// Kullanici adi.
    kullanici: String,
    /// Bulundugu sayfa.
    sayfa: u32,
    /// Sayfa icindeki cerceve sirasi.
    cerceve: u32,
}

/// Gizli girdi kanalı: ana parola ve istege bagli ikinci satır.
struct GizliGirdi {
    satirlar: Vec<Zeroizing<String>>,
    sira: usize,
}

impl GizliGirdi {
    /// Ana parolayı istenen kanaldan okur ve kalan satırları saklar.
    fn ac(stdin_isteniyor: bool) -> Result<GizliGirdi, Hata> {
        let metin = if stdin_isteniyor {
            let mut tampon = Zeroizing::new(String::new());
            io::stdin().lock().read_to_string(&mut tampon)?;
            tampon.to_string()
        } else {
            env::var(ANA_PAROLA_DEGISKENI).map_err(|_| {
                Hata::BozukArguman(format!(
                    "ana parola okunamadi: --ana-parola-stdin kullanin ya da {ANA_PAROLA_DEGISKENI} ayarlayin"
                ))
            })?
        };
        let satirlar = metin
            .split('\n')
            .map(|satir| Zeroizing::new(satir.trim_end_matches('\r').to_string()))
            .collect();
        Ok(GizliGirdi { satirlar, sira: 0 })
    }

    /// Sıradaki satırı döndürür; kalmadıysa boş dize döner.
    fn sonraki(&mut self) -> Zeroizing<String> {
        let satir = self.satirlar.get(self.sira).cloned();
        self.sira += 1;
        satir.unwrap_or_else(|| Zeroizing::new(String::new()))
    }
}

/// Argon2id ayarını seçer.
fn ayar_sec(hizli: bool) -> Argon2Ayar {
    if hizli {
        Argon2Ayar::HIZLI
    } else {
        Argon2Ayar::VARSAYILAN
    }
}

fn main() -> ExitCode {
    let komut = KomutSatiri::parse();
    match calistir(komut) {
        Ok(()) => ExitCode::SUCCESS,
        Err(hata) => {
            let _ = writeln!(io::stderr(), "hata: {hata}");
            ExitCode::FAILURE
        }
    }
}

/// Komutu çalıştırır ve yalnızca `Hata` döndürür.
fn calistir(komut: KomutSatiri) -> Result<(), Hata> {
    match komut.alt_komut {
        AltKomut::Init {
            kasa,
            ana_parola_stdin,
            hizli,
        } => {
            let mut girdi = GizliGirdi::ac(ana_parola_stdin)?;
            let parola = girdi.sonraki();
            let ayar = ayar_sec(hizli);
            let oturum = Oturum::olustur(&kasa, &parola, ayar)?;
            println!(
                "kasa olusturuldu: {}\n  argon2id: {} KiB / {} tur / {} yol\n  sayfa boyutu: {} bayt",
                kasa.display(),
                ayar.bellek_kib,
                ayar.tur,
                ayar.yol,
                oturum.baslik().sayfa_boyutu
            );
            Ok(())
        }
        AltKomut::Ekle {
            kasa,
            ana_parola_stdin,
            baslik,
            parola,
            parola_stdin,
            kullanici,
            adres,
            not,
        } => {
            let mut girdi = GizliGirdi::ac(ana_parola_stdin)?;
            let ana_parola = girdi.sonraki();
            let kayit_parola: Zeroizing<String> = if parola_stdin {
                girdi.sonraki()
            } else {
                Zeroizing::new(parola)
            };
            let mut oturum = Oturum::ac(&kasa, &ana_parola)?;
            let kayit = Kayit {
                baslik,
                kullanici,
                parola: kayit_parola.to_string(),
                adres,
                not,
            };
            oturum.ekle(&kayit)?;
            let sayi = oturum.kayit_sayisi();
            oturum.kilit();
            println!(
                "kayit eklendi: {} (kasa: {}, kayit sayisi: {sayi})",
                kayit.baslik.trim(),
                kasa.display()
            );
            Ok(())
        }
        AltKomut::Liste {
            kasa,
            ana_parola_stdin,
            json,
        } => {
            let mut girdi = GizliGirdi::ac(ana_parola_stdin)?;
            let ana_parola = girdi.sonraki();
            let oturum = Oturum::ac(&kasa, &ana_parola)?;
            let dizin = oturum.listele()?;
            if json {
                let cikti = ListeCiktisi {
                    surum: vaulta::KASA_SURUMU,
                    argon2_bellek_kib: oturum.baslik().m_cost,
                    kayit_sayisi: dizin.len(),
                    kayitlar: dizin
                        .iter()
                        .map(|k| KayitOzeti {
                            baslik: k.baslik.clone(),
                            kullanici: k.kullanici.clone(),
                            sayfa: k.sayfa,
                            cerceve: k.cerceve,
                        })
                        .collect(),
                };
                println!(
                    "{}",
                    serde_json::to_string_pretty(&cikti)
                        .map_err(|hata| Hata::BozukArguman(hata.to_string()))?
                );
            } else if dizin.is_empty() {
                println!("kasa bos: kayit yok");
            } else {
                println!(
                    "{:<3} {:<24} {:<24} {:>5} {:>8}",
                    "NO", "BASLIK", "KULLANICI", "SAYFA", "CERCEVE"
                );
                for (sira, kayit) in dizin.iter().enumerate() {
                    println!(
                        "{:<3} {:<24} {:<24} {:>5} {:>8}",
                        sira + 1,
                        kisalt(&kayit.baslik, 24),
                        kisalt(&kayit.kullanici, 24),
                        kayit.sayfa,
                        kayit.cerceve
                    );
                }
                println!("\n{} kayit.", dizin.len());
            }
            Ok(())
        }
        AltKomut::Get {
            kasa,
            ana_parola_stdin,
            baslik,
            goster_sir,
        } => {
            let mut girdi = GizliGirdi::ac(ana_parola_stdin)?;
            let ana_parola = girdi.sonraki();
            let oturum = Oturum::ac(&kasa, &ana_parola)?;
            let kayit = oturum.bul(&baslik)?;
            println!("baslik   : {}", kayit.baslik);
            println!("kullanici: {}", kayit.kullanici);
            println!("adres    : {}", kayit.adres);
            println!(
                "parola   : {}",
                if goster_sir {
                    kayit.parola.clone()
                } else {
                    "*".repeat(kayit.parola.chars().count().min(16))
                }
            );
            if !kayit.not.is_empty() {
                println!("not      : {}", kayit.not);
            }
            if !goster_sir {
                println!("\n(parolayi duz metin gormek icin --goster-sir kullanin)");
            }
            Ok(())
        }
        AltKomut::Sil {
            kasa,
            ana_parola_stdin,
            baslik,
        } => {
            let mut girdi = GizliGirdi::ac(ana_parola_stdin)?;
            let ana_parola = girdi.sonraki();
            let mut oturum = Oturum::ac(&kasa, &ana_parola)?;
            oturum.sil(&baslik)?;
            oturum.kilit();
            println!("kayit silindi: {}", baslik.trim());
            Ok(())
        }
        AltKomut::ChangeMaster {
            kasa,
            ana_parola_stdin,
            yeni_parola_stdin,
            hizli,
        } => {
            let mut girdi = GizliGirdi::ac(ana_parola_stdin)?;
            let eski = girdi.sonraki();
            let yeni = girdi.sonraki();
            let _ = yeni_parola_stdin;
            let mut oturum = Oturum::ac(&kasa, &eski)?;
            oturum.ana_parola_degistir(&yeni, ayar_sec(hizli))?;
            let sayi = oturum.kayit_sayisi();
            oturum.kilit();
            println!("ana parola degistirildi ve {sayi} kayit yeniden seifreldi");
            Ok(())
        }
        AltKomut::ExportVerified {
            kasa,
            ana_parola_stdin,
            cikti,
        } => {
            let mut girdi = GizliGirdi::ac(ana_parola_stdin)?;
            let ana_parola = girdi.sonraki();
            let oturum = Oturum::ac(&kasa, &ana_parola)?;
            let rapor = disa_aktar_ve_dogrula(&oturum, &cikti)?;
            println!("disa aktarildi : {}", cikti.display());
            println!("kayit sayisi   : {}", rapor.kayit_sayisi);
            println!("karsilastirilan: {} alan", rapor.alan_sayisi);
            println!("icerik ozeti   : sha256:{}", rapor.ozet);
            if rapor.basarili_mi() {
                println!("dogrulama      : GECTI (yazilan dosya yeniden okundu, tum alanlar esit)");
                Ok(())
            } else {
                for fark in &rapor.farklar {
                    let _ = writeln!(io::stderr(), "uyari: {fark}");
                }
                Err(Hata::BozukAktarim(format!(
                    "{} alan farkli; disa aktarim dogrulanmadi",
                    rapor.farklar.len()
                )))
            }
        }
        AltKomut::Info { kasa } => {
            let ham = std::fs::read(&kasa)?;
            let baslik = vaulta::Baslik::oku(&ham[..ham.len().min(vaulta::kasa::BASLIK_BOYUTU)])?;
            println!("dosya      : {}", kasa.display());
            println!("bicim      : KASA surum {}", baslik.surum);
            println!(
                "argon2id   : {} KiB / {} tur / {} yol",
                baslik.m_cost, baslik.t_cost, baslik.p_cost
            );
            println!(
                "sayfa      : {} adet x {} bayt",
                baslik.sayfa_sayisi, baslik.sayfa_boyutu
            );
            println!("kayit      : {}", baslik.kayit_sayisi);
            println!("tuz        : {}", vaulta::aktarim::hex(&baslik.tuz));
            println!("\n(tuz gizli degildir; gizli olan kayit icerigidir)");
            Ok(())
        }
        AltKomut::Uret { uzunluk } => {
            let uretilen = parola::uret(uzunluk)?;
            println!("{}", uretilen.as_str());
            Ok(())
        }
        AltKomut::Denetle { parola_stdin } => {
            if !parola_stdin {
                return Err(Hata::BozukArguman(
                    "--parola-stdin bayragi olmadan parola okunmaz".to_string(),
                ));
            }
            let mut girdi = GizliGirdi::ac(true)?;
            let denenen = girdi.sonraki();
            match parola::kaba_parola_denetle(&denenen) {
                Ok(()) => {
                    println!(
                        "kabul: {} karakter, NIST SP 800-63B denetiminden gecti",
                        denenen.chars().count()
                    );
                    Ok(())
                }
                Err(hata) => Err(hata),
            }
        }
    }
}

/// Bir metni verilen genişliğe kısaltır; sonuna `~` koyar.
fn kisalt(metin: &str, genislik: usize) -> String {
    let karakterler: Vec<char> = metin.chars().collect();
    if karakterler.len() <= genislik {
        metin.to_string()
    } else {
        let mut sonuc: String = karakterler[..genislik.saturating_sub(1)].iter().collect();
        sonuc.push('~');
        sonuc
    }
}
