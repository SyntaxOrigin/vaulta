//! Kasa (Vaulta) — Argon2id + XChaCha20-Poly1305 tek dosya parola kasası.
//!
//! # Ne yapar
//!
//! Parolaları ve kimlik bilgilerini **tek bir şifreli dosyada**, hesap açmadan,
//! ağ bağlantısı kurmadan tutar. Her komut ayrı bir süreçtir; kasa açıldığında
//! anahtar belleğe alınır, iş bitince sıfırlanır.
//!
//! # Kasa biçimi (sürüm 1)
//!
//! ```text
//! [96 bayt düz metin baslik: imza, surum, Argon2id m/t/p, tuz, sayilar]
//! [sifreli dizin : [u32 LE uzunluk][24 bayt nonce][sifre metni + etiket]]
//! [sifreli sayfa 0: ayni cerceve]
//! [sifreli sayfa 1: ...]
//! ```
//!
//! Her sayfanin duz metni kendi icinde kayit cercevelerine ayrilir:
//!
//! ```text
//! cerceve := [u32 LE govde uzunlugu][16 bayt butunluk etiketi][govde (JSON)]
//! ```
//!
//! # Guvenlik sozlesmesi
//!
//! - Ana parola → **Argon2id** (RFC 9106) → 32 bayt ana malzeme.
//! - Ana malzeme → **HKDF-SHA256** → dizin, sayfa ve cerceve anahtarlari
//!   (her biri ayri `info` etiketiyle ayrilmis).
//! - Her sayfa → **XChaCha20-Poly1305** + 192-bit rastgele `getrandom` nonce.
//!   Nonce asla sayaç degildir ve her yazma isleminde yeniden uretilir.
//! - Kayit cercevesi → **HKFP-MAC** butunluk etiketi (sayfa ici kayit duzeyi).
//! - Ana malzeme, alt anahtarlar ve duz metin tamponlari `zeroize` ile silinir.
//!
//! # Ag yuzeyi yoktur
//!
//! Bu crate'in bagimlilik agacinda `std::net` **kullanilmaz**: TCP, UDP, DNS,
//! TLS ve HTTP istemcisi hicbir modulde referans vermez. Tek dosya arayuz,
//! tek dosya girdi/cikti.

#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![warn(clippy::unwrap_used, clippy::expect_used)]

pub mod aktarim;
pub mod depo;
pub mod hata;
pub mod kasa;
pub mod kayit;
pub mod kripto;
pub mod parola;

pub use aktarim::{disa_aktar_ve_dogrula, Aktarim, DogrulamaRaporu};
pub use depo::Oturum;
pub use hata::Hata;
pub use kasa::{Baslik, Dizin};
pub use kayit::{DizinKaydi, Kayit};
pub use kripto::{Argon2Ayar, ANAHTAR_BOYUTU, CERCEVE_ETIKET_BOYUTU, NONCE_BOYUTU, TUZ_BOYUTU};
pub use parola::{kaba_parola_denetle, uret as parola_uret, EN_KISA_PAROLA};

/// Kasa biçiminin okunabilir sürüm numarası.
pub const KASA_SURUMU: u32 = kasa::SURUM as u32;
