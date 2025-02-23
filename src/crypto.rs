use argon2::{password_hash::{Salt, SaltString}, Argon2};
use chacha20poly1305::{AeadCore, ChaCha20Poly1305, KeyInit};
use chacha20poly1305::aead::Aead;
use rand::rngs::OsRng;
pub struct CryptoHelper;

macro_rules! encr_buf_len {
    ($plaintext_length:expr) => {
        $plaintext_length + CryptoHelper::AUTH_TAG_LENGTH
    };
}

pub(crate) use encr_buf_len;

impl CryptoHelper {
    pub const SALT_LENGTH : usize = Salt::RECOMMENDED_LENGTH;
    // key size of ChaCha20 is fixed at 32 bytes (256 bits).
    pub const KEY_LENGTH : usize = 32;
    // nonce length of ChaCha20 is fixed at 12 bytes (96 bits).
    pub const NONCE_LENGTH : usize = 12;
    // Poly1305 tag length is 16 bytes
    pub const AUTH_TAG_LENGTH : usize = 16;

    pub fn generate_salt() -> [u8; CryptoHelper::SALT_LENGTH] {
        let mut salt_bytes = [0u8; CryptoHelper::SALT_LENGTH];
        let salt = SaltString::generate(&mut OsRng);

        salt.decode_b64(&mut salt_bytes).expect("[!] Failed to decode b64 salt to byte array");

        salt_bytes
    }

    pub fn generate_key_using_salt(password : &str, salt : &[u8]) -> [u8; CryptoHelper::KEY_LENGTH] {
        let mut key = [0u8; CryptoHelper::KEY_LENGTH];
        Argon2::default().hash_password_into(password.as_bytes(), salt, &mut key)
            .expect("[!] Failed to generate key using password and salt");

        key
    }

    pub fn generate_key(password : &str) -> [u8; CryptoHelper::KEY_LENGTH] {
        let salt = CryptoHelper::generate_salt();
        CryptoHelper::generate_key_using_salt(password, &salt)
    }

    pub fn encrypt(plaintext : &[u8], key : &[u8]) -> (Vec<u8>, Vec<u8>) {
        let cipher = ChaCha20Poly1305::new_from_slice(key)
            .expect("[!] Failed to create ChaCha20Poly1305 instance from key passed as u8 slice");

        let nonce = ChaCha20Poly1305::generate_nonce(&mut chacha20poly1305::aead::OsRng);
        let ciphertext = cipher.encrypt(&nonce, plaintext).expect("[!] Failed to encrypt");

        (ciphertext, nonce.as_slice().to_owned())
    }
}