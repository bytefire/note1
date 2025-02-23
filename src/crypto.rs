use argon2::{password_hash::{Salt, SaltString}, Params, ParamsBuilder};
use rand::rngs::OsRng;
pub struct CryptoHelper;

impl CryptoHelper {
    pub const SALT_LENGTH : usize = Salt::RECOMMENDED_LENGTH;
    pub const KEY_LENGTH : usize = 32;

    pub fn get_salt_as_bytes() -> [u8; CryptoHelper::SALT_LENGTH] {
        let mut salt_bytes = [0u8; CryptoHelper::SALT_LENGTH];
        let salt = SaltString::generate(&mut OsRng);

        salt.decode_b64(&mut salt_bytes).expect("[!] Failed to decode b64 salt to byte array");

        salt_bytes
    }

    //pub fn bytes_to_base64
}