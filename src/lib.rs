use std::{fs::File, io::{Cursor, Read, Write}, path::Path, usize};

use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use crypto::{encr_buf_len, CryptoHelper};

mod crypto;

// note1.file format is simple but open to evolve as and when need arises.
// the format is based on concept of "record". a record is a (tag, value) pair.
// all tags are listed at the beginning of the file, separate from their values
// and ecrypted using the same key. each value is encrypted using a different
// key. here is the overall format of the file:
//
// first `CryptoHelper::SALT_LENGTH` bytes: salt for generating KEK
// next `CryptoHelper::NONCE_LENGTH` bytes: kek_nonce to use with KEK to decrypt FEK
// next `CryptoHelper::KEY_LENGTH + CryptoHelper::AUTH_TAG_LENGTH` bytes: encrypted FEK
// next `CryptoHelper::NONCE_LENGTH` bytes: fek_nonce used with FEK to decrypte tags
// next 4 bytes: max number of records supported by this file
// next 4 bytes: total number of records currently in this file
// next max_regords x (`TAG_REC_LENGTH` + `CryptoHelper::AUTH_TAG_LENGTH`) bytes: encrypted tags
// next max_records x `TAG_REC_LENGTH` bytes: tags
//      each tag = `TAG_LENGTH` bytes of ascii text +
//                  `TAG_FLAGS_LENGTH` bytes reserved (currently just LSB (boolean) is used
//                      as used (1) / empty (0) flag) +
//                  `CryptoHelper::KEY_LENGTH` for symmetric key of corresponding value +
//                  `CryptoHelper::NONCE_LENGTH` for nonce to go with symmetric key above
// next max_records x `ENCR_VAL_LENGTH`` bytes: values
//      each value corresponds, in relative order, to the tag in the list of
//          tags above. e.g. the value at values[i] corresponds to the tag at
//          tags[i].
//      each value is encrypted using a different key.

// Rules for encryption and decryption:
//  1. tags will only be encrypted when writing to file
//  2. tags will only be decrypted when reading from file
//  3. values will be decrypted when read
//  4. values will be encrypted only for non-empty tags
//  5. values will be encrypted when added (post) or modified (put)

const MAX_RECORDS : u32 = 100;
const VAL_LENGTH : usize = 256;
const ENCR_VAL_LENGTH : usize = encr_buf_len!(VAL_LENGTH);
const TAG_LENGTH : usize = 248;
const TAG_FLAGS_LENGTH : usize = 8;
const TAG_REC_LENGTH : usize = TAG_LENGTH + TAG_FLAGS_LENGTH + CryptoHelper::KEY_LENGTH
                + CryptoHelper::NONCE_LENGTH;
const MAX_TAGS_REC_LENGTH : usize = MAX_RECORDS as usize * TAG_REC_LENGTH;


// HTTP codes that we return
// TODO: find a way to group these codes under a type. something like C++ enum.
// http crate has HttpStatus but don't want to include whole crate just for
// status codes.
pub const HTTP_OK : u32 = 200;
pub const HTTP_CREATED : u32 = 201;
pub const HTTP_BAD_REQUEST : u32 = 400;
pub const HTTP_NOT_FOUND : u32 = 404;
pub const HTTP_CONFLICT : u32 = 409;
pub const HTTP_INTERNAL_SERVER_ERROR : u32 = 500;
pub const HTTP_INSUFFICIENT_STORAGE : u32 = 507;

struct TagRec {
    tag : [u8;TAG_LENGTH],
    flags : u64,
    val_key : [u8; CryptoHelper::KEY_LENGTH],
    val_nonce : [u8; CryptoHelper::NONCE_LENGTH],
}

impl TagRec {
    fn new() -> Self {
        TagRec {
            tag: [0; TAG_LENGTH],
            flags: 0x0,
            val_key : [0u8; CryptoHelper::KEY_LENGTH],
            val_nonce : [0u8; CryptoHelper::NONCE_LENGTH],
        }
    }

    fn is_empty(&self) -> bool {
        return if self.flags & 0x1 == 0 {
            true
        } else {
            false
        }
    }

    fn set_is_empty(&mut self, is_empty : bool) {
        if is_empty {
            self.flags &= 0xfffffffffffffffe;
        } else {
            self.flags |= 0x1;
        }
    }

    fn as_bytes(&self) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(&self.tag);
        v.extend_from_slice(&self.flags.to_le_bytes());
        v.extend_from_slice(&self.val_key);
        v.extend_from_slice(&self.val_nonce);

        v
    }

    fn set_val_key(&mut self, val_key_in : &[u8]) {
        assert_eq!(val_key_in.len(), CryptoHelper::KEY_LENGTH);
        self.val_key.copy_from_slice(val_key_in);
    }

    fn set_val_nonce(&mut self, val_nonce_in : &[u8]) {
        assert_eq!(val_nonce_in.len(), CryptoHelper::NONCE_LENGTH);
        self.val_nonce.copy_from_slice(val_nonce_in);
    }
}

struct Metadata {
    fname : String,
    // salt used to generate KEK
    salt : [u8; CryptoHelper::SALT_LENGTH],
    // nonce to use with KEK for decrypting FEK
    kek_nonce : [u8; CryptoHelper::NONCE_LENGTH],
    // encrypted file encryption key (FEK)
    encr_fek : [u8; crypto::encr_buf_len!(CryptoHelper::KEY_LENGTH)],
    max_records : u32,
    record_count : u32,
    fek_nonce : [u8; CryptoHelper::NONCE_LENGTH],
    encr_tags : [u8; encr_buf_len!(MAX_TAGS_REC_LENGTH)],
    tags : Vec<TagRec>,
    values : Vec<[u8;ENCR_VAL_LENGTH]>,
}

impl Metadata {
    fn new(filename : &str) -> Self {
        let mut md = Metadata {
            fname : String::from(filename),
            salt : [0u8; CryptoHelper::SALT_LENGTH],
            kek_nonce : [0u8; CryptoHelper::NONCE_LENGTH],
            encr_fek : [0u8; crypto::encr_buf_len!(CryptoHelper::KEY_LENGTH)],
            max_records : MAX_RECORDS,
            record_count : 0,
            fek_nonce : [0u8; CryptoHelper::NONCE_LENGTH],
            encr_tags : [0u8; encr_buf_len!(MAX_TAGS_REC_LENGTH)],
            tags : Vec::with_capacity(MAX_RECORDS as usize),
            values : Vec::with_capacity(MAX_RECORDS as usize),
        };

        // inflate the vectors
        for _i in 0..md.max_records {
            md.tags.push(TagRec::new());
            md.values.push([0; ENCR_VAL_LENGTH]);
        }

        md
    }

    fn set_salt(&mut self, salt_in : &[u8]) {
        assert_eq!(salt_in.len(), CryptoHelper::SALT_LENGTH);
        self.salt.copy_from_slice(salt_in);
    }

    fn set_kek_nonce(&mut self, nonce_in : &[u8]) {
        assert_eq!(nonce_in.len(), CryptoHelper::NONCE_LENGTH);
        self.kek_nonce.copy_from_slice(nonce_in);
    }

    fn set_encr_fek(&mut self, encr_fek_in : &[u8]) {
        assert_eq!(encr_fek_in.len(), crypto::encr_buf_len!(CryptoHelper::KEY_LENGTH));
        self.encr_fek.copy_from_slice(encr_fek_in);
    }

    fn set_fek_nonce(&mut self, fek_nonce_in : &[u8]) {
        assert_eq!(fek_nonce_in.len(), CryptoHelper::NONCE_LENGTH);
        self.fek_nonce.copy_from_slice(fek_nonce_in);
    }

    fn set_encr_tags(&mut self, encr_tags_in : &[u8]) {
        assert_eq!(encr_tags_in.len(), encr_buf_len!(MAX_TAGS_REC_LENGTH));
        self.encr_tags.copy_from_slice(encr_tags_in);
    }

    fn tags_as_byte_array(&self) -> Vec<u8> {
        let mut v : Vec<u8> = Vec::new();

        // TODO(optimize): this is copying twice, once in tag.as_bytes() and again here.
        for t in &self.tags {
            v.extend_from_slice(&t.as_bytes());
        }

        v
    }

    fn get_fek(&self, password : &str) -> Vec<u8> {
        let kek = CryptoHelper::generate_key_using_salt(password, &self.salt);
        let fek = CryptoHelper::decrypt(&self.encr_fek, &kek, &self.kek_nonce);

        fek
    }

    fn write_to_file(&mut self, password : &str) {
        let tags_ba = self.tags_as_byte_array();
        let fek = self.get_fek(password);
        let (ciphertext, nonce) = CryptoHelper::encrypt(&tags_ba, &fek);

        self.set_fek_nonce(&nonce);
        self.set_encr_tags(&ciphertext);

        // overwrite the file every time. if there is a need, we can consider
        // editing it instead of overwriting it.
        // TODO: use BufWriter for efficiency and wrap Cursor around BufWriter
        let mut f = File::create(&self.fname).unwrap();

        f.write_all(&self.salt).unwrap();
        f.write_all(&self.kek_nonce).unwrap();
        f.write_all(&self.encr_fek).unwrap();
        f.write_u32::<LittleEndian>(self.max_records).unwrap();
        f.write_u32::<LittleEndian>(self.record_count).unwrap();
        f.write_all(&self.fek_nonce).unwrap();
        f.write_all(&self.encr_tags).unwrap();
        
        // TODO: remove this loop once we have encr_tags working. we will only write encrypted tags to file.
        /*
        for tag in &self.tags {
            // TODO: following lines should be part of TagRec's method
            f.write_all(&tag.tag).unwrap();
            f.write_u64::<LittleEndian>(tag.flags).unwrap();
            f.write_all(&tag.val_key).unwrap();
            f.write_all(&tag.val_nonce).unwrap();
        }
        */

        // values must be transformed separately when they are read and written to
        for val in &self.values {
            f.write_all(val).unwrap();
        }

        f.sync_all().unwrap();

        // TODO: for security, after writing to file, clear md from memory
    }

    // path must be validated to exist before
    fn read_from_file(path : &Path, password : &str) -> Self {
        let mut md = Metadata::new(path.to_str().unwrap());
        let mut f = File::open(path).unwrap();
        f.read_exact(&mut md.salt).unwrap();
        f.read_exact(&mut md.kek_nonce).unwrap();
        f.read_exact(&mut md.encr_fek).unwrap();
        md.max_records = f.read_u32::<LittleEndian>().unwrap();
        md.record_count = f.read_u32::<LittleEndian>().unwrap();
        f.read_exact(&mut md.fek_nonce).unwrap();
        f.read_exact(&mut md.encr_tags).unwrap();

        // decrypt tags and extract them into TagRec data structures
        let fek = md.get_fek(password);
        let plain_tags = CryptoHelper::decrypt(&md.encr_tags, &fek, &md.fek_nonce);

        let mut cursor = Cursor::new(plain_tags);

        for i in 0..md.max_records as usize {
            cursor.read_exact(&mut md.tags[i].tag).unwrap();
            md.tags[i].flags = cursor.read_u64::<LittleEndian>().unwrap();
            cursor.read_exact(&mut md.tags[i].val_key).unwrap();
            cursor.read_exact(&mut md.tags[i].val_nonce).unwrap();
        }

        // read values
        for i in 0..md.max_records as usize {
            f.read_exact(&mut md.values[i]).unwrap();
        }

        md
    }

    fn index_of_matching_tag(&self, tag : &str) -> Option<usize> {
        for (index, t) in self.tags.iter().enumerate() {
            // skip empty records.
            if t.is_empty() {
                continue;
            }

            if tag ==  cstring_to_str(&t.tag) {
                return Some(index);
            }
        }

        None
    }

    fn delete_index(&mut self, index : usize) {
        self.tags[index].set_is_empty(true);
        self.record_count -= 1;
        self.tags[index].tag.fill(0);
        self.values[index].fill(0);
    }

    fn set_value_at_index(&mut self, index : usize, new_value : &[u8]) {
        let mut dest : &mut [u8] = &mut self.values[index];
        dest.write_all(new_value).unwrap();
    }

    fn encrypt_value_at_index(&mut self, password : &str, index : usize, value : &str) {
        let vbytes = value.as_bytes();
        assert!(vbytes.len() < VAL_LENGTH);
        let mut varr = [0u8; VAL_LENGTH];
        varr[..vbytes.len()].copy_from_slice(vbytes);
        let key = CryptoHelper::generate_key(password);
        let (ciphertext, nonce) = CryptoHelper::encrypt(&varr, &key);
        self.tags[index].set_val_key(&key);
        self.tags[index].set_val_nonce(&nonce);
        self.set_value_at_index(index, &ciphertext);
    }

    fn decrypt_value_at_index(&self, index: usize) -> String {
        let decrypted = CryptoHelper::decrypt(
            &self.values[index], &self.tags[index].val_key, &self.tags[index].val_nonce);

        cstring_to_str(&decrypted).to_owned()
    }
}

fn cstring_to_str(bytes : &[u8]) -> &str {
    let first_index_of_null = bytes.iter().position(|&c| c == b'\0').unwrap_or(bytes.len());
    std::str::from_utf8(&bytes[0..first_index_of_null]).expect("cstring not a valid string!")
}

fn validate_tag_and_value(tag : &str, value : &str) -> u32 {
    if !tag.is_ascii() || !value.is_ascii() {
        eprintln!("<TAG> and <VALUE> both must consist of ASCII characters only");
        return HTTP_BAD_REQUEST;
    }

    if tag.len() > TAG_LENGTH || value.len() > VAL_LENGTH {
        eprintln!("<TAG> must not be more than 248 <VALUE> must not be more than 256 ASCII characters long");
        return HTTP_BAD_REQUEST;
    }

    HTTP_OK
}

fn validate_path_and_get_md(path : &str, password : &str) -> Result<Metadata, u32> {
    let path = Path::new(path);

    match path.try_exists() {
        Ok(exists) => {
            if exists {
                return Ok(Metadata::read_from_file(path, password));
            } else {
                eprintln!("[!] File {} doesn't exist. Please run `note1 init`
                            command to initialize file", path.to_str().unwrap());
                return Err(HTTP_NOT_FOUND);
            }
        },
        Err(e) => {
            eprintln!("[!] Failed to open file {}: {}", path.to_str().unwrap(), e);
            return Err(HTTP_INTERNAL_SERVER_ERROR);
        }
    }
}

pub fn get(path : &str, password : &str, tag : &str) -> Result<String, u32> {
    let md;

    match validate_path_and_get_md(path, password) {
        Ok(m) => md = m,
        Err(e) => return Err(e),
    }

    // here means md has been initialized. search for matching tag.
    return match md.index_of_matching_tag(tag) {
        Some(index) =>  { Ok(md.decrypt_value_at_index(index)) },
        None => {
            eprintln!("[-] Failed to find the tag '{}'", tag);
            Err(HTTP_NOT_FOUND)
        }
    }
}

pub fn list_tags(path : &str, password : &str) -> Result<Vec<String>, u32> {
    let md;
    let mut tag_strings : Vec<String> = Vec::new();

    match validate_path_and_get_md(path, password) {
        Ok(m) => md = m,
        Err(e) => return Err(e),
    }

    md.tags.iter().for_each(|t| {
        if !t.is_empty() {
            tag_strings.push(String::from(cstring_to_str(&t.tag)));
        }});

    Ok(tag_strings)
}

pub fn post(path : &str, password : &str, tag : &str, value : &str) -> u32 {
    let ret = validate_tag_and_value(tag, value);
    if ret != HTTP_OK { return ret; }

    let mut md;
    match validate_path_and_get_md(path, password) {
        Ok(m) => md = m,
        Err(e) => return e,
    }

    // TODO: check for number of available records and if not available then increase max_records.
    if md.record_count == md.max_records {
        eprintln!("[-] Failed to insert new record. Max records ({}) reached.", MAX_RECORDS);
        return HTTP_INSUFFICIENT_STORAGE;
    }

    let mut first_empty_index = usize::MAX;
    // this loop searches for empty index and for a matching record. ideally
    // code outside Metadata object should not know about it's internal
    // workings and use something like md.index_of_matching_tag() but that
    // method won't directly work here so we are leaking internals in the
    // following loop. let's tidy this up later when we have a good idea about
    // addressing this problem.
    for (i, t) in (&md.tags).iter().enumerate() {
        // check whether tag is empty and if so, skip that tag
        if t.is_empty() {
            if first_empty_index == usize::MAX {
                first_empty_index = i;
            }

            continue;
        }

        if tag == cstring_to_str(&t.tag) {
            eprintln!("Tag '{}' already exists", &tag);
            return HTTP_CONFLICT;
        }
    }

    // here means the tag doesn't exist so let's add it at index `first_empty_index`
    let mut tr = TagRec::new();

    tr.set_is_empty(false);

    let mut bref : &mut[u8] = &mut tr.tag;
    bref.write_all(tag.as_bytes()).unwrap();
    // when we initialize metadata struct from note1.file, we make sure that
    // all the 100 slots in the tags and values vectors are filled.
    md.tags[first_empty_index] = tr;

    md.encrypt_value_at_index(password, first_empty_index, value);

    md.record_count += 1;

    md.write_to_file(password);

    HTTP_OK

}

pub fn delete(path : &str, passowrd : &str, tag : &str) -> u32 {
    let mut md;
    match validate_path_and_get_md(path, passowrd) {
        Ok(m) => md = m,
        Err(e) => return e,
    }

    // here means md is valid
    let index;
    match md.index_of_matching_tag(tag) {
        Some(i) => index = i,
        None => {
            eprintln!("[-] Tag '{}' doesn't exist.", tag);
            return HTTP_NOT_FOUND;
        }
    }

    // here means we found valid tag, so delete it now
    md.delete_index(index);
    md.write_to_file(passowrd);

    HTTP_OK
}

pub fn put(path : &str, password : &str, tag : &str, new_value : &str) -> u32 {
    let ret = validate_tag_and_value(tag, new_value);
    if ret != HTTP_OK { return ret; }

    let mut md;
    match validate_path_and_get_md(path, password) {
        Ok(m) => md = m,
        Err(e) => return e,
    }

    let index;
    match md.index_of_matching_tag(tag) {
        Some(i) => index = i,
        None => {
            eprintln!("[-] Tag '{}' doesn't exist.", tag);
            return HTTP_NOT_FOUND;
        }
    }

    md.encrypt_value_at_index(password, index, new_value);
    md.write_to_file(password);

    HTTP_OK
}

pub fn init(path : &str, password : &str) -> u32 {
    let path = Path::new(path);
    let ret = path.try_exists();
    assert!(ret.is_ok());
    assert!(ret.unwrap() == false);

    let mut md = Metadata::new(path.to_str().unwrap());

    let salt = CryptoHelper::generate_salt();
    md.set_salt(&salt);

    let kek = CryptoHelper::generate_key_using_salt(password, &salt);
    let fek : [u8; CryptoHelper::KEY_LENGTH] = CryptoHelper::generate_key(password);
    let (encr_fek, nonce) = CryptoHelper::encrypt(&fek, &kek);
    md.set_kek_nonce(&nonce);
    md.set_encr_fek(&encr_fek);
    // if tag is empty, we don't encrypt value. since all tags are empty at init time,
    //  we won't encrypt any value. also no point in setting value encryption key.

    // TODO:
    //      1. generate key from password using Argon2id
    //      2. encrypt tags (not max_records or record_count)
    //      3. encrypt each value with a different key generated using Argon2id
    //      4. now md contains encrypted data. above encryptions update md itself.

    md.write_to_file(password);

    return HTTP_OK;
}

#[cfg(test)]
mod tests {
    use std::fs;
    use argon2::{password_hash::SaltString, Argon2, ParamsBuilder};
    use chacha20poly1305::{ChaCha20Poly1305, KeySizeUser};
    use rand::{distributions::{Alphanumeric, DistString}, rngs::OsRng};

    use crate::crypto::CryptoHelper;

    use super::*;

    #[test]
    fn test_post() {
        let path = Alphanumeric.sample_string(&mut rand::thread_rng(), 12);
        assert!(!fs::exists(&path).unwrap());

        init(&path, "mypass");
        post(&path, "mypass", "yahoo.com", "u: abcd p: 1234");

        let md = Metadata::read_from_file(Path::new(&path), "mypass");

        assert_eq!(md.max_records, MAX_RECORDS);
        assert_eq!(md.record_count, 1);
        assert_eq!(cstring_to_str(&md.tags[0].tag), "yahoo.com");
        assert_eq!(md.tags[0].flags, 0x1);
        assert_eq!(md.decrypt_value_at_index(0), "u: abcd p: 1234");

        fs::remove_file(&path).ok();
    }

    #[test]
    fn test_duplicate_records() {
        let path = Alphanumeric.sample_string(&mut rand::thread_rng(), 12);
        assert!(!fs::exists(&path).unwrap());

        let ret1 = init(&path, "mypass");
        assert_eq!(ret1, HTTP_OK);

        let ret1 = post(&path, "mypass", "yahoo.com", "u: abcd p: 1234");
        assert_eq!(ret1, HTTP_OK);

        let ret2 = post(&path, "mypass", "yahoo.com", "u: second_user p: second_password");
        assert_eq!(ret2, HTTP_CONFLICT);

        let md = Metadata::read_from_file(Path::new(&path), "mypass");

        assert_eq!(md.record_count, 1);
        assert_eq!(md.index_of_matching_tag("yahoo.com").unwrap(), 0);
        assert_eq!(md.fname, path.as_str());
        assert_eq!(md.tags[0].is_empty(), false);
        assert_eq!(md.tags[0].flags, 1);
        assert_eq!(cstring_to_str(&md.tags[0].tag), "yahoo.com");
        assert_eq!(md.decrypt_value_at_index(0), "u: abcd p: 1234");

        let val = get(&path, "mypass",  "yahoo.com");
        assert!(val.is_ok());
        assert_eq!(val.unwrap(), "u: abcd p: 1234");

        for (i, tag) in (&md.tags[1..]).iter().enumerate() {
            assert_eq!(tag.is_empty(), true);
            assert_eq!(tag.flags, 0);
            assert_eq!(tag.tag, [0; TAG_LENGTH]);
            assert_eq!(md.values[i + 1], [0; ENCR_VAL_LENGTH]);
        }

        fs::remove_file(&path).ok();
    }

    #[test]
    fn test_delete_record() {
        let path = Alphanumeric.sample_string(&mut rand::thread_rng(), 12);
        assert!(!fs::exists(&path).unwrap());

        let ret1 = init(&path, "mypass");
        assert_eq!(ret1, HTTP_OK);

        let ret = post(&path, "mypass", "yahoo.com", "u: abcd p: 1234");
        assert_eq!(ret, HTTP_OK);

        let ret = delete(&path, "mypass",  "yahoo.com1");
        assert_eq!(ret, HTTP_NOT_FOUND);

        let ret = get(&path, "mypass", "yahoo.com");
        assert!(ret.is_ok_and(|v| v == "u: abcd p: 1234"));

        let ret = delete(&path, "mypass", "yahoo.com");
        assert_eq!(ret, HTTP_OK);

        let ret = get(&path, "mypass", "yahoo.com");
        assert!(ret.is_err());
        assert_eq!(ret.unwrap_err(), HTTP_NOT_FOUND);

        fs::remove_file(&path).ok();
    }

    #[test]
    fn test_record_count() {
        let path = Alphanumeric.sample_string(&mut rand::thread_rng(), 12);
        assert!(!fs::exists(&path).unwrap());

        let ret1 = init(&path, "mypass");
        assert_eq!(ret1, HTTP_OK);

        let ret = post(&path, "mypass", "yahoo.com", "u: abcd p: 1234");
        assert_eq!(ret, HTTP_OK);

        let md = Metadata::read_from_file(Path::new(&path), "mypass");
        assert_eq!(md.record_count, 1);
        assert_eq!(md.max_records, MAX_RECORDS);

        fs::remove_file(&path).ok();
    }

    //#[test] // this takes more than 60 seconds
    fn test_max_records() {
        let path = Alphanumeric.sample_string(&mut rand::thread_rng(), 12);
        assert!(!fs::exists(&path).unwrap());

        let ret1 = init(&path, "mypass");
        assert_eq!(ret1, HTTP_OK);

        for i in 0..MAX_RECORDS {
            let ret = post(&path, "mypass", format!("key{}", i).as_str(), format!("value{}", i).as_str());
            assert_eq!(ret, HTTP_OK);
        }

        let ret = post(&path, "mypass", "key_more", "value_more");
        assert_eq!(ret, HTTP_INSUFFICIENT_STORAGE);

        let ret = delete(&path, "mypass", "key3");
        assert_eq!(ret, HTTP_OK);

        let ret = post(&path, "mypass", "key_more", "value_more");
        assert_eq!(ret, HTTP_OK);

        fs::remove_file(&path).ok();
    }

    #[test]
    fn test_put() {
        let path = Alphanumeric.sample_string(&mut rand::thread_rng(), 12);
        assert!(!fs::exists(&path).unwrap());

        let ret1 = init(&path, "mypass");
        assert_eq!(ret1, HTTP_OK);

        let ret = post(&path, "mypass", "yahoo.com", "u: abcd p: 1234");
        assert_eq!(ret, HTTP_OK);

        let ret = put(&path, "mypass", "yahoo2.com", "xyz");
        assert_eq!(ret, HTTP_NOT_FOUND);

        let ret = put(&path, "mypass", "yahoo.com", "u: abcd p: 5678");
        assert_eq!(ret, HTTP_OK);

        let ret = get(&path, "mypass", "yahoo.com");
        assert!(ret.is_ok());
        assert_eq!(ret.unwrap(), "u: abcd p: 5678");

        fs::remove_file(&path).ok();
    }

    // TODO: add test for list_tags()

    #[test]
    fn test_chacha20poly1305() {
        // TODO: add test for chacha20poly1305 encryption:
        //      - check input vs output size (padding should not exist since it's a stream cipher but tag length will be appended)
        //      - check AAD / auth tag
        println!("ChaCha20Poly1305 key size: {}", ChaCha20Poly1305::key_size());
    }

    /*
    // TODO: add test for argon2
    #[test]
    fn test_argon2() {
        let password = b"password";
        // TODO: check if salt requires an RNG with better cryptographic properties
        let salt = SaltString::generate(&mut OsRng);
        println!("Salt length: {}\nSalt generated from argon2: {}", salt.len(), salt);
        let mut key = [0u8; 32];
        let params = CryptoHelper::generate_argon2_params();
        println!("Value from cryptohelper: {}", params);
        //let argon = Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x10,)
    }
    */
}