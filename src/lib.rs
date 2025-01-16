use std::{fs::File, io::{Read, Write}, path::Path, usize};

use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};

// note1.file format is simple but open to evolve as and when need arises.
// the format is based on concept of "record". a record is a (tag, value) pair.
// all tags are listed at the beginning of the file, separate from their values
// and ecrypted using the same key. each value is encrypted using a different
// key. here is the overall format of the file:
//
// first 4 bytes: max number of records supported by this file
// next 4 bytes: total number of records currently in this file
// next max_records x 256 bytes: tags
//      each tag = 248 bytes of ascii text + 8 bytes reserved (currently just
//          LSB (boolean) is used as used (1) / empty (0) flag)
// next max_records x 256 bytes: values
//      each value corresponds, in relative order, to the tag in the list of
//          tags above. e.g. the value at values[i] corresponds to the tag at
//          tags[i].
//      each value is encrypted using a different key.

const MAX_RECORDS : u32 = 100;

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
    tag : [u8;248],
    flags : u64,
}

impl TagRec {
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
}

struct Metadata {
    fname : String,
    max_records : u32,
    record_count : u32,
    tags : Vec<TagRec>,
    values : Vec<[u8;256]>,
}

impl Metadata {
    fn new(filename : &str) -> Self {
        let mut md = Metadata {
            fname : String::from(filename),
            max_records : MAX_RECORDS,
            record_count : 0,
            tags : Vec::with_capacity(MAX_RECORDS as usize),
            values : Vec::with_capacity(MAX_RECORDS as usize),
        };

        // inflate the vectors
        for _i in 0..md.max_records {
            md.tags.push(TagRec { tag: [0; 248], flags: 0x0 });
            md.values.push([0; 256]);
        }

        md
    }

    fn write_to_file(&mut self) {
        // overwrite the file every time. if there is a need, we can consider
        // editing it instead of overwriting it.
        // TODO: use BufWriter for efficiency and wrap Cursor around BufWriter
        let mut f = File::create(&self.fname).unwrap();

        // TODO: transform {max_records, record_count, tags}
        f.write_u32::<LittleEndian>(self.max_records).unwrap();
        f.write_u32::<LittleEndian>(self.record_count).unwrap();
        for tag in &self.tags {
            f.write_all(&tag.tag).unwrap();
            f.write_u64::<LittleEndian>(tag.flags).unwrap();
        }

        // values must be transformed separately when they are read and written to
        for val in &self.values {
            f.write_all(val).unwrap();
        }

        f.sync_all().unwrap();

        // TODO: for security, after writing to file, clear md from memory
    }

    // path must be validated to exist before
    fn read_from_file(path : &Path) -> Self {
        let mut md = Metadata::new(path.to_str().unwrap());
        let mut f = File::open(path).unwrap();
        md.max_records = f.read_u32::<LittleEndian>().unwrap();
        md.record_count = f.read_u32::<LittleEndian>().unwrap();

        // read tags. today we read all tags and values, including the empty
        // ones. an optimization could be to read only the used tags and
        // values. with 100 max records, it doesn't matter much at the moment.
        for i in 0..md.max_records as usize {
            f.read_exact(&mut md.tags[i].tag).unwrap();
            md.tags[i].flags = f.read_u64::<LittleEndian>().unwrap();
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

    if tag.len() > 248 || value.len() > 256 {
        eprintln!("<TAG> must not be more than 248 <VALUE> must not be more than 256 ASCII characters long");
        return HTTP_BAD_REQUEST;
    }

    HTTP_OK
}

fn validate_path_and_get_md(path : &str) -> Result<Metadata, u32> {
    let path = Path::new(path);

    match path.try_exists() {
        Ok(exists) => {
            if exists {
                return Ok(Metadata::read_from_file(path));
            } else {
                eprintln!("File {} doesn't exist!", path.to_str().unwrap());
                return Err(HTTP_NOT_FOUND);
            }
        },
        Err(e) => {
            eprintln!("[!] Failed to open file {}: {}", path.to_str().unwrap(), e);
            return Err(HTTP_INTERNAL_SERVER_ERROR);
        }
    }
}

fn transform(mut target : &mut [u8], source : &str) {
    // TODO: encrypt using ChaCha Poly here
    target.write_all(source.as_bytes()).unwrap();
}

pub fn get(path : &str, tag : &str) -> Result<String, u32> {
    let md;

    match validate_path_and_get_md(path) {
        Ok(m) => md = m,
        Err(e) => return Err(e),
    }

    // here means md has been initialized. search for matching tag.
    return match md.index_of_matching_tag(tag) {
        Some(index) =>  {Ok(String::from(cstring_to_str(&md.values[index]))) },
        None => {
            eprintln!("[-] Failed to find the tag '{}'", tag);
            Err(HTTP_NOT_FOUND)
        }
    }
}

pub fn post(path : &str, tag : &str, value : &str) -> u32 {
    let ret = validate_tag_and_value(tag, value);
    if ret != HTTP_OK { return ret; }

    let mut md;
    let path = Path::new(path);
    match path.try_exists() {
        Ok(exists) => {
            md = if exists {
                Metadata::read_from_file(path)
            } else {
                Metadata::new(path.to_str().unwrap())
            }
        },
        Err(e) => {
            eprintln!("Failed to open or create the backing file {}: {}", path.display(), e);
            return HTTP_INTERNAL_SERVER_ERROR;
        }
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
    let mut tr = TagRec {
        tag : [0; 248],
        flags : 0x0,
    };

    tr.set_is_empty(false);

    let mut bref : &mut[u8] = &mut tr.tag;
    bref.write_all(tag.as_bytes()).unwrap();
    // when we initialize metadata struct from note1.file, we make sure that
    // all the 100 slots in the tags and values vectors are filled.
    md.tags[first_empty_index] = tr;

    transform(&mut md.values[first_empty_index], value);

    md.record_count += 1;

    md.write_to_file();

    HTTP_OK

}

pub fn delete(path : &str, tag : &str) -> u32 {
    let mut md;
    match validate_path_and_get_md(path) {
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
    md.write_to_file();

    HTTP_OK
}

#[cfg(test)]
mod tests {
    use std::fs;

    use super::*;

    #[test]
    fn test_post() {
        fs::remove_file("note1.file").ok();
        post("note1.file", "yahoo.com", "u: abcd p: 1234");

        let md = Metadata::read_from_file(Path::new("note1.file"));

        assert_eq!(md.max_records, MAX_RECORDS);
        assert_eq!(md.record_count, 1);
        assert_eq!(cstring_to_str(&md.tags[0].tag), "yahoo.com");
        assert_eq!(md.tags[0].flags, 0x1);
        assert_eq!(cstring_to_str(&md.values[0]), "u: abcd p: 1234");
    }

    #[test]
    fn test_duplicate_records() {
        fs::remove_file("note1.file").ok();
        let ret1 = post("note1.file", "yahoo.com", "u: abcd p: 1234");
        assert_eq!(ret1, HTTP_OK);

        let ret2 = post("note1.file", "yahoo.com", "u: second_user p: second_password");
        assert_eq!(ret2, HTTP_CONFLICT);

        let md = Metadata::read_from_file(Path::new("note1.file"));

        assert_eq!(md.record_count, 1);
        assert_eq!(md.index_of_matching_tag("yahoo.com").unwrap(), 0);
        assert_eq!(md.fname, "note1.file");
        assert_eq!(md.tags[0].is_empty(), false);
        assert_eq!(md.tags[0].flags, 1);
        assert_eq!(cstring_to_str(&md.tags[0].tag), "yahoo.com");
        assert_eq!(cstring_to_str(&md.values[0]), "u: abcd p: 1234");

        let val = get("note1.file", "yahoo.com");
        assert!(val.is_ok());
        assert_eq!(val.unwrap(), "u: abcd p: 1234");

        for (i, tag) in (&md.tags[1..]).iter().enumerate() {
            assert_eq!(tag.is_empty(), true);
            assert_eq!(tag.flags, 0);
            assert_eq!(tag.tag, [0; 248]);
            assert_eq!(md.values[i + 1], [0; 256]);
        }

    }

    #[test]
    fn test_delete_record() {
        fs::remove_file("note1.file").ok();
        let ret = post("note1.file", "yahoo.com", "u: abcd p: 1234");
        assert_eq!(ret, HTTP_OK);

        let ret = delete("note1.file", "yahoo.com1");
        assert_eq!(ret, HTTP_NOT_FOUND);

        let ret = get("note1.file", "yahoo.com");
        assert!(ret.is_ok_and(|v| v == "u: abcd p: 1234"));

        let ret = delete("note1.file", "yahoo.com");
        assert_eq!(ret, HTTP_OK);

        let ret = get("note1.file", "yahoo.com");
        assert!(ret.is_err());
        assert_eq!(ret.unwrap_err(), HTTP_NOT_FOUND);
    }

    #[test]
    fn test_record_count() {
        fs::remove_file("note1.file").ok();

        let ret = post("note1.file", "yahoo.com", "u: abcd p: 1234");
        assert_eq!(ret, HTTP_OK);

        let md = Metadata::read_from_file(Path::new("note1.file"));
        assert_eq!(md.record_count, 1);
        assert_eq!(md.max_records, MAX_RECORDS);
    }

    #[test]
    fn test_max_records() {
        fs::remove_file("note1.file").ok();

        for i in 0..MAX_RECORDS {
            let ret = post("note1.file", format!("key{}", i).as_str(), format!("value{}", i).as_str());
            assert_eq!(ret, HTTP_OK);
        }

        let ret = post("note1.file", "key_more", "value_more");
        assert_eq!(ret, HTTP_INSUFFICIENT_STORAGE);

        let ret = delete("note1.file", "key3");
        assert_eq!(ret, HTTP_OK);

        let ret = post("note1.file", "key_more", "value_more");
        assert_eq!(ret, HTTP_OK);
    }
}