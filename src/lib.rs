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
//      each tag = 248 bytes of ascii text + 8 bytes reserved (currently just LSB (boolean) is used as `is_empty`` flag)
// next max_records x 256 bytes: values
//      each value corresponds, in relative order, to the tag in the list of tags above. e.g. the value at values[i]
//          corresponds to the tag at tags[i].
//      each value is encrypted using a different key.

const MAX_RECORDS : u32 = 100;

struct TagRec {
    tag : [u8;248],
    flags : u64,
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
            md.tags.push(TagRec { tag: [0; 248], flags: 0x1 });
            md.values.push([0; 256]);
        }

        md
    }

    fn write_to_file(&mut self) {
        // overwrite the file every time. if there is a need, we can consider
        // editing it instead of overwriting it.
        // TODO: use BufWriter for efficiency and wrap Cursor around BufWriter
        let mut f = File::create(&self.fname).unwrap();

        f.write_u32::<LittleEndian>(self.max_records).unwrap();
        f.write_u32::<LittleEndian>(self.record_count).unwrap();
        for tag in &self.tags {
            f.write_all(&tag.tag).unwrap();
            f.write_u64::<LittleEndian>(tag.flags).unwrap();
        }

        for val in &self.values {
            f.write_all(val).unwrap();
        }
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
}

fn cstring_to_str(bytes : &[u8]) -> &str {
    let first_index_of_null = bytes.iter().position(|&c| c == b'\0').unwrap_or(bytes.len());
    std::str::from_utf8(&bytes[0..first_index_of_null]).expect("cstring not a valid string!")
}

fn transform(mut target : &mut [u8], source : &str) {
    // TODO: encrypt using ChaCha Poly here
    target.write_all(source.as_bytes()).unwrap();
}

pub fn post(path : &str, tag : &str, value : &str) {
    if !tag.is_ascii() || !value.is_ascii() {
        eprintln!("<TAG> and <VALUE> both must consist of ASCII characters only");
        return;
    }

    if tag.len() > 248 || value.len() > 256 {
        eprintln!("<TAG> must not be more than 248 <VALUE> must not be more than 256 ASCII characters long");
        return;
    }

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
            return;
        }
    }

    // TODO: check for number of available records and if not available then increase max_records.
    let mut first_empty_index = usize::MAX;
    for (i, t) in (&md.tags).iter().enumerate() {
        // check for is_empty and if so, skip that tag
        if t.flags & 0x1 == 0x1 {
            if first_empty_index == usize::MAX {
                first_empty_index = i;
            }

            continue;
        }

        if tag == cstring_to_str(&t.tag) {
            eprintln!("Tag '{}' already exists", &tag);
            return;
        }
    }

    // here means the tag doesn't exist so let's add it at index `first_empty_index`
    let mut tr = TagRec {
        tag : [0; 248],
        flags : 0x1,
    };

    let mut bref : &mut[u8] = &mut tr.tag;
    bref.write_all(tag.as_bytes()).unwrap();
    // when we initialize metadata struct from note1.file, we make sure that
    // all the 100 slots in the tags and values vectors are filled.
    md.tags[first_empty_index] = tr;

    transform(&mut md.values[first_empty_index], value);

    md.record_count += 1;

    md.write_to_file();

}

#[cfg(test)]
mod tests {
    use std::fs;

    use byteorder::{LittleEndian, WriteBytesExt};

    use super::*;

    struct Data {
        count1 : u32,
        count2 : u32,
        list1 : [u8; 32],
        list2 : [u8; 32],
    }

    #[test]
    fn test_binary_serialization() {
        let mut d = Data {
            count1 : 0xabcdef12,
            count2 : 0x12345678,
            list1 : [0xa5; 32],
            list2 : [0xb6; 32],

        };

        d.list1[31] = 0;
        d.list1[30] = 1;

        let mut f = File::create("test1.file").unwrap();
        f.write_u32::<LittleEndian>(d.count1).unwrap();
        f.write_u32::<LittleEndian>(d.count2).unwrap();
        f.write_all(&d.list1).unwrap();

    }

    #[test]
    fn test_post() {
        fs::remove_file("note1.file").ok();
        post("note1.file", "yahoo.com", "u: abcd p: 1234");

        let md = Metadata::read_from_file(Path::new("note1.file"));

        assert_eq!(md.max_records, 100);
        assert_eq!(md.record_count, 1);
        assert_eq!(cstring_to_str(&md.tags[0].tag), "yahoo.com");
        assert_eq!(md.tags[0].flags, 0x1);
        assert_eq!(cstring_to_str(&md.values[0]), "u: abcd p: 1234");
    }

    // TODO: add test to check for duplicate record

}