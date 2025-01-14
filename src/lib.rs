use std::path::Path;

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
struct Metadata {
    record_count : u32,
    max_records : u32,
}

impl Metadata {
    
}

// TODO: implement this properly
fn init_note1(path : &Path) -> Metadata {
    // TODO: print for testing only
    println!("[+] File {} doesn't exist so creating and initializing it", path.display());
    let check = path.try_exists();
    assert!(check.is_ok());
    assert!(!check.ok().unwrap());

    Metadata {
        record_count : 0,
        max_records : 100,
    }
}

// TODO: implement this properly
fn open_note1(path : &Path) -> Metadata {
    // TODO: print for testing only
    println!("[+] File {} already exist so just opening it", path.display());
    let check = path.try_exists();
    assert!(check.is_ok());
    assert!(check.ok().unwrap());

    Metadata {
        record_count : 20,
        max_records : 100,
    }
}

pub fn post(path : &str, tag : &str, value : &str) {
    // 0. check args:
    // 1. if file at path doesn't exist, prepare it:
    //  a. create the file
    //  b. set max records
    //  c. return the whole file in a buffer or some meta data struct
    // 2. open the file
    // 3. get all records in the file and see if tag already exists. if it does, return error
    // 4. add new string
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
                // TODO: this can return error because file may fail to create
                open_note1(path)
            } else {
                init_note1(path)
            }
        },
        Err(e) => {
            eprintln!("Failed to open or create the backing file {}: {}", path.display(), e);
            return;
        }
    }

}