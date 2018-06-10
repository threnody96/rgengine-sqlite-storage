extern crate rgengine;
extern crate rgengine_sqlite_storage;
extern crate rand;
extern crate base64;
extern crate getopts;

use getopts::Options;
use std::env;
use std::path::{Path, PathBuf};
use std::fs::{create_dir, metadata};
use rgengine::resource::storage::Storage;
use rgengine::resource::storage::file_storage::FileStorage;
use rgengine_sqlite_storage::SQLiteStorage;
use rand::{ OsRng, RngCore };

const MAX_BYTES: u64 = 1024 * 1024 * 1024;

struct DbFile {
    storage: SQLiteStorage,
    path: PathBuf,
    index: u16,
    key: Vec<u8>
}

impl DbFile {

    pub fn new(dest_path: &PathBuf, index: u16, key: Vec<u8>) -> Self {
        Self { 
            storage: SQLiteStorage::new("dummy", vec![], Some(Self::generate_file_path(&dest_path, &index)), &base64::encode(&key)),
            path: dest_path.clone(),
            index: index,
            key: key
        }
    }

    pub fn next_connection(current: Self) -> Self {
        let m = metadata(Self::generate_file_path(&current.path, &current.index)).unwrap();
        if m.len() < MAX_BYTES {
            current
        } else {
            Self::new(&current.path, current.index + 1, current.key)
        }
    }

    fn generate_file_path(dest_path: &PathBuf, index: &u16) -> PathBuf {
        dest_path.clone().join(format!("data{}.dat", index))
    }

}

fn regist(db: DbFile, fstorage: &FileStorage) -> Result<(), String> {
    let files = try!(fstorage.list(None));
    let mut current_storage = db;
    for file in &files {
        current_storage = DbFile::next_connection(current_storage);
        try!(current_storage.storage.save(&file, &try!(fstorage.load(&file))));
    }
    Ok(())
}

fn prepare(dest_path: &PathBuf, key: Option<String>) -> DbFile {
    if dest_path.exists() { panic!(dest_path.to_str().unwrap().to_owned() + " is exists"); }
    let vec_key = match key {
        None => { generate_encrypt_key() },
        Some(k) => { base64::decode(&k).unwrap() }
    };
    if vec_key.len() != 48 { panic!(format!("encrypt key must be 48 bytes.")); }
    create_dir(dest_path).unwrap();
    DbFile::new(&dest_path, 1, vec_key)
}

fn generate_encrypt_key() -> Vec<u8> {
    let mut key: [u8; 48] = [0; 48];
    let mut rng = OsRng::new().unwrap();
    rng.fill_bytes(&mut key);
    let vec_key = key.to_vec();
    println!("encrypt by: {}", &base64::encode(&vec_key));
    vec_key
}

fn build_option_setting() -> Options {
    let mut opts = Options::new();
    opts.optopt("t", "target", "Set pack target directory path", "DIRECTORY_PATH");
    opts.optopt("o", "output", "Set output directory path", "DIRECTORY_PATH");
    opts.optopt("k", "key", "Set Base64 encoded encrypt key (default: random generate)", "KEY");
    opts.optflag("h", "help", "print this help menu");
    opts
}

fn print_usage(program: &str, opts: Options) {
    let brief = format!("Usage: {} [options]", program);
    print!("{}", opts.usage(&brief));
}

fn main() {
    let args: Vec<String> = env::args().collect();
    let program = args[0].clone();
    let option = build_option_setting();
    let matches = match option.parse(&args[1..]) {
        Ok(m) => { m },
        Err(f) => { panic!(f.to_string()) }
    };
    if matches.opt_present("h") || !matches.opt_present("t") || !matches.opt_present("o") {
        print_usage(&program, option);
    } else {
        let src_path = Path::new(&matches.opt_str("t").unwrap()).to_path_buf();
        let dest_path = Path::new(&matches.opt_str("o").unwrap()).to_path_buf();
        let fstorage = FileStorage::new("dummy", src_path.to_str().unwrap(), false);
        let db = prepare(&dest_path, matches.opt_str("k"));
        regist(db, &fstorage).unwrap();
    }
}
