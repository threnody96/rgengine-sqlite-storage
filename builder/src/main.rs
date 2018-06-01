extern crate rgengine;
extern crate rusqlite;
extern crate crypto;
extern crate rand;
extern crate base64;

use std::path::{Path, PathBuf};
use std::fs::{read_dir, create_dir, metadata};
use rusqlite::Connection;
use rgengine::util;
use crypto::{ symmetriccipher, buffer, aes, blockmodes };
use crypto::buffer::{ ReadBuffer, WriteBuffer, BufferResult };
use rand::{ OsRng, RngCore };

const MAX_BYTES: u64 = 1024 * 1024 * 1024;

struct DbFile {
    conn: Connection,
    path: PathBuf,
    index: u16,
    key: [u8; 48]
}

impl DbFile {

    pub fn new(dest_path: &PathBuf, index: u16, key: [u8; 48]) -> Self {
        Self { 
            conn: Self::connect(Self::generate_file_path(&dest_path, &index)),
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

    fn connect(filename: PathBuf) -> Connection {
        let conn = Connection::open(filename).unwrap();
        conn.execute("create table storage (
                      id     INTEGER PRIMARY KEY,
                      path   TEXT NOT NULL,
                      data   BLOB
                      )", &[]).unwrap();
        conn.execute("create unique index uindex_path on storage(path)", &[]).unwrap();
        conn
    }

    fn generate_file_path(dest_path: &PathBuf, index: &u16) -> PathBuf {
        let filename = "data".to_owned() + &index.to_string() + ".dat";
        dest_path.clone().join(filename)
    }

}

fn regist(db: DbFile, src_path: PathBuf, dir_paths: Vec<PathBuf>) -> Result<(), String> {
    let mut next_dir_paths: Vec<PathBuf> = vec![];
    let mut current_db = db;
    for dir_path in &dir_paths {
        if dir_path.is_file() { return Err(dir_path.to_str().unwrap().to_owned() + " is not directory."); }
        let real_path = src_path.clone().join(dir_path);
        let entries = read_dir(real_path).unwrap();
        for entry in entries {
            let entry_path = entry.unwrap().path();
            let next_path = dir_path.clone().join(entry_path.file_name().unwrap());
            if entry_path.is_file() {
                current_db = DbFile::next_connection(current_db);
                regist_file(&current_db, &entry_path, next_path.as_path());
            } else {
                next_dir_paths.push(next_path);
            }
        }
    }
    if next_dir_paths.len() == 0 { return Ok(()); }
    regist(current_db, src_path, next_dir_paths)
}

fn regist_file(current_db: &DbFile, real_path: &Path, path: &Path) {
    let data = util::load_file(real_path).unwrap();
    let encrypted_data = encrypt(&data, &current_db.key[0 .. 32], &current_db.key[32 .. 48]).unwrap();
    current_db.conn.execute(
        "insert into storage (path, data) values (?1, ?2)", 
        &[&path.to_str().unwrap(), &encrypted_data]
    ).unwrap();
}

fn prepare(src_path: &PathBuf, dest_path: &PathBuf) -> DbFile {
    if !src_path.exists() { panic!(src_path.to_str().unwrap().to_owned() + " not found"); }
    if dest_path.exists() { panic!(dest_path.to_str().unwrap().to_owned() + " is exists"); }
    create_dir(dest_path).unwrap();
    DbFile::new(&dest_path, 1, generate_encrypt_key())
}

fn generate_encrypt_key() -> [u8; 48] {
    let mut key: [u8; 48] = [0; 48];
    let mut rng = OsRng::new().unwrap();
    rng.fill_bytes(&mut key);
    println!("encrypt by: {}", &base64::encode(&key.to_vec()));
    key
}

fn encrypt(data: &[u8], key: &[u8], iv: &[u8]) -> Result<Vec<u8>, symmetriccipher::SymmetricCipherError> {
    let mut encryptor = aes::cbc_encryptor(
            aes::KeySize::KeySize256,
            key,
            iv,
            blockmodes::PkcsPadding);
    let mut final_result = Vec::<u8>::new();
    let mut read_buffer = buffer::RefReadBuffer::new(data);
    let mut buffer = [0; 4096];
    let mut write_buffer = buffer::RefWriteBuffer::new(&mut buffer);
    loop {
        let result = try!(encryptor.encrypt(&mut read_buffer, &mut write_buffer, true));
        final_result.extend(write_buffer.take_read_buffer().take_remaining().iter().map(|&i| i));
        match result {
            BufferResult::BufferUnderflow => break,
            BufferResult::BufferOverflow => { }
        }
    }
    Ok(final_result)
}

fn main() {
    let src_path = Path::new("src").to_path_buf();
    let dest_path = Path::new("dest").to_path_buf();
    let db = prepare(&src_path, &dest_path);
    regist(db, src_path, vec![PathBuf::new()]).unwrap();
}
