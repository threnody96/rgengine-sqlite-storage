extern crate rgengine;
extern crate crypto;
extern crate rusqlite;
extern crate base64;

use std::path::PathBuf;
use rgengine::resource::storage::Storage;
use rusqlite::Connection;
use base64::decode;
use crypto::{ symmetriccipher, buffer, aes, blockmodes };
use crypto::buffer::{ ReadBuffer, WriteBuffer, BufferResult };

const TABLE_NAME: &str = "storage";

struct ConnectionInfo {
    conn: Connection,
    writable: bool
}

pub struct SQLiteStorage {
    name: String,
    conns: Vec<ConnectionInfo>,
    key: Vec<u8>
}

impl SQLiteStorage {

    pub fn new(name: &str, source_paths: Vec<PathBuf>, save_path: Option<PathBuf>, base64_key: &str) -> Self {
        let mut conns = Self::connects(source_paths, false);
        let key = Self::normalize_key(base64_key);
        if save_path.is_some() { conns.push(Self::connect(save_path.unwrap(), true)); }
        Self { name: name.to_owned(), conns: conns, key: key }
    }

    fn connects(source_paths: Vec<PathBuf>, writeable: bool) -> Vec<ConnectionInfo> {
        let mut conns: Vec<ConnectionInfo> = Vec::new();
        for source_path in source_paths {
            conns.push(Self::connect(source_path, writeable));
        }
        conns
    }

    fn connect(source_path: PathBuf, writable: bool) -> ConnectionInfo {
        Self::create_db_file_if_not_exists(&source_path);
        ConnectionInfo {
            conn: Connection::open(source_path).unwrap(),
            writable: writable
        }
    }

    fn normalize_key(base64_key: &str) -> Vec<u8> {
        decode(base64_key).unwrap()
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

    fn decrypt(encrypted_data: &[u8], key: &[u8], iv: &[u8]) -> Result<Vec<u8>, String> {
        let mut decryptor = aes::cbc_decryptor(
                aes::KeySize::KeySize256,
                key,
                iv,
                blockmodes::PkcsPadding);
    
        let mut final_result = Vec::<u8>::new();
        let mut read_buffer = buffer::RefReadBuffer::new(encrypted_data);
        let mut buffer = [0; 4096];
        let mut write_buffer = buffer::RefWriteBuffer::new(&mut buffer);
    
        loop {
            let result = try!(decryptor.decrypt(&mut read_buffer, &mut write_buffer, true).map_err(|_| "decript failed"));
            final_result.extend(write_buffer.take_read_buffer().take_remaining().iter().map(|&i| i));
            match result {
                BufferResult::BufferUnderflow => break,
                BufferResult::BufferOverflow => { }
            }
        }
    
        Ok(final_result)
    }

    fn create_db_file_if_not_exists(path: &PathBuf) {
        if path.exists() { return; }
        let conn = Connection::open(path).unwrap();
        conn.execute(&(format!("create table {} (
                      id     INTEGER PRIMARY KEY,
                      path   TEXT NOT NULL,
                      data   BLOB
                      )", &TABLE_NAME)), &[]).unwrap();
        conn.execute(&(format!("create unique index uindex_path on {}(path)", &TABLE_NAME)), &[]).unwrap();
        conn.close().unwrap();
    }

}

impl Storage for SQLiteStorage {

    fn name(&self) -> String {
        self.name.clone()
    }


    fn load(&self, path: &str) -> Result<Vec<u8>, String> {
        for ref conn_info in &self.conns {
            let conn = &conn_info.conn;
            let query_result: Result<Vec<u8>, _> = conn.query_row("select data from storage where path = ?1", &[&path], |r| r.get(0));
            match query_result {
                Ok(val) => {
                    let result: Vec<u8> = Self::decrypt(val.as_slice(), &self.key[0 .. 32], &self.key[32 .. 48]).unwrap();
                    return Ok(result);
                },
                Err(_) => {}
            }
        }
        Err("Failed to read the file: ".to_owned() + path)
    }

    fn list(&self, dir: Option<&str>) -> Result<Vec<String>, String> {
        let mut files: Vec<String> = Vec::new();
        for conn_info in &self.conns {
            let conn = &conn_info.conn;
            match dir {
                None => {
                    let mut stmt = conn.prepare(&format!("select path from {}", &TABLE_NAME)).unwrap();
                    let path_iter = stmt.query_map(&[], |row| row.get(0)).unwrap();
                    for path in path_iter { files.push(path.unwrap()); }
                },
                Some(d) => {
                    let mut stmt = conn.prepare(&format!("select path from {} where path like ?1", &TABLE_NAME)).unwrap();
                    let path_iter = stmt.query_map(&[&(format!("{}%", d))], |row| row.get(0)).unwrap();
                    for path in path_iter { files.push(path.unwrap()); }
                }
            };
        }
        Ok(files)
    }

    fn save(&self, path: &str, data: &Vec<u8>) -> Result<(), String> {
        let mut writed = false;
        for ref conn_info in &self.conns {
            if conn_info.writable {
                let conn = &conn_info.conn;
                let encrypted_data = try!(SQLiteStorage::encrypt(data.as_slice(), &self.key[0 .. 32], &self.key[32 .. 48]).map_err(|_| "encrypt failed".to_owned()));
                try!(conn.execute(
                    &(format!("insert into {} (path, data) values (?1, ?2)", &TABLE_NAME)),
                    &[&path, &encrypted_data]
                ).map_err(|_| "save failed".to_owned()));
                writed = true;
                break;
            }
        }
        if writed { Ok(()) } else { Err("save failed".to_owned()) }
    }

}
