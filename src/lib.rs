extern crate rgengine;
extern crate crypto;
extern crate r2d2;
extern crate r2d2_sqlite;
extern crate rusqlite;
extern crate base64;

use std::path::PathBuf;
use rgengine::storage::Storage;
use r2d2_sqlite::SqliteConnectionManager;
use base64::decode;
use crypto::{ buffer, aes, blockmodes };
use crypto::buffer::{ ReadBuffer, WriteBuffer, BufferResult };

pub struct SQLiteStorage {
    pools: Vec<r2d2::Pool<SqliteConnectionManager>>,
    key: Vec<u8>
}

impl SQLiteStorage {

    pub fn new(source_paths: Vec<PathBuf>, base64_key: &str) -> Self {
        let pools = Self::build_pools(source_paths);
        let key = Self::normalize_key(base64_key);
        Self { pools: pools, key: key }
    }

    fn build_pools(source_paths: Vec<PathBuf>) -> Vec<r2d2::Pool<SqliteConnectionManager>> {
        let mut pools: Vec<r2d2::Pool<SqliteConnectionManager>> = vec![];
        for source_path in &source_paths {
            let manager = SqliteConnectionManager::file(source_path.as_path());
            pools.push(r2d2::Pool::builder().max_size(1).build(manager).unwrap());
        }
        pools
    }

    fn normalize_key(base64_key: &str) -> Vec<u8> {
        decode(base64_key).unwrap()
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

}

impl Storage for SQLiteStorage {

    fn load(&self, path: &str) -> Result<Vec<u8>, String> {
        for pool in &self.pools {
            let conn = try!(pool.get().map_err(|_| "lost connection".to_owned()));
            let query_result: Result<Vec<u8>, _> = conn.query_row("select data from storage where path = ?", &[&path], |r| r.get(0));
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

}
