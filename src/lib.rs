extern crate rgengine;
extern crate crypto;
extern crate rusqlite;
extern crate base64;

use std::path::PathBuf;
use rgengine::storage::Storage;
use rusqlite::Connection;
use base64::decode;
use crypto::{ buffer, aes, blockmodes };
use crypto::buffer::{ ReadBuffer, WriteBuffer, BufferResult };

pub struct SQLiteStorage {
    conns: Vec<Connection>,
    key: Vec<u8>
}

impl SQLiteStorage {

    pub fn new(source_paths: Vec<PathBuf>, base64_key: &str) -> Self {
        let conns = Self::connect(source_paths);
        let key = Self::normalize_key(base64_key);
        Self { conns: conns, key: key }
    }

    fn connect(source_paths: Vec<PathBuf>) -> Vec<Connection> {
        let mut conns: Vec<Connection> = vec![];
        for source_path in &source_paths {
            conns.push(Connection::open(source_path).unwrap());
        }
        conns
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
        for conn in &self.conns {
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

}
