use byteorder::{ByteOrder, NetworkEndian};
use log::warn;
use openssl::{
    envelope,
    pkey::{self, PKey},
    symm::Cipher,
};
use std::{fs::File, io::Read, path};

use super::ssl_key::SslKey;

pub fn decrypt_file(file: &path::Path, keys: SslKey) -> Result<Vec<u8>, std::io::Error> {
    let read_u32 = |data: &Vec<u8>, offset: &mut usize| -> u32 {
        const SIZE: usize = 4;
        let r = NetworkEndian::read_u32(&data[*offset..*offset + SIZE]);
        *offset += SIZE;
        r
    };

    let cipher = Cipher::aes_128_cbc();

    let mut enc_file = match File::open(&file) {
        Ok(file) => file,
        Err(why) => {
            warn!("couldn't open {}: {why}", file.display());
            return Err(why);
        }
    };
    let mut data_enc = Vec::new();
    let size = match enc_file.read_to_end(&mut data_enc) {
        Ok(s) => s,
        Err(why) => {
            warn!("failed to load ssl_{}: {why}", file.display());
            return Err(why);
        }
    };
    let data_enc = data_enc;

    let mut offset: usize = 0;
    // read encryption key size
    let size_et = read_u32(&data_enc, &mut offset) as usize;
    // read key
    let encrypted_key = &data_enc[offset..offset + size_et];
    offset += size_et;
    // read IV
    let iv = &data_enc[offset..offset + 16];
    offset += 16;
    // dbg!(size, offset);

    // start decryption
    let key: PKey<pkey::Private> = keys.into();
    let mut env = envelope::Open::new(cipher, &key, Some(iv), encrypted_key).unwrap();
    // we meed at least space for "size" many bytes
    let mut data_dec = vec![];
    data_dec.resize(size, 0);
    let size_dec = match env.update(&data_enc[offset..], &mut data_dec) {
        Ok(s) => s,
        Err(why) => {
            warn!("failed to decrypt ssl_{}: {}", file.display(), why);
            return Err(std::io::Error::from(std::io::ErrorKind::InvalidData));
        }
    };
    // now shrink to actually read bytes.
    data_dec.resize(size_dec, 0);

    // finish him
    let mut data_dec_remaining = vec![];
    data_dec_remaining.resize(cipher.block_size(), 0);
    let size_dec_remaining = env.finalize(&mut data_dec_remaining).unwrap();

    data_dec.append(&mut data_dec_remaining);
    let size_dec = size_dec + size_dec_remaining;

    // now shrink to actually read bytes again.
    data_dec.resize(size_dec, 0);
    // println!("{:?}", data_dec);
    assert_eq!(&size_dec, &data_dec.len());

    return Ok(data_dec);
}
