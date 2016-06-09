#![feature(question_mark)]
#![feature(collections)]
#![no_std]

#[macro_use] extern crate collections;

mod util;
mod ops;

use collections::Vec;
pub use ops::Acorn128;


#[derive(Debug)]
pub enum DecryptFail {
    TagLengthError,
    AuthenticationFail
}

pub fn aead_encrypt(key: &[u8], iv: &[u8], message: &[u8], aad: &[u8]) -> (Vec<u8>, [u8; 16]) {
    let mut output = Vec::with_capacity(message.len());
    let mut acorn = Acorn128::init(key, iv);

    for &b in aad {
        acorn.enc_onebyte(b, 0xff, 0xff);
    }
    for i in 0..(512 / 8) {
        acorn.enc_onebyte(
            if i == 0 { 1 } else { 0 },
            if i < (256 / 8) { 0xff } else { 0 },
            0xff
        );
    }

    for &b in message {
        let (b, _) = acorn.enc_onebyte(b, 0xff, 0);
        output.push(b);
    }
    for i in 0..(512 / 8) {
        acorn.enc_onebyte(
            if i == 0 { 1 } else { 0 },
            if i < (256 / 8) { 0xff } else { 0 },
            0
        );
    }

    (output, acorn.tag_generation())
}

pub fn aead_decrypt(key: &[u8], iv: &[u8], ciphertext: &[u8], aad: &[u8], tag: &[u8]) -> Result<Vec<u8>, DecryptFail> {
    if tag.len() != 16 { Err(DecryptFail::TagLengthError)? };

    let mut output = Vec::with_capacity(ciphertext.len());
    let mut acorn = Acorn128::init(key, iv);

    for &b in aad {
        acorn.enc_onebyte(b, 0xff, 0xff);
    }
    for i in 0..(512 / 8) {
        acorn.enc_onebyte(
            if i == 0 { 1 } else { 0 },
            if i < (256 / 8) { 0xff } else { 0 },
            0xff
        );
    }

    for &b in ciphertext {
        let b = acorn.dec_onebyte(b, 0xff, 0);
        output.push(b);
    }
    for i in 0..(512 / 8) {
        acorn.enc_onebyte(
            if i == 0 { 1 } else { 0 },
            if i < (256 / 8) { 0xff } else { 0 },
            0
        );
    }

    if util::eq(&acorn.tag_generation(), tag) {
        Ok(output)
    } else {
        Err(DecryptFail::AuthenticationFail)
    }
}


#[test]
fn acorn_test() {
    let key = [0; 16];
    let iv = [0; 16];
    let aad = [0; 16];
    let message = [0; 64];

    let (ciphertext, tag) = aead_encrypt(&key, &iv, &message, &aad);
    let plaintext = aead_decrypt(&key, &iv, &ciphertext, &aad, &tag).unwrap();
    assert!(util::eq(&message, &plaintext))
}
