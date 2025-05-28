use aes::{
    cipher::{consts::U16, generic_array::GenericArray, BlockDecrypt, BlockEncrypt, KeyInit},
    Aes128,
};

use crate::set1::challenge2::xor_bytes;

use super::challenge9::{pkcs7_padding, strip_pkcs7_padding};

pub fn encrypt_aes_128_ecb(data: &[u8], key: &[u8]) -> Vec<u8> {
    let key = GenericArray::from_slice(key);

    let plain = Aes128::new(key);
    let ciphertext = pkcs7_padding(data, 16)
        .chunks(16)
        .map(|c| {
            let mut block = *GenericArray::<u8, U16>::from_slice(c);
            plain.encrypt_block(&mut block);

            block
        })
        .flat_map(|b| b.to_vec())
        .collect::<Vec<u8>>();

    ciphertext
}

pub fn encrypt_aes_128_cbc(data: &[u8], key: &[u8], iv: Option<Vec<u8>>) -> Vec<u8> {
    let key = GenericArray::from_slice(key);
    let cipher = Aes128::new(key);

    let mut ciphertext = vec![];
    let mut prev_chunk = iv.unwrap_or(vec![0; 16]);
    for curr_chunk in pkcs7_padding(data, 16).chunks(16) {
        let xor_chunk = xor_bytes(&prev_chunk, curr_chunk);

        let mut ciphertext_chunk = *GenericArray::<u8, U16>::from_slice(&xor_chunk);
        cipher.encrypt_block(&mut ciphertext_chunk);

        ciphertext.append(&mut ciphertext_chunk.to_vec());
        prev_chunk = ciphertext_chunk.to_vec();
    }

    ciphertext
}

pub fn decrypt_aes_128_cbc(data: &[u8], key: &[u8], iv: Option<Vec<u8>>) -> String {
    let key = GenericArray::from_slice(key);
    let cipher = Aes128::new(key);

    let iv_data = [&iv.unwrap_or(vec![0; 16]), data].concat();
    let chunks = iv_data.chunks(16).rev().collect::<Vec<&[u8]>>();

    let mut plain = vec![];
    for chunks in chunks.windows(2) {
        let (curr_chunk, prev_chunk) = (chunks[0], chunks[1]);
        let mut plain_chunk = *GenericArray::<u8, U16>::from_slice(curr_chunk);
        cipher.decrypt_block(&mut plain_chunk);

        plain.push(xor_bytes(&plain_chunk, prev_chunk));
    }

    let plain = plain.iter().rev().flatten().cloned().collect::<Vec<u8>>();
    let plain = strip_pkcs7_padding(&plain);

    String::from_utf8_lossy(&plain).to_string()
}

#[cfg(test)]
mod tests {
    use base64::prelude::*;

    use crate::{set1::challenge7::decrypt_aes_128_ecb, set2::read_set2_resource};

    use super::*;

    #[test]
    fn encrypt_decrypt_aes_128_ecb_works() {
        let message = "Random message I need to encrypt";
        let password = "YELLOW SUBMARINE";
        let ciphertext = encrypt_aes_128_ecb(message.as_bytes(), password.as_bytes());
        assert_eq!(
            message,
            decrypt_aes_128_ecb(&ciphertext, password.as_bytes()).unwrap()
        );

        let message = "Random message";
        let password = "YELLOW SUBMARINE";
        let ciphertext = encrypt_aes_128_ecb(message.as_bytes(), password.as_bytes());
        assert_eq!(
            message,
            decrypt_aes_128_ecb(&ciphertext, password.as_bytes()).unwrap()
        );
    }

    #[test]
    fn encrypt_decrypt_aes_128_cbc_works() {
        let message = "Random message I need to encrypt";
        let password = "YELLOW SUBMARINE";
        let ciphertext = encrypt_aes_128_cbc(message.as_bytes(), password.as_bytes(), None);
        assert_eq!(
            message,
            decrypt_aes_128_cbc(&ciphertext, password.as_bytes(), None)
        );

        let message = "Random message";
        let password = "YELLOW SUBMARINE";
        let ciphertext = encrypt_aes_128_cbc(message.as_bytes(), password.as_bytes(), None);
        assert_eq!(
            message,
            decrypt_aes_128_cbc(&ciphertext, password.as_bytes(), None)
        );
    }

    #[test]
    fn decrypt_aes_128_cbc_works() {
        let file_data = read_set2_resource("challenge10.txt");
        let ciphertext = BASE64_STANDARD
            .decode(file_data.lines().collect::<String>())
            .unwrap();
        let password = "YELLOW SUBMARINE";
        let plain = decrypt_aes_128_cbc(&ciphertext, password.as_bytes(), None);
        assert!(plain.starts_with(
            "I'm back and I'm ringin' the bell \nA rockin' on the mike while the fly girls yell"
        ));
        assert!(plain.ends_with("Play that funky music \n"));
    }
}
