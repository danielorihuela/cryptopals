use std::collections::HashMap;

use base64::prelude::*;

use crate::set1::challenge8::max_repeated_block;

use super::challenge10::encrypt_aes_128_ecb;

const UNKNOWN_STRING: &str = "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK";

pub fn encryption_oracle(data: &[u8], key: &[u8]) -> Vec<u8> {
    let unknown_string = BASE64_STANDARD.decode(UNKNOWN_STRING).expect("Valid data");
    let data = [data, &unknown_string].concat();

    encrypt_aes_128_ecb(&data, key)
}

pub fn attack_ecb_one_byte_at_a_time<F>(encrypt_fn: F) -> String
where
    F: Fn(&[u8]) -> Vec<u8>,
{
    let (block_size, padding_length) = compute_block_size_and_padding_length(&encrypt_fn);
    if !is_ecb(&encrypt_fn, block_size) {
        panic!("Data not encryped with ECB");
    }

    let mut plain = vec![0; block_size - 1];
    let num_target_bytes = encrypt_fn(&[]).len() - padding_length;
    for i in 0..num_target_bytes {
        let crafted_prefix = &plain[plain.len() - (block_size - 1)..];
        let cipher_block_to_character =
            brute_force_cipher_block(&encrypt_fn, crafted_prefix, 0, block_size);

        let raw_prefix = vec![0; block_size - 1 - (i % block_size)];
        let cipher = encrypt_fn(&raw_prefix);
        let start = (i / block_size) * block_size;
        let end = start + block_size;
        let character = cipher_block_to_character
            .get(&cipher[start..end])
            .expect("Exists");

        plain.push(*character);
    }

    String::from_utf8(plain[block_size - 1..].to_vec()).expect("Valid plain message")
}

pub fn compute_block_size_and_padding_length<F>(encryption_fn: F) -> (usize, usize)
where
    F: Fn(&[u8]) -> Vec<u8>,
{
    let mut i = 0;
    let mut len_diff = 0;
    while len_diff == 0 {
        len_diff = encryption_fn(&vec![0; i + 1]).len() - encryption_fn(&vec![0; i]).len();
        i += 1;
    }

    (len_diff, i)
}

pub fn is_ecb<F>(encryption_fn: F, block_size: usize) -> bool
where
    F: Fn(&[u8]) -> Vec<u8>,
{
    let plain = vec![0; block_size * 100];
    let cipher = encryption_fn(&plain);

    max_repeated_block(&cipher) >= 90
}

pub fn brute_force_cipher_block<F>(
    encryption_fn: F,
    prefix: &[u8],
    block_position: usize,
    block_size: usize,
) -> HashMap<Vec<u8>, u8>
where
    F: Fn(&[u8]) -> Vec<u8>,
{
    let mut encrypted_block_to_character = HashMap::new();
    for i in 0..=255u8 {
        let prefix_with_character = [prefix, &[i]].concat().to_vec();
        let encrypted_data = encryption_fn(&prefix_with_character);
        let start = block_position * block_size;
        let end = start + block_size;
        let encrypted_block = encrypted_data[start..end].to_vec();
        encrypted_block_to_character.insert(encrypted_block, i);
    }

    encrypted_block_to_character
}

#[cfg(test)]
mod tests {
    use base64::prelude::*;

    use crate::set2::{
        challenge11::random_bytes,
        challenge12::{attack_ecb_one_byte_at_a_time, is_ecb, UNKNOWN_STRING},
    };

    use super::{compute_block_size_and_padding_length, encryption_oracle};

    #[test]
    fn test_discover_block_size() {
        let key = random_bytes(16);
        let encryption_fn = |data: &[u8]| encryption_oracle(data, &key);

        let (block_size, _) = compute_block_size_and_padding_length(encryption_fn);
        assert_eq!(16, block_size);
    }

    #[test]
    fn test_is_ecb() {
        let key = random_bytes(16);
        let encryption_fn = |data: &[u8]| encryption_oracle(data, &key);

        let (block_size, _) = compute_block_size_and_padding_length(encryption_fn);
        assert!(is_ecb(encryption_fn, block_size));
        assert!(!is_ecb(encryption_fn, 8));
    }

    #[test]
    fn test_attack_ecb() {
        let key = random_bytes(16);
        let encryption_fn = |data: &[u8]| encryption_oracle(data, &key);
        assert_eq!(
            String::from_utf8(BASE64_STANDARD.decode(UNKNOWN_STRING).unwrap()).unwrap(),
            attack_ecb_one_byte_at_a_time(encryption_fn)
        );
    }
}
