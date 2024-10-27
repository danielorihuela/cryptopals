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

pub fn attack_ecb_one_byte_at_a_time<F>(encryption_fn: F) -> String
where
    F: Fn(&[u8]) -> Vec<u8>,
{
    let block_size = discover_block_size(&encryption_fn);
    if !is_ecb(&encryption_fn, block_size) {
        panic!("Data not encryped with ECB");
    }

    let num_blocks = encryption_fn(&[]).len() / block_size;
    let mut decrypted_blocks: Vec<Vec<u8>> = vec![vec![]; num_blocks];
    for i in 0..num_blocks {
        for j in (0..block_size).rev() {
            let prefix = if i == 0 {
                vec![b'a'; j]
            } else {
                decrypted_blocks[i - 1][block_size - j..].to_vec()
            };
            let crafted_prefix = [&prefix, &decrypted_blocks[i][..]].concat();
            let encrypted_block_to_character =
                brute_force_encrypted_block(&encryption_fn, &crafted_prefix, 0, block_size);

            let encrypted_data = encryption_fn(&prefix);
            let character = encrypted_block_to_character
                .get(&encrypted_data[i * block_size..(i + 1) * block_size])
                .expect("Exists");

            decrypted_blocks[i].push(*character);
        }
    }

    String::from_utf8(decrypted_blocks.into_iter().flatten().collect()).unwrap()
}

pub fn discover_block_size<F>(encryption_fn: F) -> usize
where
    F: Fn(&[u8]) -> Vec<u8>,
{
    // Skip the prefix, if any, and go to the first block
    // that is modified with each different input
    let cipher_a = encryption_fn(&[]);
    let cipher_b = encryption_fn(&[0]);
    let cipher_c = encryption_fn(&[0, 0]);
    let mut k = 0;
    while cipher_a[k] == cipher_b[k] && cipher_b[k] == cipher_c[k] {
        k += 1;
    }

    for i in 3..65 {
        let prefix = vec![0; i];
        let cipher_a = encryption_fn(&prefix[..i - 2]);
        let cipher_b = encryption_fn(&prefix[..i - 1]);
        let cipher_c = encryption_fn(&prefix);
        if cipher_a[k] != cipher_b[k] || cipher_a[k] != cipher_c[k] {
            continue;
        }

        for j in k..cipher_a.len() {
            if cipher_a[j] == cipher_b[j] && cipher_b[j] == cipher_c[j] {
                continue;
            }

            return j - k;
        }
    }

    0
}

pub fn is_ecb<F>(encryption_fn: F, block_size: usize) -> bool
where
    F: Fn(&[u8]) -> Vec<u8>,
{
    let plain = vec![0; block_size * 100];
    let cipher = encryption_fn(&plain);

    max_repeated_block(&cipher) >= 90
}

pub fn brute_force_encrypted_block<F>(
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

    use super::{discover_block_size, encryption_oracle};

    #[test]
    fn test_discover_block_size() {
        let key = random_bytes(16);
        let encryption_fn = |data: &[u8]| encryption_oracle(data, &key);

        let block_size = discover_block_size(encryption_fn);
        assert_eq!(16, block_size);
    }

    #[test]
    fn test_is_ecb() {
        let key = random_bytes(16);
        let encryption_fn = |data: &[u8]| encryption_oracle(data, &key);

        let block_size = discover_block_size(encryption_fn);
        assert!(is_ecb(encryption_fn, block_size));
        assert!(!is_ecb(encryption_fn, 8));
    }

    #[test]
    fn test_attack_ecb() {
        let key = random_bytes(16);
        let encryption_fn = |data: &[u8]| encryption_oracle(data, &key);
        assert_eq!(
            String::from_utf8(BASE64_STANDARD.decode(UNKNOWN_STRING).unwrap()).unwrap(),
            attack_ecb_one_byte_at_a_time(encryption_fn).trim_end_matches('\0')
        );
    }
}
