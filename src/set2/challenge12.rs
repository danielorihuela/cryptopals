use std::collections::HashMap;

use base64::prelude::*;

use super::{challenge10::encrypt_aes_128_ecb, challenge9::pkcs7_padding_bytes};

const UNKNOWN_STRING: &str = "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK";

pub fn encryption_oracle(data: &[u8], key: &[u8]) -> Vec<u8> {
    let unknown_string = BASE64_STANDARD.decode(UNKNOWN_STRING).expect("Valid data");
    let data = [data, &unknown_string].concat();
    let padded_data = pkcs7_padding_bytes(&data, 0, data.len() + 16 - data.len() % 16);

    encrypt_aes_128_ecb(&padded_data, key)
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
                brute_force_encrypted_block(&encryption_fn, &crafted_prefix, block_size);

            let encryped_data = encryption_fn(&prefix);
            let character = encrypted_block_to_character
                .get(&encryped_data[i * block_size..(i + 1) * block_size])
                .expect("Exists");

            decrypted_blocks[i].push(*character);
        }
    }

    String::from_utf8(decrypted_blocks.into_iter().flatten().collect()).unwrap()
}

fn discover_block_size<F>(encryption_fn: F) -> usize
where
    F: Fn(&[u8]) -> Vec<u8>,
{
    for i in 2..65 {
        let prefix = vec![b'a'; i];
        let encrypted_a = encryption_fn(&prefix);
        let encrypted_b = encryption_fn(&prefix[..i - 1]);
        let first_block_stays_the_same = encrypted_a[..i - 1] == encrypted_b[..i - 1];
        if first_block_stays_the_same {
            return i - 1;
        }
    }

    0
}

fn is_ecb<F>(encryption_fn: F, block_size: usize) -> bool
where
    F: Fn(&[u8]) -> Vec<u8>,
{
    let data = vec![b'a'; 2 * block_size];
    let encrypted_data = encryption_fn(&data);

    encrypted_data[0..block_size] == encrypted_data[block_size..2 * block_size]
}

fn brute_force_encrypted_block<F>(
    encryption_fn: F,
    prefix: &[u8],
    block_size: usize,
) -> HashMap<Vec<u8>, u8>
where
    F: Fn(&[u8]) -> Vec<u8>,
{
    let mut encrypted_block_to_character = HashMap::new();
    for i in 0..=255u8 {
        let prefix_with_character = [prefix, &[i]].concat().to_vec();
        let encrypted_data = encryption_fn(&prefix_with_character);
        let encrypted_block = encrypted_data[0..block_size].to_vec();
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
