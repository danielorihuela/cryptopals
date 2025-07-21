use base64::prelude::*;
use lazy_static::lazy_static;
use rand::random;

use crate::set2::challenge12::is_ecb;

use super::{
    challenge10::encrypt_aes_128_ecb,
    challenge11::random_bytes,
    challenge12::{brute_force_ciphertext_block, compute_block_size_and_padding_length},
};

lazy_static! {
    static ref NUM_RANDOM_BYTES: usize = random::<u8>() as usize;
    static ref RANDOM_PREFIX: Vec<u8> = random_bytes(*NUM_RANDOM_BYTES);
}
const UNKNOWN_STRING: &str = "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK";

pub fn encrypt(data: &[u8], key: &[u8]) -> Vec<u8> {
    encrypt_with_prefix(&RANDOM_PREFIX, data, key)
}

pub fn encrypt_with_prefix(prefix: &[u8], data: &[u8], key: &[u8]) -> Vec<u8> {
    let unknown_string = BASE64_STANDARD.decode(UNKNOWN_STRING).expect("Valid data");
    let data = [&prefix, data, &unknown_string].concat();

    encrypt_aes_128_ecb(&data, key)
}

pub fn attack_ecb_one_byte_at_a_time_prefix<F>(encrypt_fn: F) -> String
where
    F: Fn(&[u8]) -> Vec<u8>,
{
    let (block_size, padding_length) = compute_block_size_and_padding_length(&encrypt_fn);
    if !is_ecb(&encrypt_fn, block_size) {
        panic!("Data not encryped with ECB");
    }

    let prefix_length = prefix_length(&encrypt_fn, block_size);
    let prefix_trailing_bytes = prefix_length % block_size;
    let prefix_blocks = match prefix_trailing_bytes {
        0 => prefix_length / block_size,
        _ => (prefix_length / block_size) + 1,
    };

    let bytes_to_fill_last_prefix_block = match prefix_trailing_bytes {
        0 => 0,
        _ => block_size - prefix_trailing_bytes,
    };

    let mut plain = vec![0; block_size - 1];
    let num_target_bytes = encrypt_fn(&[]).len() - padding_length - prefix_length;
    for i in 0..num_target_bytes {
        let crafted_prefix = [
            &vec![0; bytes_to_fill_last_prefix_block],
            &plain[plain.len() - (block_size - 1)..],
        ]
        .concat();
        let ciphertext_block_to_character =
            brute_force_ciphertext_block(&encrypt_fn, &crafted_prefix, prefix_blocks, block_size);

        let raw_prefix =
            vec![0; bytes_to_fill_last_prefix_block + block_size - 1 - (i % block_size)];
        let ciphertext = encrypt_fn(&raw_prefix);
        let start = (prefix_blocks + (i / block_size)) * block_size;
        let end = start + block_size;
        let character = ciphertext_block_to_character
            .get(&ciphertext[start..end])
            .expect("Exists");

        plain.push(*character);
    }

    String::from_utf8(plain[block_size - 1..].to_vec()).expect("Valid plain message")
}

pub fn prefix_length<F>(encrypt_fn: F, block_size: usize) -> usize
where
    F: Fn(&[u8]) -> Vec<u8>,
{
    let ciphertext_a = encrypt_fn(&[]);
    let ciphertext_b = encrypt_fn(&[0]);
    let prefix_smaller_than_block_size = ciphertext_a[0..block_size] != ciphertext_b[0..block_size];
    if prefix_smaller_than_block_size {
        bytes_within_last_prefix_block(encrypt_fn, 0, block_size)
    } else {
        let blocks_in_prefix = full_blocks_within_prefix(&ciphertext_a, &ciphertext_b, block_size);

        let initial_bytes = blocks_in_prefix * block_size;
        let last_bytes = bytes_within_last_prefix_block(encrypt_fn, initial_bytes, block_size);
        initial_bytes + last_bytes
    }
}

fn full_blocks_within_prefix(ciphertext_a: &[u8], ciphertext_b: &[u8], block_size: usize) -> usize {
    let mut i = 0;
    while ciphertext_a[i..i + block_size] == ciphertext_b[i..i + block_size] {
        i += block_size;
    }

    i / block_size
}

fn bytes_within_last_prefix_block<F>(
    encryption_fn: F,
    block_position: usize,
    block_size: usize,
) -> usize
where
    F: Fn(&[u8]) -> Vec<u8>,
{
    let start = block_position;
    let end = block_position + block_size;
    let ciphertext_block = |length: usize| encryption_fn(&vec![0; length])[start..end].to_vec();

    let mut i = 0;
    while ciphertext_block(i) != ciphertext_block(i + 1) {
        i += 1;
    }

    match i < block_size {
        true => block_size - i,
        false => 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::set2::challenge11::random_bytes;

    #[test]
    fn test_prefix_length() {
        let key = random_bytes(16);
        for _ in 0..10 {
            for i in 0..100 {
                let random_prefix = random_bytes(i);
                let encryption_fn =
                    |data: &[u8]| encrypt_with_prefix(&random_prefix, data, &key);
                assert_eq!(
                    random_prefix.len(),
                    prefix_length(encryption_fn, 16),
                    "Failed for {i}"
                );
            }
        }
    }

    #[test]
    fn test_attack_ecb_with_new_method() {
        let key = random_bytes(16);
        let encryption_fn = |data: &[u8]| crate::set2::challenge12::encrypt(data, &key);
        assert_eq!(
            String::from_utf8(BASE64_STANDARD.decode(UNKNOWN_STRING).unwrap()).unwrap(),
            attack_ecb_one_byte_at_a_time_prefix(encryption_fn)
        );
    }

    #[test]
    fn test_attack_ecb_with_prefix() {
        for _ in 0..10 {
            let key = random_bytes(16);
            let encryption_fn = |data: &[u8]| encrypt(data, &key);
            assert_eq!(
                String::from_utf8(BASE64_STANDARD.decode(UNKNOWN_STRING).unwrap()).unwrap(),
                attack_ecb_one_byte_at_a_time_prefix(encryption_fn).trim_end_matches('\0')
            );
        }
    }
}
