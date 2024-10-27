use base64::prelude::*;
use lazy_static::lazy_static;
use rand::random;

use crate::set2::challenge12::{brute_force_encrypted_block, discover_block_size, is_ecb};

use super::{challenge10::encrypt_aes_128_ecb, challenge11::random_bytes};

lazy_static! {
    static ref NUM_RANDOM_BYTES: usize = random::<u8>() as usize;
    static ref RANDOM_PREFIX: Vec<u8> = random_bytes(*NUM_RANDOM_BYTES);
}
const UNKNOWN_STRING: &str = "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK";

pub fn encryption_oracle(data: &[u8], key: &[u8]) -> Vec<u8> {
    encryption_oracle_with_prefix(&RANDOM_PREFIX, data, key)
}

pub fn encryption_oracle_with_prefix(prefix: &[u8], data: &[u8], key: &[u8]) -> Vec<u8> {
    let unknown_string = BASE64_STANDARD.decode(UNKNOWN_STRING).expect("Valid data");
    let data = [&prefix, data, &unknown_string].concat();

    encrypt_aes_128_ecb(&data, key)
}

pub fn attack_ecb_one_byte_at_a_time_prefix<F>(encryption_fn: F) -> String
where
    F: Fn(&[u8]) -> Vec<u8>,
{
    let block_size = discover_block_size(&encryption_fn);
    if !is_ecb(&encryption_fn, block_size) {
        panic!("Data not encryped with ECB");
    }

    let prefix_length = prefix_length(&encryption_fn, block_size);
    let prefix_extra_bytes = prefix_length % block_size;
    let bytes_to_fill_last_prefix_block = match prefix_extra_bytes {
        0 => 0,
        _ => block_size - prefix_extra_bytes,
    };
    let mut prefix_blocks = prefix_length / block_size;
    if bytes_to_fill_last_prefix_block > 0 {
        prefix_blocks += 1;
    }

    let num_blocks = encryption_fn(&vec![b'a'; bytes_to_fill_last_prefix_block]).len() / block_size;
    let target_blocks = num_blocks - prefix_blocks;
    let mut decrypted_blocks: Vec<Vec<u8>> = vec![vec![]; target_blocks];
    for i in 0..target_blocks {
        for j in (0..block_size).rev() {
            let prefix = if i == 0 {
                vec![b'a'; bytes_to_fill_last_prefix_block + j]
            } else {
                [
                    vec![b'a'; bytes_to_fill_last_prefix_block],
                    decrypted_blocks[i - 1][block_size - j..].to_vec(),
                ]
                .concat()
                .to_vec()
            };
            let crafted_prefix = [&prefix, &decrypted_blocks[i][..]].concat();
            let encrypted_block_to_character = brute_force_encrypted_block(
                &encryption_fn,
                &crafted_prefix,
                prefix_blocks,
                block_size,
            );

            let encrypted_data = encryption_fn(&prefix);
            let character = encrypted_block_to_character
                .get(
                    &encrypted_data
                        [(prefix_blocks + i) * block_size..(prefix_blocks + i + 1) * block_size],
                )
                .expect("Exists");

            decrypted_blocks[i].push(*character);
        }
    }

    String::from_utf8(decrypted_blocks.into_iter().flatten().collect()).unwrap()
}

pub fn prefix_length<F>(encryption_fn: F, block_size: usize) -> usize
where
    F: Fn(&[u8]) -> Vec<u8>,
{
    let cipher_a = encryption_fn(&[]);
    let cipher_b = encryption_fn(&[0]);
    let prefix_smaller_than_block_size = cipher_a[0..block_size] != cipher_b[0..block_size];
    if prefix_smaller_than_block_size {
        bytes_within_last_prefix_block(encryption_fn, 0, block_size)
    } else {
        let blocks_in_prefix = full_blocks_within_prefix(&cipher_a, &cipher_b, block_size);

        let initial_bytes = blocks_in_prefix * block_size;
        let last_bytes = bytes_within_last_prefix_block(encryption_fn, initial_bytes, block_size);
        initial_bytes + last_bytes
    }
}

fn full_blocks_within_prefix(cipher_a: &[u8], cipher_b: &[u8], block_size: usize) -> usize {
    let mut i = 0;
    while cipher_a[i..i + block_size] == cipher_b[i..i + block_size] {
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
    let mut input_bytes = vec![b'a'; 0];
    for i in 0..65 {
        let cipher_a = encryption_fn(&input_bytes);
        input_bytes.push(b'a');
        let cipher_b = encryption_fn(&input_bytes);

        let start = block_position;
        let end = block_position + block_size;
        if cipher_a[start..end] != cipher_b[start..end] {
            continue;
        }

        if i < block_size {
            return block_size - i;
        } else {
            return 0;
        }
    }

    0
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
                    |data: &[u8]| encryption_oracle_with_prefix(&random_prefix, data, &key);
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
        let encryption_fn = |data: &[u8]| crate::set2::challenge12::encryption_oracle(data, &key);
        assert_eq!(
            String::from_utf8(BASE64_STANDARD.decode(UNKNOWN_STRING).unwrap()).unwrap(),
            attack_ecb_one_byte_at_a_time_prefix(encryption_fn).trim_end_matches('\0')
        );
    }

    #[test]
    fn test_attack_ecb_with_prefix() {
        for _ in 0..10 {
            let key = random_bytes(16);
            let encryption_fn = |data: &[u8]| encryption_oracle(data, &key);
            assert_eq!(
                String::from_utf8(BASE64_STANDARD.decode(UNKNOWN_STRING).unwrap()).unwrap(),
                attack_ecb_one_byte_at_a_time_prefix(encryption_fn).trim_end_matches('\0')
            );
        }
    }
}
