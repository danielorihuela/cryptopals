use rand::Rng;

use crate::set1::challenge8::max_repeated_block;

use super::{
    challenge10::{encrypt_aes_128_cbc, encrypt_aes_128_ecb},
    challenge9::pkcs7_padding_bytes,
};

pub fn random_bytes(num_bytes: usize) -> Vec<u8> {
    (0..num_bytes)
        .map(|_| rand::random::<u8>())
        .collect::<Vec<u8>>()
}

pub fn encryption_oracle(data: &[u8], mode: &mut BlockMode) -> Vec<u8> {
    let mut rng = rand::thread_rng();

    let a = rng.gen_range(5..=10);
    let b = rng.gen_range(5..=10);
    let padding_length = (16 - ((data.len() + a + b) % 16));
    let data = [&random_bytes(a), data, &random_bytes(b)].concat();
    let padded_data = pkcs7_padding_bytes(&data, 0, data.len() + padding_length);

    let key = random_bytes(16);
    let ecb = rand::random::<bool>();
    if ecb {
        *mode = BlockMode::ECB;

        encrypt_aes_128_ecb(&padded_data, &key)
    } else {
        *mode = BlockMode::CBC;

        let iv = random_bytes(16);
        encrypt_aes_128_cbc(&padded_data, &key, Some(iv))
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum BlockMode {
    ECB,
    CBC,
}

pub fn ecb_or_cbc<F>(mut encrypt_fn: F) -> BlockMode
where
    F: FnMut(Vec<u8>) -> Vec<u8>,
{
    let plain = vec![0; 16 * 100];
    let cipher = encrypt_fn(plain);
    if max_repeated_block(&cipher) >= 100 {
        BlockMode::ECB
    } else {
        BlockMode::CBC
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encrypt_oracle_works() {
        (0..100).for_each(|_| {
            let mut expected_block_mode = BlockMode::ECB;
            let encrypt_fn = |data: Vec<u8>| encryption_oracle(&data, &mut expected_block_mode);
            let actual_block_mode = ecb_or_cbc(encrypt_fn);
            assert_eq!(expected_block_mode, actual_block_mode);
        });
    }
}
