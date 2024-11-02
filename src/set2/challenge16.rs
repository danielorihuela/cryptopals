use crate::set2::{
    challenge10::encrypt_aes_128_cbc, challenge11::random_bytes, challenge14::prefix_length,
};

use super::{challenge10::decrypt_aes_128_cbc, challenge12::compute_block_size_and_padding_length};

lazy_static::lazy_static! {
    static ref IV: Vec<u8> = random_bytes(16);
    static ref KEY: Vec<u8> = random_bytes(16);
}

pub fn encrypt_user_data(data: &str) -> Vec<u8> {
    let data = format!(
        "comment1=cooking%20MCs;userdata={};comment2=%20like%20a%20pound%20of%20bacon",
        data
    );
    let url_encoded_data = data
        .replace('=', "%3D")
        .replace(';', "%3B")
        .replace(' ', "%20");

    encrypt_aes_128_cbc(url_encoded_data.as_bytes(), &KEY, Some(IV.to_vec()))
}

pub fn is_admin(data: &[u8]) -> bool {
    let plain = decrypt_aes_128_cbc(data, &KEY, Some(IV.to_vec()));
    plain.contains(";admin=true;")
}

pub fn cbc_bitflipping_attack() -> Vec<u8> {
    let encrypt_fn = |data: &[u8]| encrypt_user_data(&String::from_utf8_lossy(data));
    let (block_size, _) = compute_block_size_and_padding_length(encrypt_fn);

    let full_prefix_length = prefix_length(encrypt_fn, block_size);
    let block_prefix_length = block_size - (full_prefix_length % block_size);

    let mut crafted_input = vec!["a"; block_prefix_length].join("");
    crafted_input.push_str("XadminYtrueX");

    let cipher = encrypt_user_data(&crafted_input);

    let mut crafted_cipher = cipher;
    crafted_cipher[2 * block_size] ^= b';' ^ b'X';
    crafted_cipher[2 * block_size + 6] ^= b'=' ^ b'Y';
    crafted_cipher[2 * block_size + 11] ^= b';' ^ b'X';

    crafted_cipher
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cbc_bitflipping_attack() {
        let crafted_cipher = cbc_bitflipping_attack();
        assert!(is_admin(&crafted_cipher));
    }
}
