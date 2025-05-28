use std::collections::HashMap;

use crate::{set1::challenge7::decrypt_aes_128_ecb, set2::challenge12::is_ecb};

use super::{challenge10::encrypt_aes_128_ecb, challenge12::compute_block_size_and_padding_length};

pub fn parse_query_string(query_string: &str) -> HashMap<String, String> {
    let key_value_pairs = query_string.split('&');
    key_value_pairs
        .map(|key_value| key_value.split_once('=').expect("Correct query string"))
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect()
}

pub fn profile_for(email: &str) -> String {
    let email = email
        .chars()
        .filter(|&x| x != '&' && x != '=')
        .collect::<String>();
    format!("email={email}&uid=10&role=user")
}

pub fn encrypt_profile(email: &str, key: &[u8]) -> Vec<u8> {
    encrypt_aes_128_ecb(profile_for(email).as_bytes(), key)
}

pub fn decrypt_profile(ciphertext: &[u8], key: &[u8]) -> HashMap<String, String> {
    let plain = decrypt_aes_128_ecb(ciphertext, key).expect("Valid profile");
    parse_query_string(&plain)
}

pub fn ecb_cut_and_paste_attack<F>(encrypt_fn: F) -> Vec<u8>
where
    F: Fn(&[u8]) -> Vec<u8>,
{
    let (block_size, original_padding_length) = compute_block_size_and_padding_length(&encrypt_fn);
    if !is_ecb(&encrypt_fn, block_size) {
        panic!("Data not encryped with ECB");
    }

    let admin_block_padding = vec![(block_size - 5) as u8; block_size - 5];
    let admin_block = ["admin".as_bytes(), &admin_block_padding].concat();

    let crafted_ciphertext_block =
        craft_admin_ciphertext_block(&encrypt_fn, block_size, admin_block);

    let crafted_input = vec![0; original_padding_length + "user".len()];
    let ciphertext = encrypt_fn(&crafted_input);
    let ciphertext_without_last_block = ciphertext[..ciphertext.len() - block_size].to_vec();

    [ciphertext_without_last_block, crafted_ciphertext_block].concat()
}

fn craft_admin_ciphertext_block<F>(
    encrypt_fn: F,
    block_size: usize,
    admin_block: Vec<u8>,
) -> Vec<u8>
where
    F: Fn(&[u8]) -> Vec<u8>,
{
    let mut i = 0;
    loop {
        let crafted_input = [vec![0; i], admin_block.clone(), admin_block.clone()].concat();
        let ciphertext = encrypt_fn(&crafted_input);
        let ciphertext_blocks = ciphertext.chunks(block_size).collect::<Vec<&[u8]>>();

        for j in 1..ciphertext_blocks.len() {
            if ciphertext_blocks[j - 1] == ciphertext_blocks[j] {
                return ciphertext_blocks[j].to_vec();
            }
        }

        i += 1;
    }
}

#[cfg(test)]
mod tests {
    use crate::set2::challenge11::random_bytes;

    use super::*;

    #[test]
    fn test_parse_query_string() {
        let query_string = "foo=bar&baz=qux&zap=zazzle";
        let expected = HashMap::from([
            ("foo".to_string(), "bar".to_string()),
            ("baz".to_string(), "qux".to_string()),
            ("zap".to_string(), "zazzle".to_string()),
        ]);
        assert_eq!(expected, parse_query_string(query_string));
    }

    #[test]
    fn test_profile_for() {
        assert_eq!(
            "email=foo@bar.com&uid=10&role=user",
            profile_for("foo@bar.com")
        );
        assert_eq!(
            "email=foo@bar.comroleadmin&uid=10&role=user",
            profile_for("foo@bar.com&role=admin")
        );
    }

    #[test]
    fn test_ecb_cut_and_paste_attack() {
        let key = random_bytes(16);

        let encrypt_fn = |data: &[u8]| {
            encrypt_profile(&data.iter().map(|&x| x as char).collect::<String>(), &key)
        };
        let crafted_ciphertext = ecb_cut_and_paste_attack(encrypt_fn);

        let profile = decrypt_profile(&crafted_ciphertext, &key);
        assert_eq!("admin", profile.get("role").unwrap());
    }
}
