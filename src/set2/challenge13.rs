use std::collections::HashMap;

use crate::{set1::challenge7::decrypt_aes_128_ecb, set2::challenge12::is_ecb};

use super::{challenge10::encrypt_aes_128_ecb, challenge12::discover_block_size};

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

pub fn decrypt_profile(cipher: &[u8], key: &[u8]) -> HashMap<String, String> {
    let plain = decrypt_aes_128_ecb(cipher, key).expect("Valid profile");
    parse_query_string(&plain)
}

pub fn ecb_cut_and_paste_attack<F>(encrypt_fn: F) -> Vec<u8>
where
    F: Fn(&[u8]) -> Vec<u8>,
{
    let block_size = discover_block_size(&encrypt_fn);
    if !is_ecb(&encrypt_fn, block_size) {
        panic!("Data not encryped with ECB");
    }

    let length_fn = |i: usize| encrypt_fn(&vec![0; i]).len();
    let mut i = 1;
    while length_fn(i - 1) == length_fn(i) {
        i += 1;
    }
    let num_chars_before_new_block = i;

    let crafted_input = [
        vec!["a"; num_chars_before_new_block],
        vec!["a", "d", "m", "i", "n"],
        vec!["\0"; 11],
        vec!["a", "d", "m", "i", "n"],
        vec!["\0"; 11],
    ]
    .concat()
    .join("");
    let cipher = encrypt_fn(crafted_input.as_bytes());

    let cipher_blocks = cipher
        .chunks(block_size)
        .map(|x| x.to_vec())
        .collect::<Vec<Vec<_>>>();
    let mut cipher_crafted_block = vec![];
    for i in 0..cipher_blocks.len() {
        let block_i = &cipher_blocks[i];
        for block_j in cipher_blocks.iter().skip(i + 1) {
            if block_i == block_j {
                cipher_crafted_block = block_i.clone();
                break;
            }
        }
    }

    let crafted_input = [vec!["a"; num_chars_before_new_block + 3]]
        .concat()
        .join("");
    let cipher = encrypt_fn(crafted_input.as_bytes());

    [cipher[..cipher.len() - 16].to_vec(), cipher_crafted_block].concat()
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
        let crafted_cipher = ecb_cut_and_paste_attack(encrypt_fn);

        let profile = decrypt_profile(&crafted_cipher, &key);
        assert_eq!("admin", profile.get("role").unwrap());
    }
}
