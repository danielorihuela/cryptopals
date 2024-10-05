use super::challenge3::{break_single_xor_base64, break_single_xor_hex, DecryptMetadata};

pub fn detect_single_xor_cipher_hex(sentences: &[&str]) -> Option<DecryptMetadata> {
    detect_single_xor_cipher(sentences, break_single_xor_hex)
}

pub fn detect_single_xor_cipher_base64(sentences: &[&str]) -> Option<DecryptMetadata> {
    detect_single_xor_cipher(sentences, break_single_xor_base64)
}

fn detect_single_xor_cipher(
    sentences: &[&str],
    bruteforce_fn: fn(&str) -> DecryptMetadata,
) -> Option<DecryptMetadata> {
    let decryped_data = sentences
        .iter()
        .map(|sentence| bruteforce_fn(sentence))
        .filter(|decrypt_metadata| decrypt_metadata.key != '.')
        .min_by(|a, b| {
            a.english_similarity
                .partial_cmp(&b.english_similarity)
                .unwrap_or(std::cmp::Ordering::Greater)
        });

    decryped_data
}

#[cfg(test)]
mod tests {
    use crate::set1::read_set1_resource;

    use super::*;

    #[test]
    fn detect_single_character_xor_works() {
        let file_data = read_set1_resource("challenge4.txt");
        let lines = file_data.lines().collect::<Vec<&str>>();
        let decrypt_metadata = detect_single_xor_cipher_hex(&lines).unwrap();
        assert_eq!('5', decrypt_metadata.key);
        assert_eq!(
            "Now that the party is jumping\n".to_string(),
            decrypt_metadata.decrypted_data
        );
    }
}
