use super::challenge3::{decrypt_hex_single_char_key, DecryptMetadata};

pub fn detect_single_character_xor(sentences: &[&str]) -> Option<DecryptMetadata> {
    let decryped_data = sentences
        .iter()
        .map(|sentence| decrypt_hex_single_char_key(sentence))
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
    use std::{fs::File, io::Read};

    use super::*;

    #[test]
    fn detect_single_character_xor_works() {
        let mut file = File::open("set1-challenge4.txt").expect("File should exist");
        let mut buffer = String::new();
        file.read_to_string(&mut buffer)
            .expect("File should contain valid data");

        let lines = buffer.lines().collect::<Vec<&str>>();
        let decrypt_metadata = detect_single_character_xor(&lines).unwrap();
        assert_eq!('5', decrypt_metadata.key);
        assert_eq!(
            "Now that the party is jumping\n".to_string(),
            decrypt_metadata.decrypted_data
        );
    }
}
