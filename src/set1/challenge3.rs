use std::collections::HashMap;

use base64::prelude::*;

use super::challenge2::xor_bytes;

pub struct DecryptMetadata {
    pub key: char,
    pub english_similarity: f64,
    pub decrypted_data: String,
}

impl Default for DecryptMetadata {
    fn default() -> Self {
        Self {
            key: '.',
            english_similarity: f64::MAX,
            decrypted_data: String::new(),
        }
    }
}

pub fn break_single_xor_hex(data: &str) -> DecryptMetadata {
    let data = hex::decode(data).expect("Valid hex data");
    break_single_xor_bytes(&data)
}

pub fn break_single_xor_base64(data: &str) -> DecryptMetadata {
    let data = BASE64_STANDARD.decode(data).expect("Valid base64 data");
    break_single_xor_bytes(&data)
}

pub fn break_single_xor_bytes(data: &[u8]) -> DecryptMetadata {
    let mut decrypt_metadata = DecryptMetadata::default();
    for i in 0..256u16 {
        let repeating_key = vec![i as u8; data.len()];
        let xor_data = xor_bytes(data, &repeating_key);
        let Some(decrypted_data) = String::from_utf8(xor_data).ok() else {
            continue;
        };

        let characters_count = count_characters(&decrypted_data.to_ascii_lowercase());

        let ascii_data_length = decrypted_data.chars().count() as f64;
        let actual_frequencies = compute_frequencies(characters_count, ascii_data_length);

        let similarity = similarity_to_english(actual_frequencies);
        if similarity < decrypt_metadata.english_similarity {
            decrypt_metadata = DecryptMetadata {
                key: i as u8 as char,
                english_similarity: similarity,
                decrypted_data,
            };
        }
    }

    decrypt_metadata
}

fn count_characters(data: &str) -> HashMap<char, i32> {
    let mut characters_count = HashMap::new();
    for character in data.chars() {
        *characters_count.entry(character).or_insert(1) += 1;
    }

    characters_count
}

fn compute_frequencies(data: HashMap<char, i32>, total: f64) -> HashMap<char, f64> {
    let mut actual_frequencies = HashMap::new();
    for (character, count) in data.into_iter() {
        actual_frequencies.insert(character, count as f64 / total);
    }

    actual_frequencies
}

fn similarity_to_english(frequencies: HashMap<char, f64>) -> f64 {
    let expected_frequencies = HashMap::from([
        (' ', 20.0),
        ('e', 12.7),
        ('t', 9.1),
        ('a', 8.2),
        ('o', 7.5),
        ('i', 7.0),
        ('n', 6.7),
        ('s', 6.3),
        ('h', 6.1),
        ('r', 6.0),
        ('d', 4.3),
        ('l', 4.0),
        ('c', 2.8),
        ('u', 2.8),
        ('m', 2.4),
        ('w', 2.4),
        ('f', 2.2),
        ('g', 2.0),
        ('y', 2.0),
        ('p', 1.9),
        ('b', 1.5),
        ('v', 0.98),
        ('k', 0.77),
        ('x', 0.15),
        ('j', 0.15),
        ('q', 0.095),
        ('z', 0.074),
    ]);
    let mut similarity = 0f64;
    for (character, actual_frequency) in frequencies {
        if let Some(expected_frequency) = expected_frequencies.get(&character) {
            similarity += chi_squared_test(expected_frequency, &actual_frequency);
        } else {
            similarity += 10.0;
        }
    }

    similarity
}

fn chi_squared_test(expected: &f64, actual: &f64) -> f64 {
    2f64.powf(actual - expected) / expected
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bruteforce_key_works() {
        let encrypted_data = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736";
        let metadata = break_single_xor_hex(&encrypted_data);

        assert_eq!('X', metadata.key);
        assert_eq!(
            "Cooking MC's like a pound of bacon",
            metadata.decrypted_data
        );
    }
}
