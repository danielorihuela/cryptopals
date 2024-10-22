use std::collections::HashMap;

pub fn detect_aes_128_ecb(data: &[Vec<u8>]) -> Option<String> {
    let mut detected_aes_line = String::new();
    let mut current_max_count = 0;
    for line in data {
        let max_count = max_repeated_block(line);
        if max_count > current_max_count {
            current_max_count = max_count;
            detected_aes_line = hex::encode(line);
        }
    }

    if detected_aes_line.is_empty() {
        None
    } else {
        Some(detected_aes_line)
    }
}

pub fn max_repeated_block(data: &[u8]) -> u128 {
    let mut count_chunks = HashMap::<Vec<u8>, u128>::new();
    for chunk in data.chunks(16) {
        *count_chunks.entry(chunk.to_vec()).or_insert(1) += 1;
    }

    count_chunks
        .into_values()
        .max()
        .expect("Have at least one element")
}

#[cfg(test)]
mod tests {
    use crate::set1::read_set1_resource;

    use super::*;

    #[test]
    fn decrypt_aes_128_ecb_works() {
        let file_data = read_set1_resource("challenge8.txt");
        let data = file_data
            .lines()
            .map(|l| hex::decode(l).unwrap())
            .collect::<Vec<Vec<u8>>>();

        assert_eq!("d880619740a8a19b7840a8a31c810a3d08649af70dc06f4fd5d2d69c744cd283e2dd052f6b641dbf9d11b0348542bb5708649af70dc06f4fd5d2d69c744cd2839475c9dfdbc1d46597949d9c7e82bf5a08649af70dc06f4fd5d2d69c744cd28397a93eab8d6aecd566489154789a6b0308649af70dc06f4fd5d2d69c744cd283d403180c98c8f6db1f2a3f9c4040deb0ab51b29933f2c123c58386b06fba186a", detect_aes_128_ecb(&data).unwrap());
    }
}
