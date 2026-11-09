use crate::{set1::challenge2::xor_bytes, set2::challenge9::strip_pkcs7_padding};

pub fn cbc_padding_oracle_attack<D>(ciphertext: &[u8], iv: &[u8], decrypt_fn: D) -> Vec<u8>
where
    D: Fn(&[u8]) -> bool,
{
    let data: Vec<u8> = [iv, ciphertext].concat();
    let num_blocks = data.len() / 16;

    let mut plaintext = vec![];
    for i in (1..num_blocks).rev() {
        let intermediate = compute_intermediate_block(&decrypt_fn, &data[block_range(i)]);
        let plaintext_block = xor_bytes(&intermediate, &data[block_range(i - 1)]);
        plaintext = [plaintext_block, plaintext].concat();
    }

    strip_pkcs7_padding(&plaintext).unwrap()
}

fn block_range(block_index: usize) -> std::ops::Range<usize> {
    (block_index * 16)..((block_index + 1) * 16)
}

fn compute_intermediate_block<D>(decrypt_fn: D, block: &[u8]) -> Vec<u8>
where
    D: Fn(&[u8]) -> bool,
{
    let mut crafted_block = vec![0u8; 16];
    let mut intermediate = vec![0u8; 16];

    for i in (0..16).rev() {
        for j in 0..256u16 {
            crafted_block[i] = j as u8;
            if decrypt_fn(&[&crafted_block, block].concat()) {
                if i == 15 {
                    crafted_block[14] ^= 1;
                    if !decrypt_fn(&[&crafted_block, block].concat()) {
                        continue;
                    }
                }
                intermediate[i] = crafted_block[i] ^ (16 - i) as u8;
                if i > 0 {
                    for j in (i..16).rev() {
                        crafted_block[j] = intermediate[j] ^ (16 - i + 1) as u8;
                    }
                }
                break;
            }
        }
    }

    intermediate
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::seq::IndexedRandom;

    use crate::{
        set2::{challenge10::encrypt_aes_128_cbc, challenge11::random_bytes},
        set3::read_set3_resource,
    };

    #[test]
    fn test_cbc_padding_oracle() {
        let data = read_set3_resource("challenge17.txt");
        let messages = data.lines().collect::<Vec<_>>();
        let message = messages.choose(&mut rand::rng()).unwrap();

        let key = random_bytes(16);
        let iv = random_bytes(16);

        let ciphertext = encrypt_aes_128_cbc(message.as_bytes(), &key, Some(iv.clone()));

        let decrypt_fn = |ciphertext: &[u8]| {
            crate::set2::challenge10::decrypt_aes_128_cbc(ciphertext, &key, Some(iv.clone()))
                .is_ok()
        };

        let plaintext = cbc_padding_oracle_attack(&ciphertext, &iv, decrypt_fn);
        assert_eq!(plaintext, message.as_bytes());
    }
}
