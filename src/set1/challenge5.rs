pub fn encrypt_to_hex(data: &str, key: &str) -> String {
    let data_bytes = data.as_bytes();
    let key_bytes = key.as_bytes();

    let xor_bytes = data_bytes
        .chunks(key_bytes.len())
        .flat_map(|chunk| xor_bytes(chunk, key_bytes))
        .collect::<Vec<u8>>();

    hex::encode(xor_bytes)
}

fn xor_bytes(a: &[u8], b: &[u8]) -> Vec<u8> {
    a.iter()
        .zip(b.iter())
        .map(|(a, b)| a ^ b)
        .collect::<Vec<u8>>()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encrypt_works() {
        let data = "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal";
        let key = "ICE";
        let expected_encrypted_data =
            "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f";

        assert_eq!(expected_encrypted_data, encrypt_to_hex(data, key));
    }
}
