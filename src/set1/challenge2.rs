pub fn xor_hex(a: &str, b: &str) -> String {
    let a_bytes = hex::decode(a).expect("Inputed data should be valid");
    let b_bytes = hex::decode(b).expect("Inputed data should be valid");
    let xor_bytes = a_bytes
        .iter()
        .zip(b_bytes)
        .map(|(a, b)| a ^ b)
        .collect::<Vec<u8>>();

    hex::encode(xor_bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn xor_hex_works() {
        let a_hex = "1c0111001f010100061a024b53535009181c";
        let b_hex = "686974207468652062756c6c277320657965";
        let expected_xor = "746865206b696420646f6e277420706c6179";
        assert_eq!(expected_xor, xor_hex(a_hex, b_hex));
    }
}
