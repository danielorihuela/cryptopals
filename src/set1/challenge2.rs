use base64::prelude::*;

pub fn xor_hex(a: &str, b: &str) -> String {
    let a_bytes = hex::decode(a).expect("Valid hex data");
    let b_bytes = hex::decode(b).expect("Valid hex data");

    hex::encode(xor_bytes(&a_bytes, &b_bytes))
}

pub fn xor_base64(a: &str, b: &str) -> String {
    let a_bytes = BASE64_STANDARD.decode(a).expect("Valid base64 data");
    let b_bytes = BASE64_STANDARD.decode(b).expect("Valid base64 data");

    BASE64_STANDARD.encode(xor_bytes(&a_bytes, &b_bytes))
}

pub fn xor_bytes(a: &[u8], b: &[u8]) -> Vec<u8> {
    a.iter().zip(b).map(|(a, b)| a ^ b).collect::<Vec<u8>>()
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
