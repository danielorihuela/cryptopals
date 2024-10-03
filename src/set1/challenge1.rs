use base64::prelude::*;

pub fn hex_to_base64(data: &str) -> String {
    let bytes = hex::decode(data).expect("Inputed data should be valid");
    BASE64_STANDARD.encode(bytes)
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn hex_to_base64_works() {
        let hex = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d";
        let expected_base64 = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t";
        assert_eq!(expected_base64, hex_to_base64(hex));
    }
}
