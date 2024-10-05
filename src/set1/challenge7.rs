use aes::{
    cipher::{consts::U16, generic_array::GenericArray, BlockDecrypt, KeyInit},
    Aes128,
};

pub fn decrypt_aes_128_ecb(data: &[u8], key: &str) -> Option<String> {
    let key = GenericArray::from_slice(key.as_bytes());
    let cipher = Aes128::new(key);
    let plain = data
        .chunks(16)
        .map(|c| {
            let mut block = GenericArray::<u8, U16>::from_slice(c).clone();
            cipher.decrypt_block(&mut block);

            block
        })
        .flat_map(|b| b.to_vec())
        .collect::<Vec<u8>>();

    String::from_utf8(plain).ok()
}

#[cfg(test)]
mod tests {
    use std::{fs::File, io::Read};

    use base64::prelude::*;

    use super::*;

    #[test]
    fn decrypt_aes_128_ecb_works() {
        let mut file = File::open("set1-challenge7.txt").expect("File should exist");
        let mut buffer = String::new();
        file.read_to_string(&mut buffer)
            .expect("File should contain valid data");
        let data = buffer.lines().collect::<String>();
        let data = BASE64_STANDARD.decode(data).unwrap();

        let plain = decrypt_aes_128_ecb(&data, "YELLOW SUBMARINE").unwrap();
        assert!(plain.starts_with(
            "I'm back and I'm ringin' the bell \nA rockin' on the mike while the fly girls yell"
        ));
        assert!(plain.ends_with("Play that funky music \n\u{4}\u{4}\u{4}\u{4}"));
    }
}
