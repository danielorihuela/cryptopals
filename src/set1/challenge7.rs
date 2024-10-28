use aes::{
    cipher::{consts::U16, generic_array::GenericArray, BlockDecrypt, KeyInit},
    Aes128,
};

use crate::set2::challenge9::strip_pkcs7_padding;

pub fn decrypt_aes_128_ecb(data: &[u8], key: &[u8]) -> Option<String> {
    let key = GenericArray::from_slice(key);
    let cipher = Aes128::new(key);
    let plain = data
        .chunks(16)
        .map(|c| {
            let mut block = *GenericArray::<u8, U16>::from_slice(c);
            cipher.decrypt_block(&mut block);

            block
        })
        .flat_map(|b| b.to_vec())
        .collect::<Vec<u8>>();
    let plain = strip_pkcs7_padding(&plain);

    String::from_utf8(plain).ok()
}

#[cfg(test)]
mod tests {
    use base64::prelude::*;

    use crate::set1::read_set1_resource;

    use super::*;

    #[test]
    fn decrypt_aes_128_ecb_works() {
        let file_data = read_set1_resource("challenge7.txt");
        let data = file_data.lines().collect::<String>();
        let data = BASE64_STANDARD.decode(data).unwrap();

        let plain = decrypt_aes_128_ecb(&data, "YELLOW SUBMARINE".as_bytes()).unwrap();
        assert!(plain.starts_with(
            "I'm back and I'm ringin' the bell \nA rockin' on the mike while the fly girls yell"
        ));
        assert!(plain.ends_with("Play that funky music \n"));
    }
}
