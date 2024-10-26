pub fn pkcs7_padding(data: &[u8], block_size: usize) -> Vec<u8> {
    let extra_bytes = data.len() % block_size;
    if extra_bytes == 0 {
        data.to_vec()
    } else {
        [data, &vec![0; block_size - extra_bytes]].concat()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pkcs7_padding_works() {
        assert_eq!(
            "YELLOW SUBMARINE\x00\x00\x00\x00",
            String::from_utf8(pkcs7_padding("YELLOW SUBMARINE".as_bytes(), 20)).unwrap()
        );
    }
}
