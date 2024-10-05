pub fn pkcs7_padding_bytes(data: &[u8], pad: u8, num_bytes: u8) -> Vec<u8> {
    debug_assert!(data.len() < num_bytes as usize);

    [data, &vec![pad; num_bytes as usize - data.len()]].concat()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pkcs7_padding_works() {
        assert_eq!(
            "YELLOW SUBMARINE\x04\x04\x04\x04",
            String::from_utf8(pkcs7_padding_bytes(
                "YELLOW SUBMARINE".as_bytes(),
                4 as u8,
                20
            ))
            .unwrap()
        );
    }
}
