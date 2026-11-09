pub fn pkcs7_padding(data: &[u8], block_size: usize) -> Vec<u8> {
    let extra_bytes = data.len() % block_size;

    let padding_length = block_size - extra_bytes;
    [data, &vec![padding_length as u8; padding_length]].concat()
}

pub fn strip_pkcs7_padding(data: &[u8]) -> Result<Vec<u8>, String> {
    let pad_length = *data.last().expect("Exists") as usize;
    if pad_length == 0 || pad_length > data.len() {
        return Err("Invalid PKCS#7 padding".to_string());
    }

    for &byte in &data[data.len() - pad_length..] {
        if byte as usize != pad_length {
            return Err("Invalid PKCS#7 padding".to_string());
        }
    }

    Ok(data[..data.len() - pad_length].to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pkcs7_padding_works() {
        assert_eq!(
            "YELLOW SUBMARINE\x04\x04\x04\x04",
            String::from_utf8(pkcs7_padding("YELLOW SUBMARINE".as_bytes(), 20)).unwrap()
        );

        assert_eq!(
            "YELLOW SUBMARINE\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10",
            String::from_utf8(pkcs7_padding("YELLOW SUBMARINE".as_bytes(), 16)).unwrap()
        );
    }

    #[test]
    fn strip_pkcs7_padding_works() {
        assert_eq!(
            "YELLOW SUBMARINE",
            String::from_utf8(strip_pkcs7_padding(
                "YELLOW SUBMARINE\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10"
                    .as_bytes()
            ).unwrap())
            .unwrap()
        );

        assert_eq!(
            "YELLOW SUBMARINE",
            String::from_utf8(
                strip_pkcs7_padding("YELLOW SUBMARINE\x04\x04\x04\x04".as_bytes()).unwrap()
            )
            .unwrap()
        );
    }
}
