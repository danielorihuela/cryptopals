#[derive(Debug)]
pub struct PaddingError;

impl std::fmt::Display for PaddingError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "Invalid PKCS#7 padding")
    }
}

pub fn strip_pkcs7_padding_strict(data: &[u8]) -> Result<Vec<u8>, PaddingError> {
    let pad_length = *data.last().expect("Exists") as usize;
    for &byte in data.iter().rev().take(pad_length) {
        if byte != pad_length as u8 {
            return Err(PaddingError);
        }
    }

    Ok(data[..data.len() - pad_length].to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strip_pkcs7_padding_strict_works() {
        let result = strip_pkcs7_padding_strict(
            "YELLOW SUBMARINE\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10"
                .as_bytes(),
        );
        assert_eq!(
            "YELLOW SUBMARINE",
            String::from_utf8(result.unwrap()).unwrap()
        );
    }

    #[test]
    fn strip_pkcs7_padding_strict_throws_error() {
        let result = strip_pkcs7_padding_strict("YELLOW SUBMARINE\x01\x02\x03\x04".as_bytes());
        assert!(result.is_err());
    }
}
