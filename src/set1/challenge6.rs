use base64::prelude::*;

use super::{challenge2::xor_bytes, challenge3::break_single_xor_bytes};

pub fn break_repeating_key_xor_hex(data: &str) -> String {
    let data = hex::decode(data).expect("Valid hex data");
    break_repeating_key_xor_bytes(&data)
}

pub fn break_repeating_key_xor_base64(data: &str) -> String {
    let data = BASE64_STANDARD.decode(data).expect("Valid base64 data");
    break_repeating_key_xor_bytes(&data)
}

pub fn break_repeating_key_xor_bytes(data: &[u8]) -> String {
    let mut keysize = 0;
    let mut norm_distance = f64::MAX;
    for i in 2..41 {
        if data.len() - 1 < 4 * i {
            continue;
        }

        let current_norm_distance = avg_hamming_distance_bytes(data, i) as f64 / i as f64;
        if current_norm_distance <= norm_distance {
            norm_distance = current_norm_distance;
            keysize = i;
        }
    }

    let data_chunks = data.chunks(keysize).collect::<Vec<&[u8]>>();
    let password = transpose(&data_chunks)
        .iter()
        .map(|chunk| break_single_xor_bytes(chunk).key)
        .collect::<String>();

    password
}

fn avg_hamming_distance_bytes(data: &[u8], keysize: usize) -> u64 {
    let n = 4;
    let sum_distances = (0..n - 1)
        .flat_map(|i| {
            (i + 1..n).map(move |j| {
                (
                    (i * keysize, (i + 1) * keysize),
                    (j * keysize, (j + 1) * keysize),
                )
            })
        })
        .map(|((a, b), (c, d))| hamming_distance_bytes(&data[a..b], &data[c..d]))
        .sum::<u64>();

    sum_distances / (6 * keysize) as u64
}

fn hamming_distance_bytes(a: &[u8], b: &[u8]) -> u64 {
    debug_assert_eq!(a.len(), b.len());

    xor_bytes(a, b)
        .iter()
        .flat_map(|byte| (0..8).map(move |i| (byte >> i) & 1))
        .filter(|b| b == &1)
        .count() as u64
}

fn transpose<T: Copy>(data: &[&[T]]) -> Vec<Vec<T>> {
    let mut transposed = vec![vec![]; data[0].len()];
    for row in data {
        for (j, &value) in row.iter().enumerate() {
            transposed[j].push(value);
        }
    }

    transposed
}

fn decrypt_repeating_xor_hex(data: &str, key: &str) -> String {
    let data_bytes = hex::decode(data).expect("Valid hex data");
    decrypt_repeating_xor_bytes(&data_bytes, key)
}

fn decrypt_repeating_xor_base64(data: &str, key: &str) -> String {
    let data_bytes = BASE64_STANDARD.decode(data).expect("Valid base64 data");
    decrypt_repeating_xor_bytes(&data_bytes, key)
}

fn decrypt_repeating_xor_bytes(data: &[u8], key: &str) -> String {
    let key_bytes = key.as_bytes();

    let xor_bytes = data
        .chunks(key_bytes.len())
        .flat_map(|chunk| xor_bytes(chunk, key_bytes))
        .collect::<Vec<u8>>();

    String::from_utf8(xor_bytes).expect("Valid decrypted data")
}

#[cfg(test)]
mod tests {
    use crate::set1::read_set1_resource;

    use super::*;

    #[test]
    fn hamming_distance_works() {
        let result =
            hamming_distance_bytes("this is a test".as_bytes(), "wokka wokka!!!".as_bytes());
        assert_eq!(37, result);
    }

    #[test]
    fn transpose_works() {
        let data: Vec<&[i32]> = vec![&[1, 2, 3, 4], &[1, 2, 3, 4], &[1, 2]];
        let expected_data = vec![vec![1, 1, 1], vec![2, 2, 2], vec![3, 3], vec![4, 4]];
        assert_eq!(expected_data, transpose(&data));
    }

    #[test]
    fn decrypt_works() {
        let file_data = read_set1_resource("challenge6.txt");
        let data = file_data.lines().collect::<String>();

        let password = break_repeating_key_xor_base64(&data);
        assert_eq!("Terminator X: Bring the noise", password);

        let decrypted_message = decrypt_repeating_xor_base64(&data, &password);
        assert_eq!("I'm back and I'm ringin' the bell \nA rockin' on the mike while the fly girls yell \nIn ecstasy in the back of me \nWell that's my DJ Deshay cuttin' all them Z's \nHittin' hard and the girlies goin' crazy \nVanilla's on the mike, man I'm not lazy. \n\nI'm lettin' my drug kick in \nIt controls my mouth and I begin \nTo just let it flow, let my concepts go \nMy posse's to the side yellin', Go Vanilla Go! \n\nSmooth 'cause that's the way I will be \nAnd if you don't give a damn, then \nWhy you starin' at me \nSo get off 'cause I control the stage \nThere's no dissin' allowed \nI'm in my own phase \nThe girlies sa y they love me and that is ok \nAnd I can dance better than any kid n' play \n\nStage 2 -- Yea the one ya' wanna listen to \nIt's off my head so let the beat play through \nSo I can funk it up and make it sound good \n1-2-3 Yo -- Knock on some wood \nFor good luck, I like my rhymes atrocious \nSupercalafragilisticexpialidocious \nI'm an effect and that you can bet \nI can take a fly girl and make her wet. \n\nI'm like Samson -- Samson to Delilah \nThere's no denyin', You can try to hang \nBut you'll keep tryin' to get my style \nOver and over, practice makes perfect \nBut not if you're a loafer. \n\nYou'll get nowhere, no place, no time, no girls \nSoon -- Oh my God, homebody, you probably eat \nSpaghetti with a spoon! Come on and say it! \n\nVIP. Vanilla Ice yep, yep, I'm comin' hard like a rhino \nIntoxicating so you stagger like a wino \nSo punks stop trying and girl stop cryin' \nVanilla Ice is sellin' and you people are buyin' \n'Cause why the freaks are jockin' like Crazy Glue \nMovin' and groovin' trying to sing along \nAll through the ghetto groovin' this here song \nNow you're amazed by the VIP posse. \n\nSteppin' so hard like a German Nazi \nStartled by the bases hittin' ground \nThere's no trippin' on mine, I'm just gettin' down \nSparkamatic, I'm hangin' tight like a fanatic \nYou trapped me once and I thought that \nYou might have it \nSo step down and lend me your ear \n'89 in my time! You, '90 is my year. \n\nYou're weakenin' fast, YO! and I can tell it \nYour body's gettin' hot, so, so I can smell it \nSo don't be mad and don't be sad \n'Cause the lyrics belong to ICE, You can call me Dad \nYou're pitchin' a fit, so step back and endure \nLet the witch doctor, Ice, do the dance to cure \nSo come up close and don't be square \nYou wanna battle me -- Anytime, anywhere \n\nYou thought that I was weak, Boy, you're dead wrong \nSo come on, everybody and sing this song \n\nSay -- Play that funky music Say, go white boy, go white boy go \nplay that funky music Go white boy, go white boy, go \nLay down and boogie and play that funky music till you die. \n\nPlay that funky music Come on, Come on, let me hear \nPlay that funky music white boy you say it, say it \nPlay that funky music A little louder now \nPlay that funky music, white boy Come on, Come on, Come on \nPlay that funky music \n", decrypted_message);
    }
}
