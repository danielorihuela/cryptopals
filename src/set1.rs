pub mod challenge1;
pub mod challenge2;
pub mod challenge3;
pub mod challenge4;
pub mod challenge5;
pub mod challenge6;
pub mod challenge7;
pub mod challenge8;

#[cfg(test)]
fn read_set1_resource(filename: &str) -> String {
    use std::{fs::File, io::Read};

    let mut file = File::open(format!("resources/set1/{filename}")).expect("File should exist");
    let mut data = String::new();
    file.read_to_string(&mut data)
        .expect("File should contain valid data");

    data
}
