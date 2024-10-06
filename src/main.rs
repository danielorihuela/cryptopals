pub mod set1;
pub mod set2;

#[cfg(test)]
fn read_resource(folder: &str, filename: &str) -> String {
    use std::{fs::File, io::Read};

    let mut file = File::open(format!("resources/{folder}/{filename}")).expect("File should exist");
    let mut data = String::new();
    file.read_to_string(&mut data)
        .expect("File should contain valid data");

    data
}

fn main() {}
