pub mod challenge10;
pub mod challenge11;
pub mod challenge12;
pub mod challenge9;

#[cfg(test)]
fn read_set2_resource(filename: &str) -> String {
    crate::read_resource("set2", filename)
}
