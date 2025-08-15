use std::fmt::{Write, Result};

pub struct TuskWrite;

impl Write for TuskWrite {
    fn write_str(&mut self, s: &str) -> Result {
        Ok(print!("{}", s))
    }
}
