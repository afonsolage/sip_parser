#[macro_use]
extern crate nom;

mod header;
pub use header::*;

use std::str;

pub fn is_param_char(c: u8) -> bool {
    c != b';' && c != b'\r' && c != b'\n'
}

pub fn to_str<'a>(s: &'a [u8]) -> Option<&'a str> {
    str::from_utf8(s).ok()
}

pub fn to_str_default<'a>(s: &'a [u8]) -> &'a str {
    to_str(s).unwrap_or_default()
}
