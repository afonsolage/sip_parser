#[macro_use]
extern crate nom;

mod header;
pub use header::*;

use std::str;

pub fn is_reserved_char_except(c: u8, except: &[u8]) -> bool {
    !except.contains(&c) && b"()<>@,:;\\/[]?= \t\r\n".contains(&c)
}

pub fn is_not_reserved_char_except(c: u8, exception: &[u8]) -> bool {
    !is_reserved_char_except(c, exception)
}

pub fn is_reserved_char(c: u8) -> bool {
    is_reserved_char_except(c, b"")
}

pub fn is_not_reserved_char(c: u8) -> bool {
    !is_reserved_char(c)
}

pub fn is_str_char(c: u8) -> bool {
    c != b',' && c != b';' && c != b'\r' && c != b'\n'
}

pub fn to_str<'a>(s: &'a [u8]) -> Option<&'a str> {
    str::from_utf8(s).ok().filter(|s| !s.is_empty())
}

pub fn to_str_default<'a>(s: &'a [u8]) -> &'a str {
    to_str(s).unwrap_or_default()
}
