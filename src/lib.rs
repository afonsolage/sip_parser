#[macro_use]
extern crate nom;
#[macro_use]
extern crate failure;

mod header;
pub use header::*;

pub fn is_reserved_char_except(c: u8, except: &[u8]) -> bool {
    !except.contains(&c) && b"()<>@,:;\\/?= \t\r\n".contains(&c)
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

pub fn is_any_of(c: u8, s: &[u8]) -> bool {
    s.contains(&c)
}

pub fn to_str(s: &[u8]) -> Option<String> {
    String::from_utf8(s.to_vec()).ok().filter(|s| !s.is_empty())
}

pub fn to_str_default(s: &[u8]) -> String {
    to_str(s).unwrap_or_default()
}

pub fn to_str_dbg(data: &[u8]) -> String {
    to_str_default(data).replace("\r\n", "\\r\\n\r\n")
}
