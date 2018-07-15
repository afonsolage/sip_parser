#[macro_use]
extern crate nom;

mod contact;
pub use contact::*;

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

named!(
    pub parse_u32<u32>,
    map_res!(
        map_res!(nom::digit, std::str::from_utf8),
        |s: &str| s.parse::<u32>()
    )
);

#[derive(PartialEq, Debug)]
pub struct SingleValueHeader<T> {
    value: T,
}

#[derive(PartialEq, Debug)]
pub enum SipHeader<'a, T> {
    ContactValue(Contact<'a>),
    SingleValue(SingleValueHeader<T>),
}

//named!(
//    pub parse_u32_header<&str, SingleValueHeader<u32>>,
//    do_parse!(
//        v: be_u32
//        >> (SingleValueHeader { value: v })
//   )
//);

//named!(
//    pub parse_sip_header<&str, (&str, SipHeader)>,
//    do_parse!(
//        contact: switch!(take_until_and_consume!(":"),
//                         "Contact" => parse_contact |
//                         "Expires" => parse_u32_header)
//        >> ("", contact)
//    )
//);

pub fn just_test() {
    //println!("{:#?}", contact::parse_contact("tel:85999684700\r\n"));
    println!("{:#?}", parse_u32(b"44\r\n"));
}
