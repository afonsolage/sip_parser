#[macro_use]
extern crate nom;

mod contact;
pub use contact::*;

use nom::*;
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

#[derive(PartialEq, Debug)]
pub struct SingleValueHeader<T> {
    value: T,
}

#[derive(PartialEq, Debug)]
pub enum SipHeader<'a, T> {
    ContactValue(Contact<'a>),
    SingleValue(SingleValueHeader<T>),
}

named!(
    pub parse_u32_header<SingleValueHeader<u32>>,
    do_parse!(
        d: take_while!(is_digit)
            >> (SingleValueHeader { value: str::from_utf8(d).unwrap_or_default().parse::<u32>().unwrap_or_default() })
   )
);

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
    println!("{:#?}", parse_u32_header(b"44\r\n"));
}
