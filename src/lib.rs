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
pub struct U32Header {
    value: u32,
}

#[derive(PartialEq, Debug)]
pub enum SipHeader<'a> {
    ContactHeader(Contact<'a>),
    U32Value(U32Header),
}

named!(
    pub parse_u32_header<SipHeader>,
    do_parse!(
        take_while!(is_space)
            >> d: take_while!(is_digit)
            >> (SipHeader::U32Value(
                U32Header {
                    value: str::from_utf8(d).unwrap_or_default().parse::<u32>().unwrap_or_default()
                }))
   )
);

named!(
    pub parse_sip_header<SipHeader>,
    do_parse!(
        header: complete!(
            switch!(take_until_and_consume!(":"),
                    b"Contact" => call!(parse_contact) |
                    b"Expires" => call!(parse_u32_header))
            )
        >> (header)
    )
);

pub fn just_test() {
    println!("{:#?}", parse_sip_header(b"Expires: 33\r\n"));
}

//SUBSCRIBE sip:3006@192.168.11.223;transport=UDP SIP/2.0
//Via: SIP/2.0/UDP 192.168.10.135:5060;branch=z9hG4bK-d8754z-05751188cc710991-1---d8754z-
//Max-Forwards: 70
//Contact: <sip:3006@192.168.10.135:5060;transport=UDP>
//To: <sip:3006@192.168.11.223;transport=UDP>
//From: <sip:3006@192.168.11.223;transport=UDP>;tag=1f2b1e7e
//Call-ID: MDhkMTcxYjYwNzEzMjhjZWUyZDE0OTY5NGNmZjA3YzA.
//CSeq: 1 SUBSCRIBE
//Expires: 3600
//Accept: application/simple-message-summary
//Allow: INVITE, ACK, CANCEL, BYE, NOTIFY, REFER, MESSAGE, OPTIONS, INFO, SUBSCRIBE
//Supported: replaces, norefersub, extended-refer, X-cisco-serviceuri
//User-Agent: Zoiper for Windows 2.38 rev.16635
//Event: message-summary
//Allow-Events: presence, kpml
//Content-Length: 0
