use super::*;
use std::str;

//TODO: Convert this to a tuple?
pub type Params<'a> = Vec<&'a str>;

named!(
    pub parse_params<Params>,
    do_parse!(
        params: opt!(preceded!(tag!(";"), many_till!(
            do_parse!(
                p: take_while!(call!(is_not_reserved_char_except, b"="))
                    >> opt!(tag!(";"))
                    >> (p)
            ), peek!(one_of!("()<>@,:;\\/?= \t\r\n")))))
        >> (params.unwrap_or_default().0.into_iter().filter_map(to_str).collect())
    )
);

#[derive(PartialEq, Debug)]
pub struct SockAddr<'a> {
    addr: &'a str,
    port: u32,
}

named!(
    pub parse_sock_addr<SockAddr>,
    do_parse!(
        s: take_until!(":")
            >> tag!(":")
            >> port: parse_u32
            >> (SockAddr{addr: to_str_default(s), port})
    )
);

#[derive(PartialEq, Debug)]
pub struct URI<'a> {
    protocol: &'a str,
    extension: &'a str,
    domain: Option<&'a str>,
    port: Option<&'a str>, //TODO: Convert this to u16
    params: Params<'a>,
}

named!(
    pub parse_uri_with_params<URI>,
    do_parse!(
        tag!("<")
            >> protocol: take_until_and_consume!(":")
            >> extension: take_until_either!("@>;\r\n")
            >> domain: opt!(preceded!(tag!("@"), take_until_either!(":>;\r\n")))
            >> port: opt!(preceded!(tag!(":"), take_while!(nom::is_digit)))
            >> params: call!(parse_params)
            >> tag!(">")
            >> (URI{
                protocol: to_str_default(protocol),
                extension: to_str_default(extension),
                domain: domain.and_then(to_str),
                port: port.and_then(to_str),
                params,
            })
    )
);

named!(
    pub parse_uri_wo_params<URI>,
    do_parse!(
        protocol: take_until_and_consume!(":")
            >> extension: take_until_either!("@>;\r\n")
            >> domain: opt!(preceded!(tag!("@"), take_till!(is_reserved_char)))
            >> port: opt!(preceded!(tag!(":"), take_while!(nom::is_digit)))
            >> (URI {
                protocol: to_str_default(protocol),
                extension: to_str_default(extension),
                domain: domain.and_then(to_str),
                port: port.and_then(to_str),
                params: vec![],
            })
    )
);

named!(
    pub parse_uri<URI>,
    do_parse!(
        opt!(tag!("<"))
            >> protocol: take_until_and_consume!(":")
            >> extension: take_until_either!("@>;\r\n")
            >> domain: opt!(preceded!(tag!("@"), take_until_either!(":>;\r\n")))
            >> port: opt!(preceded!(tag!(":"), take_while!(nom::is_digit)))
            >> params: call!(parse_params)
            >> opt!(tag!(">"))
            >> (URI{
                protocol: to_str_default(protocol),
                extension: to_str_default(extension),
                domain: domain.and_then(to_str),
                port: port.and_then(to_str),
                params,
            })
    )
);

#[derive(PartialEq, Debug)]
pub struct ContactInfo<'a> {
    alias: Option<&'a str>,
    uri: URI<'a>,
    params: Params<'a>,
}

named!(
    pub parse_contact<ContactInfo>,
    do_parse!(
            take_while_s!(nom::is_space)
            >> alias: opt!(
                alt_complete!(
                    //Either get the quoted string
                    delimited!(tag!("\""),take_until!("\""),tag!("\"")) |
                    //Or until there is a LT
                    take_until!("<") 
                ))
            >> take_while_s!(nom::is_space)
            >> uri: alt!(call!(parse_uri_with_params) | call!(parse_uri_wo_params))
            >> params: call!(parse_params)
            >> (ContactInfo {
                    alias: alias.and_then(to_str),
                    uri,
                    params,
                })
    )
);

named!(
    pub parse_u32<u32>,
    do_parse!(
        take_while!(is_space)
            >> d: take_while!(nom::is_digit)
            >> (to_str_default(d).parse::<u32>().unwrap_or_default())
   )
);

named!(
    pub parse_str<&str>,
    do_parse!(
        take_while!(is_space)
            >> s: complete!(
                alt_complete!(
                    delimited!(tag!("\""),take_until!("\""),tag!("\"")) |
                    take_till!(call!(is_any_of, b" ,;\r\n"))
                )
           )
            >> (to_str_default(s))
    )
);

named!(
    pub parse_str_line<&str>,
    do_parse!(
        take_while!(is_space)
            >> s: take_until!("\r\n")
            >> (to_str_default(s))
    )
);

named!(
    pub parse_str_list<Vec<&str>>,
    do_parse!(
        take_while!(is_space)
            >> list: many_till!(
                do_parse!(
                    i: parse_str
                        >> opt!(tag!(","))
                        >> (i)
                ), peek!(tag!("\r\n")))
            >> ( list.0 )
    )
);

//#[derive(PartialEq, Debug)]
//pub struct PairValue<'a> {
//    pub first: StrValue<'a>,
//    pub second: StrValue<'a>,
//    pub params: Params<'a>,
//}
//
//named!(
//    pub parse_sp_pair<PairValue>,
//    do_parse!(
//        take_while!(is_space)
//            >> first: parse_str
//            >> tag!(" ")
//            >> second: parse_str
//            >> params: parse_params
//            >> (PairValue{first, second, params})
//    )
//);

#[cfg(test)]
mod tests {
    use super::*;

    //SockAddr tests
    #[test]
    fn sockaddr() {
        assert_eq!(
            parse_sock_addr(b"192.168.0.1:4444\r\n"),
            Ok((
                b"\r\n" as &[u8],
                SockAddr {
                    addr: "192.168.0.1",
                    port: 4444
                }
            ))
        );
    }

    #[test]
    fn sockaddr_with_params() {
        assert_eq!(
            parse_sock_addr(b"192.168.0.1:4444;tag=some-thing\r\n"),
            Ok((
                b";tag=some-thing\r\n" as &[u8],
                SockAddr {
                    addr: "192.168.0.1",
                    port: 4444
                }
            ))
        );
    }

    //Params tests
    #[test]
    fn params() {
        assert_eq!(
            parse_params(b";tag=a;another=afonso\r\n"),
            Ok((b"\r\n" as &[u8], vec!["tag=a", "another=afonso"]))
        );
    }

    #[test]
    fn params_big() {
        assert_eq!(
            parse_params(b";branch=z9hG4bK-d8754z-05751188cc710991-1---d8754z-\r\n"),
            Ok((
                b"\r\n" as &[u8],
                vec!["branch=z9hG4bK-d8754z-05751188cc710991-1---d8754z-"]
            ))
        )
    }

    //StrList tests
    #[test]
    fn strlist_empty() {
        assert_eq!(parse_str_list(b"\r\n"), Ok((b"\r\n" as &[u8], vec![])));
    }

    #[test]
    fn strlist() {
        assert_eq!(
            parse_str_list(
                b"INVITE, ACK, CANCEL, BYE, NOTIFY, REFER, MESSAGE, OPTIONS, INFO, SUBSCRIBE\r\n"
            ),
            Ok((
                b"\r\n" as &[u8],
                vec![
                    "INVITE",
                    "ACK",
                    "CANCEL",
                    "BYE",
                    "NOTIFY",
                    "REFER",
                    "MESSAGE",
                    "OPTIONS",
                    "INFO",
                    "SUBSCRIBE",
                ],
            ))
        );
    }

    //StrValue tests
    #[test]
    fn strvalue_comma() {
        assert_eq!(
            parse_str(b"some,thing\r\n"),
            Ok((b",thing\r\n" as &[u8], "some"))
        );
    }

    #[test]
    fn strvalue() {
        assert_eq!(
            parse_str(b"   MDhkMTcxYjYwNzEzMjhjZWUyZDE0OTY5NGNmZjA3YzA.;tag=some\r\n"),
            Ok((
                b";tag=some\r\n" as &[u8],
                "MDhkMTcxYjYwNzEzMjhjZWUyZDE0OTY5NGNmZjA3YzA."
            ))
        );
    }

    #[test]
    fn strvalue_sp() {
        assert_eq!(
            parse_str(b"MDhkMTcxYjYwNzEzMjhjZWUy ZDE0OTY5NGNmZjA3YzA.\r\n"),
            Ok((
                b" ZDE0OTY5NGNmZjA3YzA.\r\n" as &[u8],
                "MDhkMTcxYjYwNzEzMjhjZWUy"
            ))
        );
    }

    //U32Value tests
    #[test]
    fn u32value_invalid() {
        assert_eq!(parse_u32(b"-44\r\n"), Ok((b"-44\r\n" as &[u8], 0)));
    }

    #[test]
    fn u32value() {
        assert_eq!(parse_u32(b" 44\r\n"), Ok((b"\r\n" as &[u8], 44)));
    }

    //Contact tests
    #[test]
    fn contact_full() {
        assert_eq!(
            parse_contact(
                b"\"Alice Mark\" <sip:9989898919@127.0.0.1:35436;transport=UDP>;tag=asdasdasdasd;some=nice\r\n"
            ),
            Ok((
                b"\r\n" as &[u8],
                ContactInfo {
                    alias: Some("Alice Mark"),
                    uri: URI {
                        protocol: "sip",
                        extension: "9989898919",
                        domain: Some("127.0.0.1"),
                        port: Some("35436"),
                        params: vec!["transport=UDP"]
                    },
                    params: vec!["tag=asdasdasdasd", "some=nice"],
                }
            ))
        );
    }

    #[test]
    fn contact_no_alias() {
        assert_eq!(
            parse_contact(b"sip:85999684700@localhost\r\n"),
            Ok((
                b"\r\n" as &[u8],
                ContactInfo {
                    alias: None,
                    uri: URI {
                        protocol: "sip",
                        extension: "85999684700",
                        domain: Some("localhost"),
                        port: None,
                        params: vec![],
                    },
                    params: vec![],
                }
            ))
        );
    }

    #[test]
    fn contact_no_host() {
        assert_eq!(
            parse_contact(b"tel:+5585999680047\r\n"),
            Ok((
                b"\r\n" as &[u8],
                ContactInfo {
                    alias: None,
                    uri: URI {
                        protocol: "tel",
                        extension: "+5585999680047",
                        domain: None,
                        port: None,
                        params: vec![],
                    },
                    params: vec![],
                }
            ))
        );
    }

    #[test]
    fn contact_host_with_port() {
        assert_eq!(
            parse_contact(b"sips:mark@localhost:3342\r\n"),
            Ok((
                b"\r\n" as &[u8],
                ContactInfo {
                    alias: None,
                    uri: URI {
                        protocol: "sips",
                        extension: "mark",
                        domain: Some("localhost"),
                        port: Some("3342"),
                        params: vec![],
                    },
                    params: vec![],
                }
            ))
        );
    }

    #[test]
    fn contact_alias_empty() {
        assert_eq!(
            parse_contact(b"<sip:8882@127.0.0.1>\r\n"),
            Ok((
                b"\r\n" as &[u8],
                ContactInfo {
                    alias: None,
                    uri: URI {
                        protocol: "sip",
                        extension: "8882",
                        domain: Some("127.0.0.1"),
                        port: None,
                        params: vec![],
                    },
                    params: vec![],
                }
            ))
        );
    }

    #[test]
    fn contact_with_params() {
        assert_eq!(
            parse_contact(b"sip:admin@localhost;tag=38298391\r\n"),
            Ok((
                b"\r\n" as &[u8],
                ContactInfo {
                    alias: None,
                    uri: URI {
                        protocol: "sip",
                        extension: "admin",
                        domain: Some("localhost"),
                        port: None,
                        params: vec![],
                    },
                    params: vec!["tag=38298391"],
                }
            ))
        );
    }

    #[test]
    fn contact_uri_params() {
        assert_eq!(
            parse_contact(b"\"Alisson Bae\" <sip:asd@dsds:33;transport=333>;tag=aasdasd\r\n"),
            Ok((
                b"\r\n" as &[u8],
                ContactInfo {
                    alias: Some("Alisson Bae"),
                    uri: URI {
                        protocol: "sip",
                        extension: "asd",
                        domain: Some("dsds"),
                        port: Some("33"),
                        params: vec!["transport=333"],
                    },
                    params: vec!["tag=aasdasd"],
                }
            ))
        );
    }

    #[test]
    fn contact_uri_params_only() {
        assert_eq!(
            parse_contact(b"<sip:ddd@aaa:1111;transport=UDP>\r\n"),
            Ok((
                b"\r\n" as &[u8],
                ContactInfo {
                    alias: None,
                    uri: URI {
                        protocol: "sip",
                        extension: "ddd",
                        domain: Some("aaa"),
                        port: Some("1111"),
                        params: vec!["transport=UDP"],
                    },
                    params: vec![],
                }
            ))
        );
    }

    #[test]
    fn contact_no_alias_with_params() {
        assert_eq!(
            parse_contact(b"sip:afonso@lage;tag=d2d2\r\n"),
            Ok((
                b"\r\n" as &[u8],
                ContactInfo {
                    alias: None,
                    uri: URI {
                        protocol: "sip",
                        extension: "afonso",
                        domain: Some("lage"),
                        port: None,
                        params: vec![],
                    },
                    params: vec!["tag=d2d2"],
                }
            ))
        );
    }

    #[test]
    fn contact_no_alias_w_port_n_params() {
        assert_eq!(
            parse_contact(b"sip:afonso@lage:443;tag=d2d2\r\n"),
            Ok((
                b"\r\n" as &[u8],
                ContactInfo {
                    alias: None,
                    uri: URI {
                        protocol: "sip",
                        extension: "afonso",
                        domain: Some("lage"),
                        port: Some("443"),
                        params: vec![],
                    },
                    params: vec!["tag=d2d2"],
                }
            ))
        );
    }

    #[test]
    fn contact_no_alias_no_host_w_params() {
        assert_eq!(
            parse_contact(b"tel:+5585999680047;tag=d2d2\r\n"),
            Ok((
                b"\r\n" as &[u8],
                ContactInfo {
                    alias: None,
                    uri: URI {
                        protocol: "tel",
                        extension: "+5585999680047",
                        domain: None,
                        port: None,
                        params: vec![],
                    },
                    params: vec!["tag=d2d2"],
                }
            ))
        );
    }

    #[test]
    fn contact_no_alias_no_port_w_uri_params() {
        assert_eq!(
            parse_contact(b"<tel:190;type=emergency>\r\n"),
            Ok((
                b"\r\n" as &[u8],
                ContactInfo {
                    alias: None,
                    uri: URI {
                        protocol: "tel",
                        extension: "190",
                        domain: None,
                        port: None,
                        params: vec!["type=emergency"],
                    },
                    params: vec![],
                }
            ))
        );
    }
}
