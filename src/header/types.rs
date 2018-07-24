use super::*;

//TODO: Convert this to a tuple?
pub type Params = Vec<String>;

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
pub struct SockAddr {
    addr: String,
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
pub struct URI {
    protocol: String,
    extension: String,
    domain: Option<String>,
    port: Option<u32>,
    params: Params,
}

named!(
    pub parse_uri_with_params<URI>,
    do_parse!(
        tag!("<")
            >> protocol: take_until_and_consume!(":")
            >> extension: take_until_either!("@>;\r\n")
            >> domain: opt!(preceded!(tag!("@"), take_until_either!(":>;\r\n")))
            >> port: opt!(preceded!(tag!(":"), parse_u32))
            >> params: call!(parse_params)
            >> tag!(">")
            >> (URI{
                protocol: to_str_default(protocol),
                extension: to_str_default(extension),
                domain: domain.and_then(to_str),
                port,
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
            >> port: opt!(preceded!(tag!(":"), parse_u32))
            >> (URI {
                protocol: to_str_default(protocol),
                extension: to_str_default(extension),
                domain: domain.and_then(to_str),
                port,
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
            >> port: opt!(preceded!(tag!(":"), parse_u32))
            >> params: call!(parse_params)
            >> opt!(tag!(">"))
            >> (URI{
                protocol: to_str_default(protocol),
                extension: to_str_default(extension),
                domain: domain.and_then(to_str),
                port,
                params,
            })
    )
);

#[derive(PartialEq, Debug)]
pub struct ContactInfo {
    alias: Option<String>,
    uri: URI,
    params: Params,
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
    pub parse_str<String>,
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
    pub parse_str_line<String>,
    do_parse!(
        take_while!(is_space)
            >> s: take_until!("\r\n")
            >> (to_str_default(s))
    )
);

named!(
    pub parse_str_list<Vec<String>>,
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
                    addr: "192.168.0.1".to_owned(),
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
                    addr: "192.168.0.1".to_owned(),
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
            Ok((
                b"\r\n" as &[u8],
                vec!["tag=a".to_owned(), "another=afonso".to_owned()]
            ))
        );
    }

    #[test]
    fn params_big() {
        assert_eq!(
            parse_params(b";branch=z9hG4bK-d8754z-05751188cc710991-1---d8754z-\r\n"),
            Ok((
                b"\r\n" as &[u8],
                vec!["branch=z9hG4bK-d8754z-05751188cc710991-1---d8754z-".to_owned()]
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
                    "INVITE".to_owned(),
                    "ACK".to_owned(),
                    "CANCEL".to_owned(),
                    "BYE".to_owned(),
                    "NOTIFY".to_owned(),
                    "REFER".to_owned(),
                    "MESSAGE".to_owned(),
                    "OPTIONS".to_owned(),
                    "INFO".to_owned(),
                    "SUBSCRIBE".to_owned(),
                ],
            ))
        );
    }

    //StrValue tests
    #[test]
    fn strvalue_comma() {
        assert_eq!(
            parse_str(b"some,thing\r\n"),
            Ok((b",thing\r\n" as &[u8], "some".to_owned()))
        );
    }

    #[test]
    fn strvalue() {
        assert_eq!(
            parse_str(b"   MDhkMTcxYjYwNzEzMjhjZWUyZDE0OTY5NGNmZjA3YzA.;tag=some\r\n"),
            Ok((
                b";tag=some\r\n" as &[u8],
                "MDhkMTcxYjYwNzEzMjhjZWUyZDE0OTY5NGNmZjA3YzA.".to_owned()
            ))
        );
    }

    #[test]
    fn strvalue_sp() {
        assert_eq!(
            parse_str(b"MDhkMTcxYjYwNzEzMjhjZWUy ZDE0OTY5NGNmZjA3YzA.\r\n"),
            Ok((
                b" ZDE0OTY5NGNmZjA3YzA.\r\n" as &[u8],
                "MDhkMTcxYjYwNzEzMjhjZWUy".to_owned()
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
                    alias: Some("Alice Mark".to_owned()),
                    uri: URI {
                        protocol: "sip".to_owned(),
                        extension: "9989898919".to_owned(),
                        domain: Some("127.0.0.1".to_owned()),
                        port: Some(35436),
                        params: vec!["transport=UDP".to_owned()]
                    },
                    params: vec!["tag=asdasdasdasd".to_owned(), "some=nice".to_owned()],
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
                        protocol: "sip".to_owned(),
                        extension: "85999684700".to_owned(),
                        domain: Some("localhost".to_owned()),
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
                        protocol: "tel".to_owned(),
                        extension: "+5585999680047".to_owned(),
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
                        protocol: "sips".to_owned(),
                        extension: "mark".to_owned(),
                        domain: Some("localhost".to_owned()),
                        port: Some(3342),
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
                        protocol: "sip".to_owned(),
                        extension: "8882".to_owned(),
                        domain: Some("127.0.0.1".to_owned()),
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
                        protocol: "sip".to_owned(),
                        extension: "admin".to_owned(),
                        domain: Some("localhost".to_owned()),
                        port: None,
                        params: vec![],
                    },
                    params: vec!["tag=38298391".to_owned()],
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
                    alias: Some("Alisson Bae".to_owned()),
                    uri: URI {
                        protocol: "sip".to_owned(),
                        extension: "asd".to_owned(),
                        domain: Some("dsds".to_owned()),
                        port: Some(33),
                        params: vec!["transport=333".to_owned()],
                    },
                    params: vec!["tag=aasdasd".to_owned()],
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
                        protocol: "sip".to_owned(),
                        extension: "ddd".to_owned(),
                        domain: Some("aaa".to_owned()),
                        port: Some(1111),
                        params: vec!["transport=UDP".to_owned()],
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
                        protocol: "sip".to_owned(),
                        extension: "afonso".to_owned(),
                        domain: Some("lage".to_owned()),
                        port: None,
                        params: vec![],
                    },
                    params: vec!["tag=d2d2".to_owned()],
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
                        protocol: "sip".to_owned(),
                        extension: "afonso".to_owned(),
                        domain: Some("lage".to_owned()),
                        port: Some(443),
                        params: vec![],
                    },
                    params: vec!["tag=d2d2".to_owned()],
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
                        protocol: "tel".to_owned(),
                        extension: "+5585999680047".to_owned(),
                        domain: None,
                        port: None,
                        params: vec![],
                    },
                    params: vec!["tag=d2d2".to_owned()],
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
                        protocol: "tel".to_owned(),
                        extension: "190".to_owned(),
                        domain: None,
                        port: None,
                        params: vec!["type=emergency".to_owned()],
                    },
                    params: vec![],
                }
            ))
        );
    }
}
