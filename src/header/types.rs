use super::*;
use std::str;

#[derive(PartialEq, Debug)]
pub struct URI<'a> {
    protocol: &'a str,
    extension: &'a str,
    domain: Option<&'a str>,
    port: Option<&'a str>, //TODO: Convert this to u16
    params: Vec<&'a str>,  //TODO: Convert this to a tuple?
}

named!(
    pub parse_uri_with_params<URI>,
    do_parse!(
        tag!("<")
            >> protocol: take_until_and_consume!(":")
            >> extension: take_until_either!("@>;\r\n")
            >> domain: opt!(preceded!(tag!("@"), take_until_either!(":>;\r\n")))
            >> port: opt!(preceded!(tag!(":"), take_while!(nom::is_digit)))
            >> params: opt!(preceded!(tag!(";"), many_till!(
                do_parse!(
                    p: take_while!(is_param_char)
                        >> opt!(tag!(";"))
                        >> (p)
                ), tag!(">"))))
            >> opt!(tag!(">"))
            >> (URI{
                protocol: to_str_default(protocol),
                extension: to_str_default(extension),
                domain: domain.and_then(to_str),
                port: port.and_then(to_str),
                params: params.unwrap_or_default().0.into_iter().filter_map(to_str).collect()
            })
    )
);

named!(
    pub parse_uri<URI>,
    do_parse!(
        protocol: take_until_and_consume!(":")
            >> extension: take_until_either!("@>;\r\n")
            >> domain: opt!(preceded!(tag!("@"), take_until_either!(":>;\r\n")))
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

#[derive(PartialEq, Debug)]
pub struct ContactInfo<'a> {
    alias: Option<&'a str>,
    uri: URI<'a>,
    params: Vec<&'a str>,  //TODO: Convert this to a tuple?
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
            >> uri: alt!(call!(parse_uri_with_params) | call!(parse_uri))
            >> opt!(tag!(";"))
            >> params: many_till!(
                //Do those parses
                do_parse!(
                    p: take_while!(is_param_char) //Save the content on "p"
                        >> opt!(tag!(";")) //Remove skip semi-colon
                        >> (p) //Return p and continue
                        
                //While isn't the end
                ), peek!(one_of!(",\r\n"))) 
            >> (ContactInfo {
                    alias: alias.and_then(to_str),
                    uri,
                    params: params.0.into_iter().filter_map(to_str).collect()
                })
    )
);

#[derive(PartialEq, Debug)]
pub struct U32Value {
    pub value: u32,
}

named!(
    pub parse_u32<U32Value>,
    do_parse!(
        take_while!(is_space)
            >> d: take_while!(is_digit)
            >> (U32Value {
                    value: str::from_utf8(d).unwrap_or_default().parse::<u32>().unwrap_or_default()
                })
   )
);

#[derive(PartialEq, Debug)]
pub struct StrValue<'a> {
    pub value: &'a str,
}

impl<'a> StrValue<'a> {
    pub fn new(value: &str) -> StrValue {
        StrValue{value}
    }
}

named!(
    pub parse_str<StrValue>,
    do_parse!(
        take_while!(is_space)
            >> s: complete!(take_while!(is_str_char))
            >> (StrValue { value: str::from_utf8(s).unwrap_or_default() })
    )
);

#[derive(PartialEq, Debug)]
pub struct StrList<'a> {
    pub list: Vec<StrValue<'a>>,
}

named!(
    pub parse_str_list<StrList>,
    do_parse!(
        take_while!(is_space)
            >> list: many_till!(
                do_parse!(
                    i: parse_str
                        >> opt!(tag!(","))
                        >> (i)
                ), peek!(tag!("\r\n")))
            >> ( StrList{ list: list.0 } )
    )
);

#[cfg(test)]
mod tests {
    use super::*;

    //TODO: Add more tests?
    //Maybe some variance of aliases, host and port with tags can give some error.

    //StrList tests
    #[test]
    fn strlist_empty() {
    	assert_eq!(
    	        parse_str_list(
    	            b"\r\n"
    	        ),
    	        Ok((
    	            b"\r\n" as &[u8],
    	            StrList { list: vec![] }
    	        ))    
    	);
    }
    
    #[test]
    fn strlist() {
        assert_eq!(
            parse_str_list(
                b"INVITE, ACK, CANCEL, BYE, NOTIFY, REFER, MESSAGE, OPTIONS, INFO, SUBSCRIBE\r\n"
            ),
            Ok((
                b"\r\n" as &[u8],
                StrList { list: vec![
                    StrValue::new("INVITE"),
                    StrValue::new("ACK"),
                    StrValue::new("CANCEL"),
                    StrValue::new("BYE"),
                    StrValue::new("NOTIFY"),
                    StrValue::new("REFER"),
                    StrValue::new("MESSAGE"),
                    StrValue::new("OPTIONS"),
                    StrValue::new("INFO"),
                    StrValue::new("SUBSCRIBE"),
                ]}
            ))    
        );
    }
    
    //StrValue tests
    #[test]
    fn strvalue_comma() {
        assert_eq!(
            parse_str(
                b"some,thing\r\n"
            ),
            Ok((
                b",thing\r\n" as &[u8],
                StrValue { value: "some" }
            ))    
        );
    }
    
    #[test]
    fn strvalue() {
        assert_eq!(
            parse_str(
                b"   MDhkMTcxYjYwNzEzMjhjZWUyZDE0OTY5NGNmZjA3YzA.\r\n"
            ),
            Ok((
                b"\r\n" as &[u8],
                StrValue { value: "MDhkMTcxYjYwNzEzMjhjZWUyZDE0OTY5NGNmZjA3YzA." }
            ))    
        );
    }
    
    //U32Value tests
    #[test]
    fn u32value_invalid() {
        assert_eq!(
            parse_u32(
                b"-44\r\n"
            ),
            Ok((
                b"-44\r\n" as &[u8],
                U32Value { value: 0 }
            ))    
        );
    }

    #[test]
    fn u32value() {
        assert_eq!(
            parse_u32(
                b" 44\r\n"
            ),
            Ok((
                b"\r\n" as &[u8],
                U32Value { value: 44 }
            ))    
        );
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
                        params: vec![]
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
                        params: vec![]
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
                        params: vec![]
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
                    params:vec!["tag=aasdasd"],
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
                    params:vec![],
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
                    params:vec!["tag=d2d2"],
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
                    params:vec!["tag=d2d2"],
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
                    params:vec!["tag=d2d2"],
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
                    params:vec![],
                }
            ))
        );
    }
}
