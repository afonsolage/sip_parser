use super::*;
use std::str;

#[derive(PartialEq, Debug)]
pub struct Contact<'a> {
    alias: Option<&'a str>,
    protocol: &'a str,
    extension: &'a str,
    domain: Option<&'a str>,
    port: Option<&'a str>, //TODO: Convert this to u16
    params: Vec<&'a str>,  //TODO: Convert this to a tuple?
}

named!(
    pub parse_contact<Contact>,
    do_parse!(
            alias: opt!(
                alt_complete!(
                    //Either get the quoted string
                    delimited!(tag!("\""),take_until!("\""),tag!("\"")) |
                    //Or until there is a LT
                    take_until!("<") 
                ))
            >> take_while_s!(nom::is_space)
            >> opt!(tag!("<"))
            >> protocol: take_until_and_consume!(":")
            >> extension: take_until_either!("@>;\r\n")
            >> domain: opt!(preceded!(tag!("@"), take_until_either!(":>;\r\n")))
            >> port: opt!(preceded!(tag!(":"), take_while!(nom::is_digit)))
            >> opt!(tag!(">"))
            >> opt!(tag!(";"))
            >> params: many_till!(
                //Do those parses
                do_parse!(
                    p: take_while!(is_param_char) //Save the content on "p"
                        >> opt!(tag!(";")) //Remove skip semi-colon
                        >> (p) //Return p and continue
                        
                //While isn't the end
                ), tag!("\r\n")) 
            >> (Contact {
                    alias: alias.and_then(to_str),
                    protocol: to_str_default(protocol),
                    extension: to_str_default(extension),
                    domain: domain.and_then(to_str),
                    port: port.and_then(to_str),
                    params: params.0.into_iter().filter_map(to_str).collect()
                })
    )
);

#[derive(PartialEq, Debug)]
pub struct U32Header {
    pub value: u32,
}

#[cfg(test)]
mod tests {
    use super::*;

    //TODO: Add more tests?
    //Maybe some variance of aliases, host and port with tags can give some error.

    #[test]
    fn contact_full() {
        assert_eq!(
            parse_contact(
                b"\"Alice Mark\" <sip:9989898919@127.0.0.1:35436>;tag=asdasdasdasd;some=nice\r\n"
            ),
            Ok((
                b"" as &[u8],
                Contact {
                    alias: Some("Alice Mark"),
                    protocol: "sip",
                    extension: "9989898919",
                    domain: Some("127.0.0.1"),
                    port: Some("35436"),
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
                b"" as &[u8],
                Contact {
                    alias: None,
                    protocol: "sip",
                    extension: "85999684700",
                    domain: Some("localhost"),
                    port: None,
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
                b"" as &[u8],
                Contact {
                    alias: None,
                    protocol: "tel",
                    extension: "+5585999680047",
                    domain: None,
                    port: None,
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
                b"" as &[u8],
                Contact {
                    alias: None,
                    protocol: "sips",
                    extension: "mark",
                    domain: Some("localhost"),
                    port: Some("3342"),
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
                b"" as &[u8],
                Contact {
                    alias: Some(""),
                    protocol: "sip",
                    extension: "8882",
                    domain: Some("127.0.0.1"),
                    port: None,
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
                b"" as &[u8],
                Contact {
                    alias: None,
                    protocol: "sip",
                    extension: "admin",
                    domain: Some("localhost"),
                    port: None,
                    params: vec!["tag=38298391"],
                }
            ))
        );
    }
}
