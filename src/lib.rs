#[macro_use]
extern crate nom;

#[derive(PartialEq, Debug)]
struct Contact<'a> {
    alias: Option<&'a str>,
    protocol: &'a str,
    extension: &'a str,
    domain: Option<&'a str>,
    port: Option<&'a str>, //TODO: Convert this to u16
    params: Vec<&'a str>,  //TODO: Convert this to a tuple?
}

fn is_space(c: char) -> bool {
    c == ' '
}

fn is_digit(c: char) -> bool {
    c.is_digit(10)
}

fn is_param_char(c: char) -> bool {
    c != ';' && c != '\r' && c != '\n'
}

named!(
    parse_contact<&str, Contact>,
    do_parse!(
        tag!("Contact")
            >> take_while_s!(is_space)
            >> tag!(":")
            >> take_while_s!(is_space)
            >> alias: opt!(
                alt_complete!(
                    delimited!(tag!("\""),take_until!("\""),tag!("\"")) | //Either get the quoted string
                    take_until!("<") //Or until there is a LT
                )
               )
            >> take_while_s!(is_space)
            >> opt!(tag!("<"))
            >> protocol: take_until_and_consume!(":")
            >> extension: take_until_either!("@>;\r\n")
            >> domain: opt!(preceded!(tag!("@"), take_until_either!(":>;\r\n")))
            >> port: opt!(preceded!(tag!(":"), take_while_s!(is_digit)))
            >> opt!(tag!(">"))
            >> opt!(tag!(";"))
            >> params: many_till!(do_parse!(p: take_while_s!(is_param_char) >> opt!(tag!(";")) >> (p)), tag!("\r\n"))
            >> (Contact { alias, protocol, extension, domain, port, params: params.0})
    )
);

pub fn just_test() {
    println!("{:#?}", parse_contact("Contact: tel:85999684700\r\n"));
}

#[cfg(test)]
mod tests {
    use super::*;

    //TODO: Add more tests? Maybe some variance of aliases, host and port with tags can give some error.

    #[test]
    fn contact_full() {
        assert_eq!(
            parse_contact("Contact: \"Alice Mark\" <sip:9989898919@127.0.0.1:35436>;tag=asdasdasdasd;some=nice\r\n"),
            Ok((
                "",
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
            parse_contact("Contact: sip:85999684700@localhost\r\n"),
            Ok((
                "",
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
            parse_contact("Contact: tel:+5585999680047\r\n"),
            Ok((
                "",
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
            parse_contact("Contact: sips:mark@localhost:3342\r\n"),
            Ok((
                "",
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
            parse_contact("Contact: <sip:8882@127.0.0.1>\r\n"),
            Ok((
                "",
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
            parse_contact("Contact: sip:admin@localhost;tag=38298391\r\n"),
            Ok((
                "",
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
