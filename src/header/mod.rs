use nom::*;

mod types;
pub use self::types::*;

use super::*;

#[derive(PartialEq, Debug)]
pub enum SipHeader<'a> {
    Contact(ContactInfo<'a>),
    To(ContactInfo<'a>),
    From(ContactInfo<'a>),
    Expires(U32Value),
    MaxForwards(U32Value),
    ContentLength(U32Value),
    CallID(StrValue<'a>),
    Accept(StrValue<'a>),
    UserAgent(StrValue<'a>),
    Event(StrValue<'a>),
    Allow(StrList<'a>),
    AllowEvents(StrList<'a>),
    Supported(StrList<'a>),

    Via {
        protocol: &'a str,
        uri: URI<'a>,
        params: Params<'a>,
    },
    CSeq {
        seq: u32,
        header: &'a str,
    },
}

#[derive(PartialEq, Debug)]
pub enum SipMethod<'a> {
    Register {
        uri: URI<'a>,
        version: &'a str,
    },
    Invite {
        uri: URI<'a>,
        version: &'a str,
    },
    Subscribe {
        uri: URI<'a>,
        version: &'a str,
    },
    Ack {
        uri: URI<'a>,
        version: &'a str,
    },
    Cancel {
        uri: URI<'a>,
        version: &'a str,
    },
    Bye {
        uri: URI<'a>,
        version: &'a str,
    },
    Options {
        uri: URI<'a>,
        version: &'a str,
    },
    Response {
        version: &'a str,
        code: u32,
        reason: &'a str,
    },
    Unknown {
        method: &'a str,
        uri: URI<'a>,
        version: &'a str,
    },
}

impl<'a> SipMethod<'a> {
    fn new_req(method: &'a str, uri: URI<'a>, version: &'a str) -> SipMethod<'a> {
        match method {
            "REGISTER" => SipMethod::Register { uri, version },
            "INVITE" => SipMethod::Invite { uri, version },
            "ACK" => SipMethod::Ack { uri, version },
            "CANCEL" => SipMethod::Cancel { uri, version },
            "BYE" => SipMethod::Bye { uri, version },
            "OPTIONS" => SipMethod::Options { uri, version },
            _ => SipMethod::Unknown {
                method,
                uri,
                version,
            },
        }
    }
}

#[derive(PartialEq, Debug)]
pub struct SipMessage<'a> {
    method: SipMethod<'a>,
    headers: Vec<SipHeader<'a>>,
}

//Simple header parsing

named!(
    parse_supported_header<SipHeader>,
    do_parse!(list: parse_str_list >> (SipHeader::Supported(list)))
);

named!(
    parse_allow_header<SipHeader>,
    do_parse!(list: parse_str_list >> (SipHeader::Allow(list)))
);

named!(
    parse_allow_events_header<SipHeader>,
    do_parse!(list: parse_str_list >> (SipHeader::AllowEvents(list)))
);

named!(
    parse_call_id_header<SipHeader>,
    do_parse!(s: parse_str >> (SipHeader::CallID(s)))
);

named!(
    parse_accept_header<SipHeader>,
    do_parse!(s: parse_str >> (SipHeader::Accept(s)))
);

named!(
    parse_user_agent_header<SipHeader>,
    do_parse!(s: parse_str >> (SipHeader::UserAgent(s)))
);

named!(
    parse_event_header<SipHeader>,
    do_parse!(s: parse_str >> (SipHeader::Event(s)))
);

named!(
    parse_contact_header<SipHeader>,
    do_parse!(contact: parse_contact >> (SipHeader::Contact(contact)))
);

named!(
    parse_to_header<SipHeader>,
    do_parse!(contact: parse_contact >> (SipHeader::To(contact)))
);

named!(
    parse_from_header<SipHeader>,
    do_parse!(contact: parse_contact >> (SipHeader::From(contact)))
);

named!(
    parse_expires_header<SipHeader>,
    do_parse!(u32h: parse_u32 >> (SipHeader::Expires(u32h)))
);

named!(
    parse_max_forwards_header<SipHeader>,
    do_parse!(u32h: parse_u32 >> (SipHeader::MaxForwards(u32h)))
);

named!(
    parse_content_length_header<SipHeader>,
    do_parse!(u32h: parse_u32 >> (SipHeader::ContentLength(u32h)))
);

//Complex header parsing
named!(
    parse_via_header<SipHeader>,
    do_parse!(
        p: preceded!(tag!("SIP/2.0/"), take_till!(nom::is_space))
            >> tag!(" ")
            >> uri: call!(parse_uri)
            >> params: call!(parse_params) >> (SipHeader::Via {
            protocol: to_str_default(p),
            uri,
            params,
        })
    )
);

named!(
    parse_cseq_header<SipHeader>,
    do_parse!(
        s: parse_u32 >> tag!(" ") >> h: parse_str >> (SipHeader::CSeq {
            seq: s.value,
            header: h.value,
        })
    )
);

//Method parsing
named!(
    parse_sip_request<SipMethod>,
    do_parse!(
        m: complete!(take_until_and_consume!(" "))
            >> uri: parse_uri
            >> v: parse_str
            >> tag!("\r\n")
            >> (SipMethod::new_req(to_str(m).unwrap_or_default(), uri, v.value))
    )
);

//General header parsing
named!(
    parse_sip_header<SipHeader>,
    do_parse!(
        header:
            complete!(switch!(take_until_and_consume!(":"),
                              b"Contact" => call!(parse_contact_header) |
                              b"To" => call!(parse_to_header) |
                              b"From" => call!(parse_from_header) |
                              b"Expires" => call!(parse_expires_header) |
                              b"Max-Forwards" => call!(parse_max_forwards_header) |
                              b"Content-Length" => call!(parse_content_length_header) |
                              b"Call-ID" => call!(parse_call_id_header) |
                              b"CSeq" => call!(parse_cseq_header) |
                              b"Accept" => call!(parse_accept_header) |
                              b"User-Agent" => call!(parse_user_agent_header) |
                              b"Event" => call!(parse_event_header) |
                              b"Allow" => call!(parse_allow_header) |
                              b"Allow-Events" => call!(parse_allow_events_header) | 
                              b"Supported" => call!(parse_supported_header) |
                              b"Via" => call!(parse_via_header)
            )) >> (header)
    )
);

named!(
    pub parse_sip_message<SipMessage>,
    do_parse!(
        method: parse_sip_request
        >> headers: many_till!(
            do_parse!(
                i: parse_sip_header
                    >> opt!(tag!("\r\n"))
                    >> (i)
            ), tag!("\r\n\r\n"))
            >> (SipMessage{method, headers: headers.0})
    )
);

pub fn just_test() {
    let res = parse_sip_message(
        b"SUBSCRIBE sip:3006@192.168.11.223;transport=UDP SIP/2.0\r\n\
          Contact: <sip:3006@192.168.10.135:5060;transport=UDP>\r\n\
          Max-Forwards: 70\r\n\
          Contact: <sip:3006@192.168.10.135:5060;transport=UDP>\r\n\
          To: <sip:3006@192.168.11.223;transport=UDP>\r\n\
          From: <sip:3006@192.168.11.223;transport=UDP>;tag=1f2b1e7e\r\n\
          Call-ID: MDhkMTcxYjYwNzEzMjhjZWUyZDE0OTY5NGNmZjA3YzA.\r\n\
          CSeq: 1 SUBSCRIBE\r\n\
          Expires: 3600\r\n\
          Accept: application/simple-message-summary\r\n\
          Allow: INVITE, ACK, CANCEL, BYE, NOTIFY, REFER, MESSAGE, OPTIONS, INFO, SUBSCRIBE\r\n\
          Supported: replaces, norefersub, extended-refer, X-cisco-serviceuri\r\n\
          User-Agent: Zoiper for Windows 2.38 rev.16635\r\n\
          Event: message-summary\r\n\
          Allow-Events: presence, kpml\r\n\
          Content-Length: 0\r\n\
          \r\n\r\n",
    );
    /*  let res = parse_via_header(
        b"SIP/2.0/UDP 192.168.10.135:5060;branch=z9hG4bK-d8754z-05751188cc710991-1---d8754z-\r\n",
    );*/
    match res {
        Ok((remaining, header)) => println!(
            "res:\r\n{0}\r\nInfo:\r\n{1:#?}",
            str::from_utf8(remaining).unwrap_or_default(),
            header
        ),
        Err(e) => if let nom::Err::Error(c) = e {
            match c {
                nom::Context::Code(b, d) => {
                    println!(
                        "Failed to parse. Error at {0:#?}. Remaining:\r\n{1}",
                        d,
                        str::from_utf8(b).unwrap_or_default()
                    );
                }
            }
        } else {
            println!("Unkown error")
        },
    }
}

//
//Via: SIP/2.0/UDP 192.168.10.135:5060;branch=z9hG4bK-d8754z-05751188cc710991-1---d8754z-
//
/*




*/
