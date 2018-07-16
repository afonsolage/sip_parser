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
    CSeq(StrValue<'a>),
    Accept(StrValue<'a>),
    UserAgent(StrValue<'a>),
    Event(StrValue<'a>),
    Allow(StrList<'a>),
    AllowEvents(StrList<'a>),
    Supported(StrList<'a>),
}

#[derive(PartialEq, Debug)]
pub struct SipMessage<'a> {
    headers: Vec<SipHeader<'a>>,
}

//Individual header parsing

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
    parse_cseq_header<SipHeader>,
    do_parse!(s: parse_str >> (SipHeader::CSeq(s)))
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
                    b"Supported" => call!(parse_supported_header) 
            )) >> (header)
    )
);

named!(
    pub parse_sip_message<SipMessage>,
    do_parse!(
        headers: many_till!(
            do_parse!(
                i: parse_sip_header
                    >> opt!(tag!("\r\n"))
                    >> (i)
            ), tag!("\r\n\r\n"))
            >> (SipMessage{headers: headers.0})
    )
);

pub fn just_test() {
    println!(
        "{:#?}",
        parse_sip_header(
            //TODO: Separate Contact into two types: URI and Contact.
            //      URI may contain params if it is enclosed with <>.
            //      If there is no <>, all params bellongs to Contact.
            b"\
        Contact: <sip:3006@192.168.10.135:5060;transport=UDP>\r\n
        \r\n\r\n"
        )
    );
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
