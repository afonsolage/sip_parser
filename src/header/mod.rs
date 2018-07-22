use nom::*;

mod types;
pub use self::types::*;

use super::*;
use std::fmt;
use std::io::Read;

type SipResult<T> = Result<T, MessageParserError>;

#[derive(PartialEq, Debug)]
pub enum SipHeader<'a> {
    Contact(ContactInfo<'a>),
    To(ContactInfo<'a>),
    From(ContactInfo<'a>),
    Expires(u32),
    MaxForwards(u32),
    ContentLength(u32),
    CallID(&'a str),
    Accept(&'a str),
    UserAgent(&'a str),
    Event(&'a str),
    Allow(Vec<&'a str>),
    AllowEvents(Vec<&'a str>),
    Supported(Vec<&'a str>),
    Authorization(Vec<&'a str>),
    WWWAuthenticate(Vec<&'a str>),
    SessionID(&'a str),
    Server(&'a str),
    Date(&'a str),
    ContentType(&'a str),
    Require(Vec<&'a str>),
    AcceptLanguage(&'a str),

    MinSE(u32), //Minimum value for Session-Expires
    SessionExpires {
        value: u32,
        params: Params<'a>,
    },

    Via {
        protocol: &'a str,
        addr: SockAddr<'a>,
        params: Params<'a>,
    },
    CSeq {
        seq: u32,
        header: &'a str,
    },

    Unknown {
        name: &'a str,
        value: &'a str,
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
            "SUBSCRIBE" => SipMethod::Subscribe { uri, version },
            _ => SipMethod::Unknown {
                method,
                uri,
                version,
            },
        }
    }
}

#[derive(Debug, Fail)]
enum MessageParserError {
    #[fail(
        display = "Error at parsing near: {}. Remaining: {1}",
        detail,
        remaining
    )]
    Parse { detail: String, remaining: String },

    #[fail(display = "IO Error: {}", error)]
    IO { error: std::io::Error },

    #[fail(display = "EOF Reached!")]
    EOF,
}

impl From<std::io::Error> for MessageParserError {
    fn from(error: std::io::Error) -> Self {
        MessageParserError::IO { error }
    }
}

impl<'a> From<nom::Err<&'a [u8]>> for MessageParserError {
    fn from(error: nom::Err<&'a [u8]>) -> Self {
        if let nom::Err::Error(c) = error {
            match c {
                nom::Context::Code(remaining, detail) => MessageParserError::Parse {
                    remaining: to_str_default(remaining).to_string(),
                    detail: detail.description().to_string(),
                },
            }
        } else {
            MessageParserError::Parse {
                detail: String::from("Unkown Error"),
                remaining: String::from(""),
            }
        }
    }
}

pub struct SipMessage<'a> {
    buffer: Vec<u8>,
    pub method: SipMethod<'a>,
    pub headers: Vec<SipHeader<'a>>,
    pub content: Vec<&'a str>,
}

impl<'a> SipMessage<'a> {
    /*    fn new(data: &[u8]) -> Self {
        let buffer = data.to_vec();
        let method = 
    }*/
}

impl<'a> fmt::Debug for SipMessage<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "SipMessage {{ method: {0:#?}, headers: {1:#?}, content: {2:#?} }}",
            self.method, self.headers, self.content
        )
    }
}

impl<'a> fmt::Display for SipMessage<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "SipMessage {{ method: {0:?}, headers: {1:?}, content: {2:?} }}",
            self.method, self.headers, self.content
        )
    }
}
/*
struct MessageParser<'a, R: 'a> {
    buffer: [u8; 1024],
    index: usize,
    bytes: std::io::Bytes<R>,
    _p: std::marker::PhantomData<&'a R>, //Need to use a phantomdata, since we need a life time to return SipMessages
}

impl<'a, R: Read> MessageParser<'a, R> {
    fn new(stream: R) -> MessageParser<'a, R> {
        MessageParser {
            buffer: [0; 1024],
            index: 0,
            bytes: stream.bytes(),
            _p: std::marker::PhantomData,
        }
    }

    fn read_until(&mut self, delim: &[u8]) -> SipResult<usize> {
        let mut read_count = 0;

        while let Some(byte) = self.bytes.next() {
            self.buffer[self.index] = byte?;
            self.index += 1;
            read_count += 1;

            if read_count > delim.len() {
                let len = delim.len();
                if delim == &self.buffer[self.index - len..len] {
                    return Ok(read_count);
                }
            }
        }

        Err(MessageParserError::EOF)
    }

    fn read_method(&mut self) -> SipResult<SipMethod<'a>> {
        let rc = self.read_until(b"\r\n")?;

        let res = parse_sip_method(&self.buffer[self.index..rc])?;

        self.index += rc;
        Ok(res.1)
    }

    fn read_headers(&'a mut self) -> SipResult<Vec<SipHeader<'a>>> {
        let rc = self.read_until(b"\r\n\r\n")?;

        let res = parse_sip_headers(&self.buffer[self.index..rc])?;

        self.index += rc;
        Ok(res.1)
    }
}

impl<'a, R: Read> MessageParser<'a, R> {
    fn get_next(&'a mut self) -> SipResult<SipMessage<'a>> {
        self.index = 0;

        let method = self.read_method()?;

        let headers = self.read_headers()?;

        Err(MessageParserError::EOF)
    }
}

impl<'a, R> Iterator for MessageParser<'a, R> {
    type Item = SipMessage<'a>;

    fn next(&mut self) -> Option<SipMessage<'a>> {
        None
    }
}
*/
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
    parse_require_header<SipHeader>,
    do_parse!(list: parse_str_list >> (SipHeader::Require(list)))
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
    do_parse!(s: take_until!("\r\n") >> (SipHeader::UserAgent(to_str(s).unwrap_or_default())))
);

named!(
    parse_session_id_header<SipHeader>,
    do_parse!(s: take_until!("\r\n") >> (SipHeader::SessionID(to_str(s).unwrap_or_default())))
);

named!(
    parse_server_header<SipHeader>,
    do_parse!(s: take_until!("\r\n") >> (SipHeader::Server(to_str(s).unwrap_or_default())))
);

named!(
    parse_date_header<SipHeader>,
    do_parse!(s: take_until!("\r\n") >> (SipHeader::Date(to_str(s).unwrap_or_default())))
);

named!(
    parse_content_type_header<SipHeader>,
    do_parse!(s: take_until!("\r\n") >> (SipHeader::ContentType(to_str(s).unwrap_or_default())))
);

named!(
    parse_session_expires_header<SipHeader>,
    do_parse!(
        value: parse_u32 >> params: parse_params >> (SipHeader::SessionExpires { value, params })
    )
);

named!(
    parse_accept_language_header<SipHeader>,
    do_parse!(s: take_until!("\r\n") >> (SipHeader::AcceptLanguage(to_str(s).unwrap_or_default())))
);

named!(
    parse_min_se_header<SipHeader>,
    do_parse!(u: parse_u32 >> (SipHeader::MinSE(u)))
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
        take_while!(nom::is_space)
            >> p: preceded!(tag!("SIP/2.0/"), take_till!(nom::is_space))
            >> tag!(" ")
            >> addr: call!(parse_sock_addr)
            >> params: call!(parse_params) >> (SipHeader::Via {
            protocol: to_str_default(p),
            addr,
            params,
        })
    )
);

named!(
    parse_cseq_header<SipHeader>,
    do_parse!(s: parse_u32 >> tag!(" ") >> h: parse_str >> (SipHeader::CSeq { seq: s, header: h }))
);

named!(
    parse_authorization_header<SipHeader>,
    do_parse!(
        opt!(take_while!(nom::is_space))
            >> tag!("Digest ")
            >> l: parse_str_list
            >> (SipHeader::Authorization(l))
    )
);

named!(
    parse_www_authenticate_header<SipHeader>,
    do_parse!(
        opt!(take_while!(nom::is_space))
            >> tag!("Digest ")
            >> l: parse_str_list
            >> (SipHeader::WWWAuthenticate(l))
    )
);

//Method parsing
named!(
    parse_sip_method<SipMethod>,
    alt_complete!(parse_sip_response | parse_sip_request)
);

named!(
    parse_sip_request<SipMethod>,
    do_parse!(
        m: complete!(take_until_and_consume!(" "))
            >> uri: parse_uri
            >> v: parse_str
            >> tag!("\r\n")
            >> (SipMethod::new_req(to_str(m).unwrap_or_default(), uri, v))
    )
);

named!(
    parse_sip_response<SipMethod>,
    do_parse!(
        version: parse_str
            >> tag!(" ")
            >> code: parse_u32
            >> tag!(" ")
            >> reason: parse_str_line
            >> tag!("\r\n") >> (SipMethod::Response {
            version,
            code,
            reason,
        })
    )
);

//General header parsing
named!(
    parse_sip_header<SipHeader>,
    do_parse!(
        take_while!(nom::is_space) >> name: take_until_and_consume!(":")
            >> header:
                complete!(switch!(value!(name),
                              b"Contact" => call!(parse_contact_header)
                              | b"To" => call!(parse_to_header)
                              | b"From" => call!(parse_from_header)
                              | b"Expires" => call!(parse_expires_header)
                              | b"Max-Forwards" => call!(parse_max_forwards_header)
                              | b"Content-Length" => call!(parse_content_length_header)
                              | b"Call-ID" => call!(parse_call_id_header)
                              | b"CSeq" => call!(parse_cseq_header)
                              | b"Accept" => call!(parse_accept_header)
                              | b"User-Agent" => call!(parse_user_agent_header)
                              | b"Event" => call!(parse_event_header)
                              | b"Allow" => call!(parse_allow_header)
                              | b"Allow-Events" => call!(parse_allow_events_header)
                              | b"Via" => call!(parse_via_header)
                              | b"Supported" => call!(parse_supported_header)
                              | b"Authorization" => call!(parse_authorization_header)
                              | b"Session-ID" => call!(parse_session_id_header)
                              | b"Server" => call!(parse_server_header)
                              | b"WWW-Authenticate" => call!(parse_www_authenticate_header)
                              | b"Date" => call!(parse_date_header)
                              | b"Content-Type" => call!(parse_content_type_header)
                              | b"Session-Expires" => call!(parse_session_expires_header)
                              | b"Require" => call!(parse_require_header)
                              | b"Accept-Language" => call!(parse_accept_language_header)
                              | b"Min-SE" => call!(parse_min_se_header)
                              | _ => do_parse!(
                                  value: parse_str_line
                                      >> (SipHeader::Unknown{name: to_str_default(name), value})
                              )
            )) >> (header)
    )
);

named!(
    parse_sip_headers<Vec<SipHeader>>,
    do_parse!(
        h: many_till!(
            do_parse!(i: parse_sip_header >> opt!(tag!("\r\n")) >> (i)),
            tag!("\r\n")
        ) >> (h.0)
    )
);

/*
pub fn just_test() {
    //    test_message();
    test_messages();
}

fn test_messages() {
    use std::fs::File;
    use std::io::{BufReader, Read};

    let f = File::open("test_data/messages.log").expect("Failed to open messages.log file");
    let bytes = BufReader::new(f).bytes();
    let mut buffer = vec![0u8; 1024];

    let mut i = 0;
    for byte in bytes {
        buffer[i] = byte.unwrap();
        i += 1;

        if i == 2 && buffer[0] == b'\r' && buffer[1] == b'\n' {
            i = 0;
        }

        if i > 6
            && buffer[i - 6] == b'\r'
            && buffer[i - 5] == b'\n'
            && buffer[i - 4] == b'\r'
            && buffer[i - 3] == b'\n'
            && buffer[i - 2] == b'\r'
            && buffer[i - 1] == b'\n'
        {
            //            println!("Testing data:\r\n{}", to_str_dbg(&buffer[0..i]));
            test_parse(&buffer[0..i]);
            i = 0;
        }
    }
}

fn test_parse(data: &[u8]) {
    let res = parse_sip_message(data);
    match res {
        Ok((_remaining, _msg)) => {
            if let SipMethod::Unknown {
                method: _,
                uri: _,
                version: _,
            } = &_msg.method
            {
                println!(
                    "res:\r\n{0}\r\nInfo:\r\n{1:?}",
                    str::from_utf8(_remaining).unwrap_or_default(),
                    _msg
                );
            }
        }
        Err(e) => if let nom::Err::Error(c) = e {
            match c {
                nom::Context::Code(b, d) => {
                    println!(
                        "#################### FAILED TO PARSE!. ###################\r\nError at {0:#?}\r\n -- Remaining: --\r\n{1} -- Original: --\r\n{2}",
                        d,
                        to_str_dbg(b),
                        to_str_dbg(data),
                    );
                }
            }
        } else {
            println!("Unkown error")
        },
    }
}

fn test_message() {
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
          Via: SIP/2.0/UDP 192.168.10.135:5060;branch=z9hG4bK-d8754z-05751188cc710991-1---d8754z-\r\n",
    );
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
            println!("Unkown error: {}", e);
        },
    }
}
*/
