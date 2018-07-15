#[macro_use]
extern crate nom;

mod contact;

fn is_space(c: char) -> bool {
    c == ' '
}

fn is_digit(c: char) -> bool {
    c.is_digit(10)
}

fn is_param_char(c: char) -> bool {
    c != ';' && c != '\r' && c != '\n'
}

pub fn just_test() {
    println!("{:#?}", contact::parse_contact("tel:85999684700\r\n"));
}
