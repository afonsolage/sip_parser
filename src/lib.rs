#[macro_use]
extern crate nom;

mod contact;

//TODO: Remove this later on
pub use contact::just_test;

fn is_space(c: char) -> bool {
    c == ' '
}

fn is_digit(c: char) -> bool {
    c.is_digit(10)
}

fn is_param_char(c: char) -> bool {
    c != ';' && c != '\r' && c != '\n'
}
