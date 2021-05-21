use serde::{de, ser};
use std::fmt::{self, Display};

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Clone, Debug, PartialEq)]
pub enum Error {
    Message(String),
    Eof,
    TrailingBytes,
    UnknownSize,
}

impl ser::Error for Error {
    fn custom<T: Display>(msg: T) -> Self {
        Error::Message(msg.to_string())
    }
}

impl de::Error for Error {
    fn custom<T: Display>(msg: T) -> Self {
        Error::Message(msg.to_string())
    }
}

impl Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Error::Message(msg) => write!(f, "{}", msg),
            Error::Eof => f.write_str("unexpected end of input"),
            /* and so forth */
            _ => unimplemented!(),
        }
    }
}

impl std::error::Error for Error {}

impl From<crate::serde::Error> for Error {
    fn from(e: crate::serde::Error) -> Self {
        match e {
            crate::serde::Error::Message(s) => Error::Message(s),
            crate::serde::Error::Eof => Error::Eof,
            crate::serde::Error::TrailingBytes => Error::TrailingBytes,
            crate::serde::Error::UnknownSize => Error::UnknownSize,
        }
    }
}
