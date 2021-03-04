#[derive(Debug)]
pub enum RsError {
    Generic, // not nice but used where "something" went wrong
    StdIo(std::io::Error),
    Ssl(openssl::ssl::Error),
    ParserError(RsErrorParser),
}

#[derive(Debug)]
pub enum RsErrorParser {
    IsRawHeader,
    UnknownHeaderType,
}

impl From<std::io::Error> for RsError {
    fn from(err: std::io::Error) -> Self {
        RsError::StdIo(err)
    }
}

// impl From<openssl::error::Error> for RsError {
//     fn from(err: openssl::error::Error) -> Self {
//         RsError::Ssl(err)
//     }
// }

impl From<openssl::ssl::Error> for RsError {
    fn from(err: openssl::ssl::Error) -> Self {
        RsError::Ssl(err)
    }
}

// used for debugging
impl Default for RsError {
    fn default() -> Self {
        RsError::Generic
    }
}
