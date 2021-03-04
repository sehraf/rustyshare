// use std::io::{Read, Write};
use std::sync::Arc;

// use openssl::ssl::{SslConnector, SslMethod, SslStream};
// use std::net::{SocketAddr, TcpStream};
use openssl::{pkey, x509};

// use crate::error::RsError;

pub type SslKeyPair = Arc<(x509::X509, pkey::PKey<openssl::pkey::Private>)>;

// pub struct RsSsl {}

// impl RsSsl {
//     pub fn get_ssl_connector(keystore: &SslKeyPair) -> SslConnector {
//         // ssl
//         let mut builder =
//             SslConnector::builder(SslMethod::tls()).expect("failed to creat connector builder");
//         builder.set_certificate(&keystore.0).unwrap(); // TODO
//         builder.set_private_key(&keystore.1).unwrap();
//         builder
//             .set_max_proto_version(Some(openssl::ssl::SslVersion::TLS1_2))
//             .unwrap(); // TODO
//         builder
//             .set_min_proto_version(Some(openssl::ssl::SslVersion::TLS1_2))
//             .unwrap();
//         builder.set_verify(openssl::ssl::SslVerifyMode::NONE); // TODO

//         builder.build()
//     }
// }

// impl RsSsl {
//     pub fn connect_tls<T>(socket: T, connector: &Arc<SslConnector>) -> Result<SslStream<T>, RsError>
//     where
//         T: Read + Write,
//     {
//         let mut stream = match connector.connect("sehraf", socket) {
//             Ok(s) => s,
//             Err(why) => {
//                 use openssl::ssl::HandshakeError;

//                 println!("hand shake failure");
//                 match why {
//                     HandshakeError::SetupFailure(stack) => {
//                         println!("SetupFailure: {:?}", stack);
//                     }
//                     HandshakeError::Failure(_) => {
//                         println!("Failure");
//                     }
//                     HandshakeError::WouldBlock(_) => {
//                         println!("WouldBlock");
//                     }
//                 }
//                 return Err(RsError::default());
//             }
//         };

//         println!(
//             "using: {:?} {:?}",
//             stream.ssl().version_str(),
//             stream.ssl().current_cipher().unwrap().name(),
//         );

//         // stream.connect().unwrap();
//         // stream.flush().unwrap();
        

//         Ok(stream)
//     }
// }
