use std::net::{SocketAddr, TcpStream};

use openssl::ssl::{SslConnector, SslMethod, SslStream};
use sequoia_openpgp as openpgp;

use crate::transport::ssl::SslKeyPair;

// use super::ssl;

pub(crate) struct Builder {
    // own_key_pair: SslKeyPair,
    // target: SocketAddr,
    // target_pub: openpgp::Cert,
    ssl_connector: SslConnector,
}

impl Builder {
    pub fn new(own_key_pair: &SslKeyPair) -> Self {
        let connector = Builder::get_ssl_connector(&own_key_pair);
        Builder {
            // own_key_pair: own_key_pair.clone(),
            // target: target.clone(),
            // target_pub: target_pub.clone(),
            ssl_connector: connector,
        }
    }

    pub fn connect(
        &self,
        target: &SocketAddr,
        _target_pub: &openpgp::Cert,
    ) -> Option<SslStream<TcpStream>> {
        // tcp connect
        let socket = match TcpStream::connect_timeout(&target, std::time::Duration::from_secs(5)) {
            Ok(s) => s,
            Err(_why) => {
                // println!("failed to connecto to {}: {}", &self.target, why);
                return None;
            }
        };

        // ssl connect client
        let stream = match self.ssl_connector.connect("sehraf", socket) {
            Ok(s) => s,
            Err(why) => {
                println!("hand shake failure: {}", why);
                return None;
            }
        };

        // make non blocking
        stream.get_ref().set_nonblocking(true).unwrap();

        Some(stream)
    }

    pub fn incoming(&self, socket: TcpStream) -> Option<SslStream<TcpStream>> {
        // ssl connect server
        let ssl = openssl::ssl::Ssl::new(self.ssl_connector.context()).unwrap();
        let stream = match ssl.accept(socket) {
            Ok(s) => s,
            Err(why) => {
                println!("incoming: {}", why);
                return None;
            }
        };

        // make non blocking
        stream.get_ref().set_nonblocking(true).unwrap();

        Some(stream)
    }

    fn get_ssl_connector(keystore: &SslKeyPair) -> SslConnector {
        // ssl
        let mut builder =
            SslConnector::builder(SslMethod::tls()).expect("failed to creat connector builder");
        builder.set_certificate(&keystore.0).unwrap();
        builder.set_private_key(&keystore.1).unwrap();
        builder
            .set_max_proto_version(Some(openssl::ssl::SslVersion::TLS1_2))
            .unwrap(); // TODO
        builder
            .set_min_proto_version(Some(openssl::ssl::SslVersion::TLS1_2))
            .unwrap();
        builder.set_cipher_list("ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384").unwrap();
        // builder.set_cipher_list("DHE-RSA-WITH-AES-256-GCM-SHA384").unwrap();
        builder.set_verify(openssl::ssl::SslVerifyMode::NONE); // TODO
                                                               // builder.set_verify_callback(mode, verify) // TODO

        builder.build()
    }
}
