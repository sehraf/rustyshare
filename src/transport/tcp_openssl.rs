use std::{
    io::{Read, Write},
    net::{SocketAddr, TcpStream},
};

use openssl::{
    pkey::{PKey, Private},
    ssl::{SslConnector, SslMethod, SslStream},
    x509::X509,
};
use sequoia_openpgp as openpgp;

// use crate::transport::ssl::SslKeyPair;
use super::{ConnectionType, RsPeerConnection};
use crate::retroshare_compat::ssl_key::SslKey;

pub struct ConTcpOpenssl {
    // own_key: SslKey,
    con: Option<SslStream<TcpStream>>,

    target: Option<SocketAddr>,
    target_id: openpgp::Cert,

    b: Builder,
}

impl RsPeerConnection for ConTcpOpenssl {
    fn init(ssl_key: &SslKey, target_id: &openpgp::Cert) -> Option<Box<Self>> {
        Some(Box::new(ConTcpOpenssl {
            con: None,
            // own_key: ssl_key.to_owned(),

            target: None,
            target_id: target_id.to_owned(),

            b: Builder::new(ssl_key),
        }))
    }

    fn connect(&mut self, addr: ConnectionType) -> bool {
        if let ConnectionType::Tcp(addr) = addr {
            let con = self.b.connect(&addr, &self.target_id);
            if con.is_none() {
                return false;
            }
            
            self.con = con;
            self.target = Some(addr);

            return true;
        }
        false
    }

    fn target(&self) -> ConnectionType {
        ConnectionType::Tcp(self.target.unwrap()) // crash otherwise, TODO
    }
}

impl Read for ConTcpOpenssl {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if let Some(con) = self.con.as_mut() {
            return con.read(buf);
        }
        Err(std::io::Error::from(std::io::ErrorKind::ConnectionReset))
    }
}

impl Write for ConTcpOpenssl {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        if let Some(con) = self.con.as_mut() {
            return con.write(buf);
        }
        Err(std::io::Error::from(std::io::ErrorKind::ConnectionReset))
    }

    fn flush(&mut self) -> std::io::Result<()> {
        if let Some(con) = self.con.as_mut() {
            return con.flush();
        }
        Err(std::io::Error::from(std::io::ErrorKind::ConnectionReset))
    }
}

pub(crate) struct Builder {
    // own_key_pair: SslKeyPair,
    // target: SocketAddr,
    // target_pub: openpgp::Cert,
    ssl_connector: SslConnector,
}

impl Builder {
    pub fn new(own_key_pair: &SslKey) -> Self {
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
                println!("handshake failure: {}", why);
                return None;
            }
        };

        // make non blocking
        stream.get_ref().set_nonblocking(true).unwrap();

        Some(stream)
    }

    #[allow(unused)]
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

    fn get_ssl_connector(key_pair: &SslKey) -> SslConnector {
        let pub_key: X509 = key_pair.to_owned().into();
        let priv_key: PKey<Private> = key_pair.to_owned().into();

        // ssl
        let mut builder =
            SslConnector::builder(SslMethod::tls()).expect("failed to create connector builder");
        builder.set_certificate(&pub_key).unwrap();
        builder.set_private_key(&priv_key).unwrap();
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
