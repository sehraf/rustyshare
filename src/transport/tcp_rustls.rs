use std::{
    convert::TryInto,
    io::{Read, Write},
    net::{SocketAddr, TcpStream},
    sync::Arc,
};

// use rustls::{ClientConnection, RootCertStore, ServerName, Stream};
use rustls::{ClientConnection, RootCertStore};
use sequoia_openpgp as openpgp;

use super::{ConnectionType, RsPeerConnection};
// use crate::error::RsError;
use crate::retroshare_compat::ssl_key::SslKey;

// enum State<'a> {
//     NotInited,
//     Inited(ClientConnection),
//     Connected(
//         SocketAddr,
//         TcpStream,
//         Stream<'a, ClientConnection, TcpStream>,
//     ),
// }

pub struct ConTcpRusTls {
    client_connection: ClientConnection,

    connected: Option<(SocketAddr, TcpStream)>,
    // //     own_key: SslKey,
    // con: Option<Stream<'a, ClientConnection, TcpStream>>,

    // target: Option<SocketAddr>,
    // //     target_id: openpgp::Cert,
    // cc: ClientConnection,

    // state: State<'a>
}

impl RsPeerConnection for ConTcpRusTls {
    fn init(ssl_key: &SslKey, target_id: &openpgp::Cert) -> Option<Box<Self>> {
        let mut root_store = RootCertStore::empty();
        root_store.add(&ssl_key.to_owned().into()).unwrap();
        let config = rustls::ClientConfig::builder()
            .with_safe_defaults()
            .with_root_certificates(root_store)
            .with_single_cert(vec![ssl_key.to_owned().into()], ssl_key.to_owned().into())
            .unwrap(); // TODO: handle error

        let pgp_name = {
            let mut s1: String = String::new();
            for ua in target_id.userids() {
                let s2 = String::from_utf8_lossy(ua.value());
                s1.push_str(&s2);
            }
            s1
        };
        // let server_name: ServerName = ServerName::try_from(pgp_name.as_str()).expect("invalid DNS name");
        // let server_name = pgp_name.as_str().try_into().expect("invalid DNS name");
        let server_name = "".try_into().expect("invalid DNS name");
        let conn = ClientConnection::new(Arc::new(config), server_name).unwrap();

        Some(Box::new(ConTcpRusTls {
            client_connection: conn,
            connected: None,
        }))
    }

    fn connect(&mut self, addr: ConnectionType) -> bool {
        if let ConnectionType::Tcp(addr) = addr {
            let socket = match TcpStream::connect_timeout(&addr, std::time::Duration::from_secs(5))
            {
                Ok(s) => s,
                Err(_why) => {
                    // println!("failed to connecto to {}: {}", &self.target, why);
                    return false;
                }
            };
            // let cc_2 = self.cc;
            // let mut tls = rustls::Stream::new(  &mut self.client_connection, &mut socket);

            // self.con = Some(tls);
            // self.target = Some(addr);
            self.connected = Some((addr, socket));
        }
        false

        // match self.state {
        //     State::NotInited | State::Connected(..) => unreachable!("state missmatch!"),
        //     State::Inited(mut cc) => {
        //         if let ConnectionType::Tcp(addr) = addr {
        //             let mut socket = match TcpStream::connect_timeout(
        //                 &addr,
        //                 std::time::Duration::from_secs(5),
        //             ) {
        //                 Ok(s) => s,
        //                 Err(_why) => {
        //                     // println!("failed to connecto to {}: {}", &self.target, why);
        //                     return false;
        //                 }
        //             };
        //             let tls = rustls::Stream::new(&mut cc, &mut socket);

        //             self.state = State::Connected(addr, socket, tls)
        //         }
        //     }
        // }
        // true
    }

    fn target(&self) -> ConnectionType {
        // ConnectionType::Tcp(self.target.unwrap()) // crash otherwise, TODO

        // match self.state {
        //     State::Connected(dst, ..) => ConnectionType::Tcp(dst),
        //     _ => unreachable!("not connected!"),
        // }

        if let Some((dst, ..)) = self.connected {
            ConnectionType::Tcp(dst)
        } else {
            unreachable!()
        }
    }
}

impl Read for ConTcpRusTls {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        // if let Some(con) = self.con.as_mut() {
        //     return con.read(buf);
        // }
        // Err(std::io::Error::from(std::io::ErrorKind::ConnectionReset))

        // match &mut self.state {
        //     State::Connected(_, _, tls) => {
        //         if tls.wa
        //         tls.read(buf)
        //     },
        //     _ => Err(std::io::Error::from(std::io::ErrorKind::ConnectionReset)),
        // }

        if let Some((_, socket)) = &mut self.connected {
            let mut tls = rustls::Stream::new(&mut self.client_connection, socket);
            tls.read(buf)
        } else {
            Err(std::io::Error::from(std::io::ErrorKind::ConnectionReset))
        }
    }
}

impl Write for ConTcpRusTls {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        // if let Some(con) = self.con.as_mut() {
        //     return con.write(buf);
        // }
        // Err(std::io::Error::from(std::io::ErrorKind::ConnectionReset))

        // match &mut self.state {
        //     State::Connected(_, _, tls) => tls.write(buf),
        //     _ => Err(std::io::Error::from(std::io::ErrorKind::ConnectionReset)),
        // }

        if let Some((_, socket)) = &mut self.connected {
            let mut tls = rustls::Stream::new(&mut self.client_connection, socket);
            tls.write(buf)
        } else {
            Err(std::io::Error::from(std::io::ErrorKind::ConnectionReset))
        }
    }

    fn flush(&mut self) -> std::io::Result<()> {
        // if let Some(con) = self.con.as_mut() {
        //     return con.flush();
        // }
        // Err(std::io::Error::from(std::io::ErrorKind::ConnectionReset))

        // match &mut self.state {
        //     State::Connected(_, _, tls) => tls.flush(),
        //     _ => Err(std::io::Error::from(std::io::ErrorKind::ConnectionReset)),
        // }

        if let Some((_, socket)) = &mut self.connected {
            let mut tls = rustls::Stream::new(&mut self.client_connection, socket);
            tls.flush()
        } else {
            Err(std::io::Error::from(std::io::ErrorKind::ConnectionReset))
        }
    }
}

// pub fn try_connect(
//     target: &SocketAddr,
//     target_pub: &openpgp::Cert,
//     target_common_name: &str,
//     identity: &Identity,
// ) -> Result<TlsStream<TcpStream>, RsError> {
//     // let bytes = own_key_pair.1.private_key_to_der().unwrap();
//     // let id = Identity::from_pkcs12(der, password)

//     let mut root_store = RootCertStore::empty();
//     let config = rustls::ClientConfig::builder()
//         .with_safe_defaults()
//         .with_root_certificates(root_store, &[])
//         .with_single_cert(cert_chain, key_der);

//     let mut conn =
//         rustls::ClientConnection::new(Arc::new(config), target_common_name.into()).unwrap();
//     let socket = match TcpStream::connect_timeout(&target, std::time::Duration::from_secs(5)) {
//         Ok(s) => s,
//         Err(_why) => {
//             // println!("failed to connecto to {}: {}", &self.target, why);
//             return None;
//         }
//     };
//     let mut tls = rustls::Stream::new(&mut conn, &mut sock);

//     let connector = TlsConnector::builder()
//         .min_protocol_version(Some(Protocol::Tlsv12))
//         .disable_built_in_roots(true)
//         .danger_accept_invalid_hostnames(true)
//         .identity(identity.to_owned())
//         .build()
//         .expect("failed to creat TLS connector!");

//     let stream = TcpStream::connect(target)?;
//     let stream = match connector.connect(target_common_name, stream) {
//         Ok(s) => s,
//         Err(HandshakeError::Failure(e)) => return Err(e.into()),
//         Err(_why) => {
//             panic!("is this supposed to happen!?")
//         }
//     };

//     Ok(stream)
// }

// pub fn try_accept(
//     target: TcpStream,
//     // target_pub: &openpgp::Cert,
//     // target_loc_name: &str,
//     identity: &Identity,
// ) -> Result<TlsStream<TcpStream>, RsError> {
//     let acceptor = TlsAcceptor::builder(identity.to_owned())
//         .min_protocol_version(Some(Protocol::Tlsv12))
//         .build()
//         .expect("failed to creat TLS acceptor!");

//     let stream = match acceptor.accept(target) {
//         Ok(s) => s,
//         Err(HandshakeError::Failure(e)) => return Err(e.into()),
//         Err(_why) => {
//             panic!("is this supposed to happen!?")
//         }
//     };

//     Ok(stream)
//     // Err(RsError::Generic)
// }
