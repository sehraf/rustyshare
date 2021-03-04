use std::net::{SocketAddr, TcpStream};

use openssl::ssl::SslStream;

pub mod connection;
pub mod ssl;
// pub mod tcp;
pub mod listener;
pub mod tcp_openssl;

// use ssl::{RsSsl, SslKeyPair};

// use crate::error::RsError;

#[derive(Clone, Debug)]
pub enum ConnectionType {
    Tcp(SocketAddr),
    #[allow(dead_code)]
    Udp(SocketAddr),
}

pub struct Transport {
    pub target: ConnectionType,
    // pub socket: Box<TcpStream>,
    pub stream: SslStream<TcpStream>,
    // stream: SslRef,
    // stream_in: Arc<Box<dyn Read>>,
    // stream_out: Arc<Box<dyn Write>>,
}
