// use futures::{AsyncRead, AsyncWrite};
// use sequoia_openpgp as openpgp;
use std::{
    // io::{Read, Write},
    net::SocketAddr,
};

// pub mod connection;
// // pub mod ssl; // not used anymore
// // pub mod tcp;
// pub mod listener;
// pub mod tcp_openssl;
// pub mod tcp_rustls;

// use crate::retroshare_compat::ssl_key::SslKey;

#[derive(Clone, Debug)]
pub enum ConnectionType {
    Tcp(SocketAddr),
    #[allow(dead_code)]
    Udp(SocketAddr),
}

// pub trait RsPeerConnection {
//     /// Call init to setup what ever is needed to be ready to establish a connection
//     ///
//     /// Should only be called once.
//     async fn init(ssl_key: &SslKey, target_id: &openpgp::Cert) -> Self;

//     /// Try to connect to the given target, might be called multiple times until successful
//     async fn connect<T: AsyncRead + AsyncWrite>(&mut self, addr: ConnectionType) -> Option<T>; // TODO: use Result

//     // // fn accept(&mut self, socket: TcpStream) -> bool; // TODO: use Result
//     // /// Return the address of the current connection
//     // fn target(&self) -> ConnectionType;
// }
