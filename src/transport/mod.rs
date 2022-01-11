use std::{
    io::{Read, Write},
    net::{SocketAddr},
};

use sequoia_openpgp as openpgp;

pub mod connection;
// pub mod ssl; // not used anymore
// pub mod tcp;
pub mod listener;
pub mod tcp_openssl;
// pub mod tcp_rustls;

use crate::retroshare_compat::ssl_key::SslKey;

#[derive(Clone, Debug)]
pub enum ConnectionType {
    Tcp(SocketAddr),
    #[allow(dead_code)]
    Udp(SocketAddr),
}

// TODO handle UDP (e.g. use ToSocketAddr trait?)
pub trait RsPeerConnection
where
    Self: Read + Write,
{
    /// Call init to setup what ever is needed to be ready to establish a connection
    ///
    /// Should only be called once.
    fn init(ssl_key: &SslKey, target_id: &openpgp::Cert) -> Option<Box<Self>>;
    /// Try to connect to the given target, might be called multiple times until successful
    fn connect(&mut self, addr: ConnectionType) -> bool; // TODO: use Result
    // fn accept(&mut self, socket: TcpStream) -> bool; // TODO: use Result
    /// Return the address of the current connection 
    fn target(&self) -> ConnectionType;
}
