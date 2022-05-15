use native_tls::{
    HandshakeError, Identity, Protocol, TlsAcceptor, TlsAcceptorBuilder, TlsConnector,
    TlsConnectorBuilder, TlsStream,
};
use openssl::{pkcs12, pkey::*};
use sequoia_openpgp as openpgp;
use std::net::{SocketAddr, TcpStream};

use crate::error::RsError;
use crate::transport::ssl::SslKeyPair;

pub fn try_connect(
    target: &SocketAddr,
    target_pub: &openpgp::Cert,
    target_common_name: &str,
    identity: &Identity,
) -> Result<TlsStream<TcpStream>, RsError> {
    // let bytes = own_key_pair.1.private_key_to_der().unwrap();

    // let id = Identity::from_pkcs12(der, password)

    let connector = TlsConnector::builder()
        .min_protocol_version(Some(Protocol::Tlsv12))
        .disable_built_in_roots(true)
        .danger_accept_invalid_hostnames(true)
        .identity(identity.to_owned())
        .build()
        .expect("failed to creat TLS connector!");

    let stream = TcpStream::connect(target)?;
    let stream = match connector.connect(target_common_name, stream) {
        Ok(s) => s,
        Err(HandshakeError::Failure(e)) => return Err(e.into()),
        Err(_why) => {
            panic!("is this supposed to happen!?")
        }
    };

    Ok(stream)
}

pub fn try_accept(
    target: TcpStream,
    // target_pub: &openpgp::Cert,
    // target_loc_name: &str,
    identity: &Identity,
) -> Result<TlsStream<TcpStream>, RsError> {
    let acceptor = TlsAcceptor::builder(identity.to_owned())
        .min_protocol_version(Some(Protocol::Tlsv12))
        .build()
        .expect("failed to creat TLS acceptor!");

    let stream = match acceptor.accept(target) {
        Ok(s) => s,
        Err(HandshakeError::Failure(e)) => return Err(e.into()),
        Err(_why) => {
            panic!("is this supposed to happen!?")
        }
    };

    Ok(stream)
    // Err(RsError::Generic)
}
