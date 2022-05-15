use futures::io;
use log::info;
#[allow(unused_imports)]
use openpgp::parse::Parse;
#[allow(unused_imports)]
use openssl::{self, hash::MessageDigest};
use rustls::{
    client::{InvalidDnsNameError, ServerCertVerifier},
    version::TLS13,
    Certificate, ClientConfig, ServerName,
};
use sequoia_openpgp as openpgp;
use std::{net::SocketAddr, sync::Arc};
use tokio::{
    io::{AsyncRead, AsyncWrite},
    net::TcpStream,
};
use tokio_rustls::TlsConnector;

use crate::retroshare_compat::ssl_key::SslKey;

#[derive(Clone, Debug)]
pub enum ConnectionType {
    Tcp(SocketAddr),
    #[allow(dead_code)]
    Udp(SocketAddr),
}

struct PeerVerifier {
    _peer_name: ServerName,
    _peer_cert: sequoia_openpgp::Cert,
}

#[allow(unused)]
impl ServerCertVerifier for PeerVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &rustls::Certificate,
        intermediates: &[rustls::Certificate],
        server_name: &ServerName,
        scts: &mut dyn Iterator<Item = &[u8]>,
        ocsp_response: &[u8],
        now: std::time::SystemTime,
    ) -> Result<rustls::client::ServerCertVerified, rustls::Error> {
        // use openssl::x509::*;
        info!("verify_server_cert {server_name:?}");

        let cert = openssl::x509::X509::from_der(end_entity.as_ref()).unwrap();
        // info!("{cert:?}");

        // let sig = cert.signature();
        // let verifier = openssl::sign::Verifier::new(cert.signature_algorithm().into(), self._peer_cert);

        // let pub_key = self._peer_cert.primary_key().verify(sig, hash_algo, digest)

        // let pkey = self._peer_cert.primary_key().key();
        // let pkey = openssl::pkey::PKey::from(pkey);
        // let res = cert.verify(&pkey);

        Ok(rustls::client::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &Certificate,
        dss: &rustls::internal::msgs::handshake::DigitallySignedStruct,
    ) -> Result<rustls::client::HandshakeSignatureValid, rustls::Error> {
        info!("verify_tls12_signature");
        // info!("{message:?}");
        // info!("{cert:?}");
        // info!("{dss:?}");

        Ok(rustls::client::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &Certificate,
        dss: &rustls::internal::msgs::handshake::DigitallySignedStruct,
    ) -> Result<rustls::client::HandshakeSignatureValid, rustls::Error> {
        info!("verify_tls13_signature");
        // info!("{message:?}");
        // info!("{cert:?}");
        // info!("{dss:?}");

        Ok(rustls::client::HandshakeSignatureValid::assertion())
    }
}

pub struct Connection {
    config: Arc<ClientConfig>,
    peer_name: ServerName,
}

impl Connection {
    pub fn new(
        own_key_pair: &SslKey,
        peer_cert: sequoia_openpgp::Cert,
        peer_name: &str,
    ) -> Result<Self, InvalidDnsNameError> {
        let peer_name: ServerName = peer_name.try_into()?;

        // let mut trust_store = RootCertStore::empty();
        // trust_store.add_parsable_certificates(&[peer_cert_der.to_owned()]);

        let verifier = Arc::new(PeerVerifier {
            _peer_name: peer_name.to_owned(),
            _peer_cert: peer_cert,
        });

        let config = ClientConfig::builder()
            // .with_safe_defaults()
            .with_safe_default_cipher_suites()
            .with_safe_default_kx_groups()
            .with_protocol_versions(&[&TLS13])
            .unwrap()
            // // .with_root_certificates(trust_store)
            .with_custom_certificate_verifier(verifier)
            .with_single_cert(vec![own_key_pair.into()], own_key_pair.into())
            .expect("faield to load key pair");

        let config = Arc::new(config);

        Ok(Connection { config, peer_name })
    }

    pub async fn connect(&self, target: ConnectionType) -> io::Result<impl AsyncWrite + AsyncRead> {
        let ip_addr = match target {
            ConnectionType::Tcp(ip) => ip,
            ConnectionType::Udp(_) => unimplemented!("UDP support not implemented"),
        };

        let connector = TlsConnector::from(self.config.clone());
        let stream = TcpStream::connect(&ip_addr).await?;
        connector.connect(self.peer_name.clone(), stream).await
    }
}
