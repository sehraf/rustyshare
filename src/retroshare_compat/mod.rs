pub mod config_store;
pub mod keyring;
pub mod ssl_key;

pub type PgpId = [u8; 8];
pub type PeerId = PgpId;
pub type SslId = [u8; 16];
pub type LocationId = SslId;