pub mod tags;
pub mod tlv_base;
pub mod tlv_ip_addr;
pub mod tlv_keys;
pub mod tlv_map;
pub mod tlv_set;
pub mod tlv_string;

pub const TLV_HEADER_SIZE: usize = 6;

use std::fmt::Debug;

pub use tlv_base::{Tlv, Tlv2};

pub type TlvBinaryData<const T: u16> = Tlv2<T, Vec<u8>>;

impl<const T: u16> Debug for TlvBinaryData<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "TlvBinaryData: {}", hex::encode(self.as_slice()))
    }
}
