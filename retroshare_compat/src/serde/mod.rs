mod de;
mod error;
mod ser;

pub use de::{from_retroshare_wire, LengthReader, RetroShareWireDeserializer};
pub use error::{Error, Result};
pub use ser::{to_retroshare_wire, RetroShareWireSerializer};

pub trait RetroShareTLV {
    fn get_tlv_tag(&self) -> u16;
}
