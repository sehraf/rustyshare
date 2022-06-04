use serde::Deserialize;
use serde_repr::Deserialize_repr;

use crate::{
    basics::Sha1CheckSum,
    tlv::{tags::*, tlv_set::TlvSet, Tlv, TlvBinaryData},
};

#[derive(Debug, Deserialize_repr)]
#[repr(u32)]
pub enum ImageType {
    None = 0,
    Png = 1,
    Jpg = 2,
}

impl Default for ImageType {
    fn default() -> Self {
        ImageType::None
    }
}

#[derive(Debug, Deserialize, Default)]
struct Image {
    ty: ImageType,
    data: TlvBinaryData<TLV_TYPE_BIN_IMAGE>,
}

#[derive(Debug, Deserialize)]
pub struct GxsIdGroupItem {
    mPgpIdHash: Sha1CheckSum,
    mPgpIdSign: TlvBinaryData<TLV_TYPE_STR_SIGN>,
    mRecognTags: TlvSet<TLV_TYPE_RECOGNSET, String>,
    #[serde(default)]
    mImage: Tlv<TLV_TYPE_IMAGE, Image>,
}
