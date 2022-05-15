use ::serde::{Deserialize, Serialize};
use std::fmt;

use crate::basics::*;

// TODO this is transported as TLV, currently (de)serialized by hand in the service
struct BwCtrlAllowedItem {
    allowed_bw: u32,
}
