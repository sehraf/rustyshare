use crate::tlv::Tlv;

const BWCTRL_ITEM_TAG: u16 = 0x0035;

pub type BwCtrlAllowedItem = Tlv<BWCTRL_ITEM_TAG, u32>;
