use serde::{
    de::{DeserializeOwned, Visitor},
    Deserialize, Deserializer, Serialize, Serializer,
};
use std::{collections::HashSet, fmt, hash::Hash, marker::PhantomData};

use crate::{
    basics::*,
    read_u16, read_u32,
    serde::{from_retroshare_wire, to_retroshare_wire},
    tlv::{tags::*, TLV_HEADER_SIZE},
    write_u16, write_u32,
};

#[derive(Debug, Eq, PartialEq, Default, Clone)]
pub struct TlvSet<const TAG: u16, T>(pub HashSet<T>)
where
    T: Eq + PartialEq + Hash;

impl<const TAG: u16, T> Serialize for TlvSet<TAG, T>
where
    T: Serialize + Eq + PartialEq + Hash,
{
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut bytes = to_retroshare_wire(&self.0).expect("failed to serialize");
        // remove length
        let bytes: Vec<_> = bytes.drain(4..).collect();

        let mut ser = vec![];
        write_u16(&mut ser, TAG);
        write_u32(&mut ser, (bytes.len() + TLV_HEADER_SIZE) as u32);
        ser.extend_from_slice(&bytes);

        serializer.serialize_bytes(ser.as_slice())
    }
}

impl<'de, const TAG: u16, T> Deserialize<'de> for TlvSet<TAG, T>
where
    T: DeserializeOwned + Eq + PartialEq + Hash,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct TlvVisitor<const TAG: u16, T>(PhantomData<T>);

        impl<'de, const TAG: u16, T> Visitor<'de> for TlvVisitor<TAG, T>
        where
            T: DeserializeOwned + PartialEq + Eq + Hash,
        {
            type Value = TlvSet<TAG, T>;

            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                write!(f, "TLV")
            }

            fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                let mut item = HashSet::new();
                let tag = read_u16(&mut v[0..2].to_owned());
                if tag != TAG {
                    return Err(::serde::de::Error::custom(crate::serde::Error::WrongTag));
                }
                let len = read_u32(&mut v[2..6].to_owned()) as usize;
                assert!(len >= TLV_HEADER_SIZE);
                assert!(len == v.len());

                let mut bytes: Vec<_> = v[6..len].into();
                while !bytes.is_empty() {
                    let id: T = from_retroshare_wire(&mut bytes).expect("failed to deserialize");
                    item.insert(id);
                }

                Ok(TlvSet(item))
            }
        }

        deserializer.deserialize_byte_buf(TlvVisitor(PhantomData))
    }
}

// typedef t_RsTlvIdSet<RsPeerId,      TLV_TYPE_PEERSET>	        RsTlvPeerIdSet ;
// typedef t_RsTlvIdSet<RsPgpId,       TLV_TYPE_PGPIDSET>	        RsTlvPgpIdSet ;
// typedef t_RsTlvIdSet<Sha1CheckSum,  TLV_TYPE_HASHSET> 	        RsTlvHashSet ;
// typedef t_RsTlvIdSet<RsGxsId,       TLV_TYPE_GXSIDSET>          RsTlvGxsIdSet ;
// typedef t_RsTlvIdSet<RsGxsMessageId,TLV_TYPE_GXSMSGIDSET>       RsTlvGxsMsgIdSet ;
// typedef t_RsTlvIdSet<RsGxsCircleId, TLV_TYPE_GXSCIRCLEIDSET>    RsTlvGxsCircleIdSet ;
// typedef t_RsTlvIdSet<RsNodeGroupId, TLV_TYPE_NODEGROUPIDSET>    RsTlvNodeGroupIdSet ;

pub type TlvPeerIdSet = TlvSet<TLV_TYPE_PEERSET, SslId>;
pub type TlvPgpIdSet = TlvSet<TLV_TYPE_PGPIDSET, PgpId>;
pub type TlvHashSet = TlvSet<TLV_TYPE_HASHSET, Sha1CheckSum>;
pub type TlvGxsIdSet = TlvSet<TLV_TYPE_GXSIDSET, GxsId>;
pub type TlvGxsMsgIdSet = TlvSet<TLV_TYPE_GXSMSGIDSET, GxsMessageId>;
pub type TlvGxsCircleIdSet = TlvSet<TLV_TYPE_GXSCIRCLEIDSET, GxsCircleId>;
pub type TlvNodeGroupIdSet = TlvSet<TLV_TYPE_NODEGROUPIDSET, NodeGroupId>;

#[cfg(test)]
mod tests_tlv {
    use std::collections::HashSet;

    use crate::{
        basics::SslId,
        read_u16, read_u32,
        serde::{from_retroshare_wire, to_retroshare_wire},
        tlv::tlv_set::TLV_TYPE_PEERSET,
        write_u16, write_u32,
    };

    use super::{TlvPeerIdSet, TLV_HEADER_SIZE};

    impl TlvPeerIdSet {
        pub fn write(&self) -> Vec<u8> {
            let mut data: Vec<u8> = vec![];

            // write payload
            for entry in &self.0 {
                data.append(&mut to_retroshare_wire(entry).expect("failed to serialize ID"));
            }
            // create TLV header
            let mut packet: Vec<u8> = vec![];
            write_u16(&mut packet, TLV_TYPE_PEERSET);
            write_u32(&mut packet, (data.len() + TLV_HEADER_SIZE) as u32);
            packet.append(&mut data);

            packet
        }

        pub fn read(data: &mut Vec<u8>) -> Self {
            let mut item = TlvPeerIdSet { 0: HashSet::new() };
            let tag = read_u16(data);
            let len = read_u32(data) as usize;
            assert_eq!(tag, TLV_TYPE_PEERSET);

            let end = data.len() - (len - TLV_HEADER_SIZE);
            while data.len() > end {
                let id = from_retroshare_wire(data).expect("failed to read ID");
                item.0.insert(id);
            }

            item
        }
    }

    #[test]
    fn test_tlv_peer_id_set_single() {
        // only add one due to randomness
        let mut orig = TlvPeerIdSet::default();
        orig.0.insert("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".into()); // 16 bytes

        let ser = to_retroshare_wire(&orig).expect("failed to serialize");

        let mut expected = vec![];
        write_u16(&mut expected, TLV_TYPE_PEERSET);
        write_u32(&mut expected, (16 * 1 + TLV_HEADER_SIZE) as u32);
        expected.append(
            &mut hex::decode("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
                // &mut hex::decode("")
                .unwrap()
                .into(),
        );

        let expected2 = orig.write();

        println!("{ser:?}");
        println!("{expected:?}");
        println!("{expected2:?}");
        assert_eq!(ser, expected);
        assert_eq!(expected, expected2);
    }

    #[test]
    fn test_tlv_peer_id_set_multiple() {
        // only add one due to randomnes
        let mut orig = TlvPeerIdSet::default();
        orig.0.insert(SslId::default());
        orig.0.insert("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".into()); // 16 bytes
        orig.0.insert("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".into()); // 16 bytes
        orig.0.insert("cccccccccccccccccccccccccccccccc".into()); // 16 bytes
        orig.0.insert("eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee".into()); // 16 bytes
        orig.0.insert("ffffffffffffffffffffffffffffffff".into()); // 16 bytes

        let mut ser = to_retroshare_wire(&orig).expect("failed to serialize");
        let de: TlvPeerIdSet = from_retroshare_wire(&mut ser).expect("failed to deserialize");

        assert_eq!(orig, de);
    }
}
