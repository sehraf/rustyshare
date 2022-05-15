use nom::{
    self,
    error::{make_error, ErrorKind},
    Err, IResult,
};
use serde::Deserialize;

use crate::serde::from_retroshare_wire;

fn tlv<'a, T>(data: &[u8], tag: u16) -> IResult<&[u8], T>
where
    T: Deserialize<'a>,
{
    let (data, _tag) = nom::bytes::complete::tag(tag.to_be_bytes())(data)?;
    let (data, len) = nom::number::complete::be_u32(data)?;
    let (data, value) = nom::bytes::complete::take(len)(data)?;

    let mut value = value.to_vec();
    let mut foo = Box::new(None);
    {
        let res = from_retroshare_wire(&mut value)
            .map_err(|_err| Err::Error(make_error(data, ErrorKind::Fail)))?;
        foo.insert(res);
    }

    Ok((data, foo.unwrap()))
}
