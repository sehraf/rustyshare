use bitflags::bitflags;

use crate::basics::PgpId;

use super::GxsReputation;

pub trait ServiceString {
    fn service_to_string(&self) -> String;
    fn service_from_string(txt: &str) -> Self;
}

#[derive(Debug, Clone, PartialEq)]
struct SSGxsIdPgp {
    validated_signature: bool,
    last_check_ts: u32,
    check_attempts: i64,
    pgp_id: PgpId,
}

bitflags! {
    struct SSGxsIdRecognTagsFlags: u32 {
        const PROCESSED = 0x1000;
        const PENDING = 0x2000;
    }
}

#[derive(Debug, Clone, PartialEq)]
struct SSGxsIdRecognTags {
    tag_flags: SSGxsIdRecognTagsFlags,
    publish_ts: i64,
    last_check_ts: i64,
}

#[derive(Debug, Clone, PartialEq)]
struct SSGxsIdReputation {
    rep: GxsReputation,
}

// This was an old previous used class. RS itself does not read this anymore itself
// #[derive(Debug, Clone, PartialEq)]
// struct SSGxsIdCumulator {
//     count: u32,
//     nullcount: u32,
//     sum: f64,
//     sumsq: f64,
// }

#[derive(Debug, Clone, PartialEq)]
pub struct SSGxsIdGroup {
    // pgphash status
    pgp: SSGxsIdPgp,
    // recogTags.
    recogntags: SSGxsIdRecognTags,
    // reputation score.
    score: SSGxsIdReputation,
}

fn read(part: &str, identifier: char) -> String {
    let mut txt = part.to_string();
    let expected = identifier.to_string() + ":";
    assert!(txt.starts_with(&expected));
    let _: Vec<_> = txt.drain(0..2).collect();
    txt
}

impl ServiceString for SSGxsIdPgp {
    fn service_from_string(txt: &str) -> Self {
        let mut parts = txt.split_ascii_whitespace();

        let mut check_attempts = 0;
        let mut last_check_ts = 0;
        let mut pgp_id = PgpId::default();
        let mut validated_signature = false;

        // loop for break
        loop {
            if let Some(k) = parts.next() {
                assert!(k.starts_with("K:"));

                if k.chars().nth(2).unwrap() == '1' {
                    validated_signature = true;

                    let id = parts.next().unwrap();
                    pgp_id = read(id, 'I').into();
                } else {
                    if let Some(txt) = parts.next() {
                        last_check_ts = read(txt, 'T').parse().unwrap_or_default();
                    } else {
                        break;
                    }

                    if let Some(txt) = parts.next() {
                        check_attempts = read(txt, 'C').parse().unwrap_or_default();
                    } else {
                        break;
                    }

                    if let Some(id) = parts.next() {
                        pgp_id = read(id, 'I').into();
                    } else {
                        break;
                    }
                }
            }
            break;
        }

        SSGxsIdPgp {
            check_attempts,
            last_check_ts,
            pgp_id,
            validated_signature,
        }
    }

    fn service_to_string(&self) -> String {
        if self.validated_signature {
            format!("K:1 I:{}", self.pgp_id)
        } else {
            if self.pgp_id.is_default() {
                format!("K:0 T:{} C:{}", self.last_check_ts, self.check_attempts)
            } else {
                format!(
                    "K:0 T:{} C:{} I:{}",
                    self.last_check_ts, self.check_attempts, self.pgp_id
                )
            }
        }
    }
}

impl ServiceString for SSGxsIdRecognTags {
    fn service_from_string(txt: &str) -> Self {
        let mut parts = txt.split_ascii_whitespace();

        let tag_flags = if let Some(txt) = parts.next() {
            SSGxsIdRecognTagsFlags::from_bits(read(txt, 'F').parse().unwrap_or_default()).unwrap()
        } else {
            SSGxsIdRecognTagsFlags::empty()
        };
        let publish_ts = if let Some(txt) = parts.next() {
            read(txt, 'P').parse().unwrap_or_default()
        } else {
            0
        };
        let last_check_ts = if let Some(txt) = parts.next() {
            read(txt, 'T').parse().unwrap_or_default()
        } else {
            0
        };

        SSGxsIdRecognTags {
            last_check_ts,
            publish_ts,
            tag_flags,
        }
    }

    fn service_to_string(&self) -> String {
        format!(
            "F:{} P:{} T:{}",
            self.tag_flags.bits(),
            self.publish_ts,
            self.last_check_ts
        )
    }
}

impl ServiceString for SSGxsIdReputation {
    fn service_from_string(txt: &str) -> Self {
        let mut parts = txt.split_ascii_whitespace();

        assert_eq!(parts.clone().count(), 4);

        let parse_one = |part: &str| -> i32 { part.parse().unwrap_or_default() };

        let overall_score = if let Some(txt) = parts.next() {
            parse_one(txt)
        } else {
            0
        };
        let id_score = if let Some(txt) = parts.next() {
            parse_one(txt)
        } else {
            0
        };
        let own_opinion = if let Some(txt) = parts.next() {
            parse_one(txt)
        } else {
            0
        };
        let peer_opinion = if let Some(txt) = parts.next() {
            parse_one(txt)
        } else {
            0
        };

        let rep = GxsReputation {
            overall_score,
            id_score,
            own_opinion,
            peer_opinion,
        };
        SSGxsIdReputation { rep }
    }

    fn service_to_string(&self) -> String {
        let rep = &self.rep;
        format!(
            "{} {} {} {}",
            rep.overall_score, rep.id_score, rep.own_opinion, rep.peer_opinion,
        )
    }
}

// impl ServiceString for SSGxsIdCumulator {
//     fn service_from_string(txt: &str) -> Self {
//         let mut parts = txt.split_ascii_whitespace();

//         assert_eq!(parts.clone().count(), 4);

//         let count = if let Some(txt) = parts.next() {
//             txt.parse().unwrap_or_default()
//         } else {
//             0
//         };

//         let nullcount = if let Some(txt) = parts.next() {
//             txt.parse().unwrap_or_default()
//         } else {
//             0
//         };

//         let sum = if let Some(txt) = parts.next() {
//             txt.parse().unwrap_or_default()
//         } else {
//             0f64
//         };

//         let sumsq = if let Some(txt) = parts.next() {
//             txt.parse().unwrap_or_default()
//         } else {
//             0f64
//         };

//         SSGxsIdCumulator {
//             count,
//             nullcount,
//             sum,
//             sumsq,
//         }
//     }

//     fn service_to_string(&self) -> String {
//         unimplemented!("THIS IS DEPRECATED");
//     }
// }

// TODO better error handling
impl ServiceString for SSGxsIdGroup {
    fn service_from_string(txt: &str) -> Self {
        let mut txt = txt.to_owned();

        assert!(txt.starts_with("v2 "));

        let pgp = if let (Some(start), Some(end)) = (txt.find("{"), txt.find("}")) {
            // drain complete {...}
            let mut sub_str = String::from_iter(txt.drain(start..=end));
            assert!(sub_str.starts_with("{P:"));
            assert!(sub_str.ends_with("}"));

            // remove "{P:" and "}""
            let sub_str = String::from_iter(sub_str.drain(3..sub_str.len() - 1));
            SSGxsIdPgp::service_from_string(&sub_str)
        } else {
            panic!("failed to load SSGxsIdPgp");
        };

        let recogntags = if let (Some(start), Some(end)) = (txt.find("{"), txt.find("}")) {
            // drain complete {...}
            let mut sub_str = String::from_iter(txt.drain(start..=end));
            assert!(sub_str.starts_with("{T:"));
            assert!(sub_str.ends_with("}"));

            // remove "{T:" and "}""
            let sub_str = String::from_iter(sub_str.drain(3..sub_str.len() - 1));
            SSGxsIdRecognTags::service_from_string(&sub_str)
        } else {
            panic!("failed to load SSGxsIdRecognTags");
        };

        let score = if let (Some(start), Some(end)) = (txt.find("{"), txt.find("}")) {
            // drain complete {...}
            let mut sub_str = String::from_iter(txt.drain(start..=end));
            assert!(sub_str.starts_with("{R:"));
            assert!(sub_str.ends_with("}"));

            // remove "{R:" and "}""
            let sub_str = String::from_iter(sub_str.drain(3..sub_str.len() - 1));
            SSGxsIdReputation::service_from_string(&sub_str)
        } else {
            panic!("failed to load SSGxsIdReputation");
        };

        #[allow(deprecated)]
        SSGxsIdGroup {
            pgp,
            recogntags,
            score,
        }
    }

    fn service_to_string(&self) -> String {
        String::from("v2 ")
            + "{P:"
            + &self.pgp.service_to_string()
            + "}{T:"
            + &self.recogntags.service_to_string()
            + "}{R:"
            + &self.score.service_to_string()
            + "}"
    }
}

#[cfg(test)]
mod test_service_string {
    use crate::gxs::{
        service_string::{
            SSGxsIdGroup, SSGxsIdPgp, SSGxsIdRecognTags, SSGxsIdRecognTagsFlags, SSGxsIdReputation,
            ServiceString,
        },
        GxsReputation,
    };

    #[test]
    fn test_ssgxs_id_pgp_a() {
        let orig = SSGxsIdPgp {
            check_attempts: 3,
            last_check_ts: 13,
            pgp_id: "a98fe1c5b5efa8f2".into(),
            validated_signature: false,
        };

        let ser = orig.service_to_string();

        let expected = String::from("K:0 T:13 C:3 I:a98fe1c5b5efa8f2");
        assert_eq!(ser, expected);

        let de = SSGxsIdPgp::service_from_string(&ser);

        assert_eq!(orig, de);
    }

    #[test]
    fn test_ssgxs_id_pgp_b() {
        let orig = SSGxsIdPgp {
            check_attempts: 0,
            last_check_ts: 0,
            pgp_id: "a98fe1c5b5efa8f2".into(),
            validated_signature: true,
        };

        let ser = orig.service_to_string();

        let expected = String::from("K:1 I:a98fe1c5b5efa8f2");
        assert_eq!(ser, expected);

        let de = SSGxsIdPgp::service_from_string(&ser);

        assert_eq!(orig, de);
    }

    #[test]
    fn test_ssgxs_id_recogn_tags() {
        let orig = SSGxsIdRecognTags {
            last_check_ts: 3,
            publish_ts: 13,
            tag_flags: SSGxsIdRecognTagsFlags::PENDING,
        };

        let ser = orig.service_to_string();

        let expected = String::from("F:8192 P:13 T:3");
        assert_eq!(ser, expected);

        let de = SSGxsIdRecognTags::service_from_string(&ser);

        assert_eq!(orig, de);
    }

    #[test]
    fn test_ssgxs_id_reputation() {
        let orig = SSGxsIdReputation {
            rep: GxsReputation {
                id_score: 5,
                overall_score: 42,
                own_opinion: 7,
                peer_opinion: 3,
            },
        };

        let ser = orig.service_to_string();

        let expected = String::from("42 5 7 3");
        assert_eq!(ser, expected);

        let de = SSGxsIdReputation::service_from_string(&ser);

        assert_eq!(orig, de);
    }

    // #[test]
    // #[should_panic]
    // fn test_ssgxs_id_cumulator_a() {
    //     let orig = SSGxsIdCumulator {
    //         count: 5,
    //         nullcount: 7,
    //         sum: 4.2,
    //         sumsq: 13.37,
    //     };

    //     let ser = orig.service_to_string();

    //     let expected = String::from("F:5 P:13 T:3");
    //     assert_eq!(ser, expected);

    //     let de = SSGxsIdCumulator::service_from_string(&ser);

    //     assert_eq!(orig, de);
    // }

    // #[test]
    // fn test_ssgxs_id_cumulator_b() {
    //     let orig = SSGxsIdCumulator {
    //         count: 5,
    //         nullcount: 7,
    //         sum: 4.2,
    //         sumsq: 13.37,
    //     };

    //     let ser = String::from("5 7 4.2 13.37");
    //     let de = SSGxsIdCumulator::service_from_string(&ser);

    //     assert_eq!(orig, de);
    // }

    #[test]
    fn test_ssgxs_id_group_a() {
        let orig = SSGxsIdGroup {
            pgp: SSGxsIdPgp {
                check_attempts: 3,
                last_check_ts: 13,
                pgp_id: "a98fe1c5b5efa8f2".into(),
                validated_signature: false,
            },
            recogntags: SSGxsIdRecognTags {
                last_check_ts: 3,
                publish_ts: 13,
                tag_flags: SSGxsIdRecognTagsFlags::PROCESSED,
            },
            score: SSGxsIdReputation {
                rep: GxsReputation {
                    id_score: 5,
                    overall_score: 42,
                    own_opinion: 7,
                    peer_opinion: 3,
                },
            },
        };

        let ser = orig.service_to_string();

        let expected =
            String::from("v2 {P:K:0 T:13 C:3 I:a98fe1c5b5efa8f2}{T:F:4096 P:13 T:3}{R:42 5 7 3}");
        assert_eq!(ser, expected);

        let de = SSGxsIdGroup::service_from_string(&ser);

        assert_eq!(orig, de);
    }
    #[test]
    fn test_ssgxs_id_group_b() {
        // test some random values from RS
        let values = vec![
            "v2 {P:K:0 T:0 C:0}{T:F:4096 P:1652905981 T:1654373766}{R:5 5 0 0}",
            "v2 {P:K:1 I:4339D0EA9E32E9BA}{T:F:0 P:0 T:0}{R:5 5 0 0}",
            "v2 {P:K:1 I:70C9F52040C6DE22}{T:F:4096 P:1629788436 T:1653132923}{R:50 50 0 0}",
            "v2 {P:K:1 I:B765434C05C55193}{T:F:4096 P:1552323299 T:1653142318}{R:50 50 0 0}",
            "v2 {P:K:1 I:E20DC624159035B0}{T:F:4096 P:1615838443 T:1615934396}{R:50 50 0 0}",
            "v2 {P:K:1 I:8947AA48B25DD8C2}{T:F:4096 P:1653589772 T:1653590372}{R:50 50 0 0}",
            "v2 {P:K:1 I:F77F32C042C009EC}{T:F:4096 P:1646307765 T:1653589712}{R:50 50 0 0}",
            "v2 {P:K:1 I:64C96C2383FBA80F}{T:F:4096 P:1509617562 T:1558718111}{R:50 50 0 0}",
            "v2 {P:K:1 I:481637634A78B0FD}{T:F:4096 P:1591595315 T:1653142310}{R:50 50 0 0}",
            "v2 {P:K:1 I:298C22B175B5B7DF}{T:F:4096 P:1442507042 T:1653142301}{R:50 50 0 0}",
            "v2 {P:K:1 I:F84B28ED1937265E}{T:F:4096 P:1474669204 T:1654373793}{R:50 50 0 0}",
            "v2 {P:K:1 I:2639A81F50C5CF32}{T:F:4096 P:1549982030 T:1549982042}{R:50 50 0 0}",
            "v2 {P:K:1 I:AD662977173AEDAD}{T:F:4096 P:1633550995 T:1633555778}{R:50 50 0 0}",
            "v2 {P:K:1 I:A6F020C1E7FCBC3A}{T:F:0 P:0 T:0}{R:5 5 0 0}",
            "v2 {P:K:1 I:3FE838E49C91E878}{T:F:4096 P:1632835562 T:1654373809}{R:50 50 0 0}",
            "v2 {P:K:1 I:DE1730D3701EBD01}{T:F:4096 P:1620454645 T:1653142292}{R:50 50 0 0}",
            "v2 {P:K:1 I:EA0EECEA814C4A2E}{T:F:4096 P:1486069623 T:1654373791}{R:50 50 0 0}",
            "v2 {P:K:1 I:B724CC0BD38ADB9C}{T:F:4096 P:1650425195 T:1650573293}{R:50 50 0 0}",
            "v2 {P:K:0 T:0 C:0}{T:F:4096 P:1645098649 T:1645115103}{R:5 5 0 0}",
            "v2 {P:K:1 I:AA29CEDE7170EF05}{T:F:4096 P:1446333600 T:1653142270}{R:50 50 0 0}",
            "v2 {P:K:1 I:3F0E6AFC66B68735}{T:F:4096 P:1516279970 T:1654373700}{R:50 50 0 0}",
            "v2 {P:K:1 I:1309AFE99C27FAF9}{T:F:4096 P:1505320596 T:1654373708}{R:50 50 0 0}",
            "v2 {P:K:1 I:D17AA8AE3E2144D5}{T:F:4096 P:1648971822 T:1653142317}{R:50 50 0 0}",
            "v2 {P:K:1 I:7562D7AC7B907066}{T:F:4096 P:1440426512 T:1558725935}{R:50 50 0 0}",
            "v2 {P:K:1 I:7A93B8EFE35591DB}{T:F:0 P:0 T:0}{R:5 5 0 0}",
            "v2 {P:K:0 T:0 C:0}{T:F:4096 P:1633084447 T:1633084507}{R:5 5 0 0}",
            "v2 {P:K:1 I:81349C7E71918C30}{T:F:0 P:0 T:0}{R:5 5 0 0}",
            "v2 {P:K:1 I:34254EA3DF47481F}{T:F:4096 P:1446334342 T:1653142325}{R:50 50 0 0}",
            "v2 {P:K:1 I:F20A12512CC5A887}{T:F:4096 P:1494771344 T:1653142289}{R:50 50 0 0}",
            "v2 {P:K:0 T:0 C:0}{T:F:4096 P:1508017968 T:1508017971}{R:5 5 0 0}",
            "v2 {P:K:1 I:365DFF5A81EFCB7F}{T:F:0 P:0 T:0}{R:50 50 0 0}",
            "v2 {P:K:1 I:9C228BAFD76CE6C1}{T:F:4096 P:1639560063 T:1653142339}{R:50 50 0 0}",
            "v2 {P:K:1 I:23E7D3A9A1516EC7}{T:F:4096 P:1647445270 T:1647515524}{R:50 50 0 0}",
            "v2 {P:K:1 I:14F30DEA005BB8EA}{T:F:4096 P:1460089752 T:1654373762}{R:50 50 0 0}",
            "v2 {P:K:1 I:81E94014DABBEEE3}{T:F:4096 P:1527194502 T:1654373748}{R:50 50 0 0}",
            "v2 {P:K:1 I:280BC8B85190BCCE}{T:F:4096 P:1466879604 T:1466879629}{R:50 50 0 0}",
            "v2 {P:K:0 T:0 C:0}{T:F:4096 P:1562787448 T:1562787449}{R:5 5 0 0}",
            "v2 {P:K:1 I:5DF45F7822C7A0D0}{T:F:0 P:0 T:0}{R:5 5 0 0}",
            "v2 {P:K:1 I:108391E85BDB8377}{T:F:0 P:0 T:0}{R:5 5 0 0}",
            "v2 {P:K:1 I:CBAC3BE61918F9E6}{T:F:0 P:0 T:0}{R:5 5 0 0}",
            "v2 {P:K:1 I:34AD1C30BC5B67CB}{T:F:4096 P:1542010139 T:1542012639}{R:50 50 0 0}",
            "v2 {P:K:0 T:0 C:0}{T:F:0 P:0 T:0}{R:5 5 0 0}",
            "v2 {P:K:1 I:E1F276A06A91B9CF}{T:F:0 P:0 T:0}{R:5 5 0 0}",
            "v2 {P:K:1 I:00D48600655554A9}{T:F:4096 P:1617626947 T:1617815827}{R:50 50 0 0}",
            "v2 {P:K:1 I:E2EA124A60233DF8}{T:F:4096 P:1646651439 T:1646651465}{R:50 50 0 0}",
            "v2 {P:K:1 I:F73659B3D8CD2DA3}{T:F:4096 P:1535035829 T:1653132925}{R:50 50 0 0}",
            "v2 {P:K:1 I:6D68535194A9011E}{T:F:4096 P:1622025041 T:1622025080}{R:50 50 0 0}",
            "v2 {P:K:1 I:7A187F0B755B3517}{T:F:4096 P:1645382534 T:1654373744}{R:50 50 0 0}",
            "v2 {P:K:1 I:F19724D9DEAB05BA}{T:F:4096 P:1640015166 T:1654373801}{R:50 50 0 0}",
            "v2 {P:K:1 I:2DAB71C0F2A5C3A7}{T:F:4096 P:1648056663 T:1653142328}{R:50 50 0 0}",
            "v2 {P:K:1 I:3DFCA135E03C8F55}{T:F:4096 P:1425737995 T:1654373842}{R:50 50 0 0}",
            "v2 {P:K:1 I:226F1ABB344E3827}{T:F:4096 P:1633836434 T:1653142331}{R:50 50 0 0}",
            "v2 {P:K:1 I:06CEE2C5EEF95E8A}{T:F:4096 P:1617258985 T:1654373841}{R:50 50 0 0}",
            "v2 {P:K:1 I:1A98A1059FED9EF7}{T:F:4096 P:1617890361 T:1653142276}{R:50 50 0 0}",
            "v2 {P:K:1 I:A6EA65267C2C6FE1}{T:F:0 P:0 T:0}{R:5 5 0 0}",
            "v2 {P:K:1 I:E6B7283424D29B91}{T:F:4096 P:1538320185 T:1653142271}{R:50 50 0 0}",
            "v2 {P:K:1 I:7DB34F46EDA6425B}{T:F:4096 P:1452542351 T:1653142291}{R:50 50 0 0}",
            "v2 {P:K:1 I:6C95EAC2B735F7AD}{T:F:4096 P:1631712303 T:1653142311}{R:50 50 0 0}",
            "v2 {P:K:1 I:382435E70BB06F1A}{T:F:4096 P:1435041463 T:1613076480}{R:50 50 0 0}",
            "v2 {P:K:1 I:5ACC5A37C335651D}{T:F:4096 P:1605575346 T:1654373710}{R:50 50 0 0}",
            "v2 {P:K:1 I:133E525084DE5D4D}{T:F:4096 P:1614029822 T:1653132924}{R:50 50 0 0}",
            "v2 {P:K:1 I:877F5863EA104F56}{T:F:4096 P:1418592888 T:1653142307}{R:50 50 0 0}",
            "v2 {P:K:1 I:866DD19E5658F0E4}{T:F:4096 P:1621609811 T:1654373832}{R:50 50 0 0}",
            "v2 {P:K:1 I:4475B2C22974214B}{T:F:4096 P:1640014194 T:1653142281}{R:50 50 0 0}",
            "v2 {P:K:0 T:0 C:0}{T:F:4096 P:1590905120 T:1590905126}{R:5 5 0 0}",
            "v2 {P:K:1 I:2535A377C8DF8DA8}{T:F:4096 P:1433962260 T:1433962306}{R:50 50 0 0}",
            "v2 {P:K:1 I:1F4338DFAF6863D6}{T:F:0 P:0 T:0}{R:5 5 0 0}",
            "v2 {P:K:1 I:0956C334FC924061}{T:F:4096 P:1615455445 T:1615455447}{R:50 50 0 0}",
            "v2 {P:K:1 I:F7929EF06FC5D979}{T:F:0 P:0 T:0}{R:5 5 0 0}",
            "v2 {P:K:1 I:5E5009EA8ECC4217}{T:F:0 P:0 T:0}{R:5 5 0 0}",
            "v2 {P:K:1 I:63042D68B2C8BFAD}{T:F:0 P:0 T:0}{R:5 5 0 0}",
            "v2 {P:K:1 I:C566ADABAB33E2FB}{T:F:4096 P:1530928110 T:1654373784}{R:50 50 0 0}",
            "v2 {P:K:0 T:0 C:0}{T:F:4096 P:1482573227 T:1654373692}{R:5 5 0 0}",
            "v2 {P:K:1 I:123E7B0D1F246C30}{T:F:4096 P:1640618451 T:1653142264}{R:50 50 0 0}",
            "v2 {P:K:1 I:2790EA14FA360499}{T:F:4096 P:1438526774 T:1654373704}{R:50 50 0 0}",
            "v2 {P:K:1 I:16E1E8DF47B16B0C}{T:F:0 P:0 T:0}{R:50 50 0 0}",
            "v2 {P:K:1 I:40D6706AA976A30B}{T:F:0 P:0 T:0}{R:5 5 0 0}",
            "v2 {P:K:1 I:8F4106D07C858563}{T:F:4096 P:1476956489 T:1654373849}{R:50 50 0 0}",
            "v2 {P:K:1 I:48A8B05D0F8CBBB1}{T:F:4096 P:1477051258 T:1477051259}{R:50 50 0 0}",
            "v2 {P:K:1 I:D155E2299191D9EF}{T:F:0 P:0 T:0}{R:50 50 0 0}",
            "v2 {P:K:1 I:6519A47DA2B5555B}{T:F:4096 P:1435787439 T:1559067387}{R:50 50 0 0}",
        ];

        for val in values {
            _ = SSGxsIdGroup::service_from_string(val);
        }
    }
}
