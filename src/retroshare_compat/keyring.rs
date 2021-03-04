use std::io::Read;
use std::{fs::File, path::Path};

use openpgp::cert::prelude::*;
use openpgp::parse::PacketParser;
use openpgp::parse::Parse;
use sequoia_openpgp as openpgp;

const KEYRING_BASE_DIR: &'static str = "pgp";
const KEYRING_PUBKEY: &'static str = "retroshare_public_keyring.gpg";
const KEYRING_PRIVKEY: &'static str = "retroshare_secret_keyring.gpg";

fn read_key_ring(file: &str) -> Result<Vec<openpgp::Cert>, std::io::Error> {
    let mut f = File::open(file).expect(&format!("failed to open file {}", file));
    let mut keyring = Vec::new();
    f.read_to_end(&mut keyring).expect("failed to read file");
    let ppr = PacketParser::from_bytes(&keyring).expect("failed to parse keyring");
    let mut ring = Vec::new();
    for certo in CertParser::from(ppr) {
        match certo {
            Ok(cert) => ring.push(cert),
            Err(why) => println!("Error reading keyring: {}", why),
        }
    }
    Ok(ring)
}

pub struct Keyring {
    public_keys: Vec<openpgp::Cert>,
    priv_keys: Vec<openpgp::Cert>,
}

impl Keyring {
    pub fn new() -> Keyring {
        Keyring {
            public_keys: Vec::new(),
            priv_keys: Vec::new(),
        }
    }

    #[allow(dead_code)]
    pub fn public_keys(&self) -> &Vec<openpgp::Cert> {
        &self.public_keys
    }

    #[allow(dead_code)]
    pub fn priv_keys(&self) -> &Vec<openpgp::Cert> {
        &self.priv_keys
    }
}

impl Keyring {
    pub fn parse(&mut self, path: &Path) {
        self.public_keys = read_key_ring(&format!(
            "{}/{}/{}",
            path.to_str().unwrap(),
            KEYRING_BASE_DIR,
            KEYRING_PUBKEY
        ))
        .unwrap_or_default();
        self.priv_keys = read_key_ring(&format!(
            "{}/{}/{}",
            path.to_str().unwrap(),
            KEYRING_BASE_DIR,
            KEYRING_PRIVKEY
        ))
        .unwrap_or_default();

        println!(
            "loaded keyrings: public keys: {} private keys: {}",
            self.public_keys.len(),
            self.priv_keys.len()
        );
    }

    pub fn get_key_by_id_str(&self, id_in_hex: &str, priv_key: bool) -> Option<&openpgp::Cert> {
        let ring = if priv_key {
            &self.priv_keys
        } else {
            &self.public_keys
        };

        ring.iter().find(|&x| x.keyid().to_hex() == id_in_hex)
    }

    pub fn get_key_by_id_bytes(
        &self,
        id_in_bytes: &[u8],
        priv_key: bool,
    ) -> Option<&openpgp::Cert> {
        let ring = if priv_key {
            &self.priv_keys
        } else {
            &self.public_keys
        };

        ring.iter().find(|&x| x.keyid().as_bytes() == id_in_bytes)
    }

    #[allow(dead_code)]
    pub fn get_priv_keys(&self) -> &Vec<Cert> {
        &self.priv_keys
    }
}
