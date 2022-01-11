use std::io::{self, Read, Write};
use std::path;
use std::{fs::File, sync::Arc};

use openpgp::{
    cert::prelude::*,
    crypto::SessionKey,
    parse::{stream::*, Parse},
    policy::{Policy, StandardPolicy as P},
    types::SymmetricAlgorithm,
};
use openssl::{
    pkey::{self, PKey},
    x509::X509,
};
use rustls::{Certificate, PrivateKey};
use sequoia_openpgp as openpgp;

/// Simple type wrapper for DER encoded public key
pub type PublicKeyDer = Vec<u8>;
/// Simple type wrapper for DER encoded private key
pub type PrivateKeyDer = Vec<u8>;
/// Key pair container
#[derive(Clone)]
pub struct SslKey {
    keys: Arc<Box<(PublicKeyDer, PrivateKeyDer)>>,
}

impl SslKey {
    pub fn new() -> SslKey {
        SslKey {
            keys: Arc::new(Box::new((Vec::new(), Vec::new()))),
        }
    }

    pub fn public_key(&self) -> &PublicKeyDer {
        &self.keys.0
    }

    pub fn private_key(&self) -> &PrivateKeyDer {
        &self.keys.1
    }
}

impl From<SslKey> for X509 {
    fn from(key: SslKey) -> Self {
        X509::from_der(&key.public_key()).unwrap()
    }
}

impl From<SslKey> for PKey<pkey::Private> {
    fn from(key: SslKey) -> Self {
        PKey::private_key_from_der(&key.private_key()).unwrap()
    }
}

impl From<SslKey> for Certificate {
    fn from(key: SslKey) -> Self {
        Certificate(key.public_key().to_owned())
    }
}

impl From<SslKey> for PrivateKey {
    fn from(key: SslKey) -> Self {
        PrivateKey(key.private_key().to_owned())
    }
}

impl From<(PublicKeyDer, PrivateKeyDer)> for SslKey {
    fn from(from: (PublicKeyDer, PrivateKeyDer)) -> Self {
        SslKey {
            keys: Arc::new(Box::new((from.0, from.1))),
        }
    }
}

impl SslKey {
    pub fn load_encrypted(
        &self,
        pgp: &Cert,
        localtion_path: &path::Path,
        pw: &str,
    ) -> Result<SslKey, std::io::Error> {
        // decrypt (ssl)key passphrase
        let full_path = localtion_path.join("keys/");
        let password = SslKey::decrypt_passphrase(&full_path, pgp, pw)?;

        // print ssl password for debug only!
        // println!("{}", String::from_utf8_lossy(&password));

        // sounds a bit stupid, RS won't generate such passphrases!
        assert!(
            !password.contains(&0),
            "your SSL passphrase contains \0 this is currently a problem!"
        );

        // OpenSSL stuff

        // user_cert.pem
        let mut user_cert_file = File::open(&full_path.join("user_cert.pem"))?;
        let mut user_cert = Vec::new();
        user_cert_file.read_to_end(&mut user_cert)?;

        // user_pk.pem
        let mut user_pk_file = File::open(&full_path.join("user_pk.pem"))?;
        let mut user_pk = Vec::new();
        user_pk_file.read_to_end(&mut user_pk)?;

        // convert PEM to DER
        // XXX: replace openssl
        let user_cert_open = openssl::x509::X509::from_pem(&user_cert)?;
        let user_cert = user_cert_open.to_der()?;
        let user_pk_open = PKey::private_key_from_pem_passphrase(&user_pk, password.as_ref())
            .expect("failed to decrypt private key!");
        let user_pk = user_pk_open.private_key_to_der()?;
        // // native-tls stuff
        // let mut identity_file = File::open(&full_path.join("identity.pfx"))?;
        // let mut identity = Vec::new();
        // identity_file.read_to_end(&mut identity)?;

        // let identity = Identity::from_pkcs12(&identity, &"phpkid").unwrap();

        // let user_pk = PKey::private_key_from_pem_callback(&user_pk, |pw_buffer| {
        //     assert!(password.len() <= pw_buffer.len(), "not enough space!");
        //     pw_buffer[0..password.len()].copy_from_slice(password.as_slice());
        //     Ok(password.len())
        // })
        // .expect("failed to decrypt private key!");

        Ok((user_cert, user_pk).into())

        // Ok((
        //     user_cert_open,
        //     user_pk_open, // , identity
        // ))
    }

    fn decrypt_passphrase(
        path: &path::Path,
        key: &Cert,
        pw: &str,
    ) -> Result<Vec<u8>, std::io::Error> {
        let full_path = path.join("ssl_passphrase.pgp");

        let mut file = match File::open(&full_path) {
            Ok(file) => file,
            Err(why) => {
                println!("couldn't open {}: {}", full_path.display(), why);
                return Err(why);
            }
        };
        let mut msg = Vec::new();
        match file.read_to_end(&mut msg) {
            Ok(_) => {}
            Err(why) => {
                println!("failed to load ssl_{}: {}", full_path.display(), why);
                return Err(why);
            }
        }

        let pw = openpgp::crypto::Password::from(pw);
        let p = &P::new();

        // Decrypt the message.
        let mut plaintext = Vec::new();
        decrypt(p, &mut plaintext, &msg, &key, &pw).or_else(|_| Err(std::io::ErrorKind::Other))?;

        Ok(plaintext)
    }

    // fn generate(&mut self) {
    //     let rsa = Rsa::generate(4096).unwrap();

    //     self.public_key = rsa.public_key_to_der().unwrap();
    //     self.private_key = rsa.private_key_to_der().unwrap();
    // }

    // fn save(&self, file: &str) {
    //     {
    //         let full_name: String = format!("{}{}", file, "_pub.der");
    //         let full_path = path::Path::new(&full_name);
    //         save_data(full_path, &self.public_key);

    //     }
    //     {
    //         let full_name: String = format!("{}{}", file, "_priv.der");
    //         let full_path = path::Path::new(&full_name);
    //         save_data(full_path, &self.private_key);
    //     }
    // }

    // fn load(&mut self, file: &str) -> bool {
    //     let mut success = true;
    //     {
    //         let full_name = format!("{}{}", file, "_pub.der");
    //         match File::open(&full_name) {
    //             Ok(mut o) => {
    //                 let size = o.read_to_end(&mut self.public_key).unwrap();
    //                 if size == 0 {
    //                     println!("zero file!");
    //                     success = false;
    //                 }
    //             }
    //             Err(e) => {
    //                 println!("opening {}: {}", full_name, e);
    //                 success = false;
    //             }
    //         };
    //     }
    //     {
    //         let full_name = format!("{}{}", file, "_priv.der");
    //         match File::open(&full_name) {
    //             Ok(mut o) => {
    //                 let size = o.read_to_end(&mut self.private_key).unwrap();
    //                 if size == 0 {
    //                     println!("zero file!");
    //                     success = false;
    //                 }
    //             }
    //             Err(e) => {
    //                 println!("opening {}: {}", full_name, e);
    //                 success = false;
    //             }
    //         };
    //     }
    //     return success;
    // }

    // pub fn load_or_generate(&mut self, file: &str) {
    //     let r = self.load(file);
    //     if r == false {
    //         self.generate();
    //         self.save(file);
    //     }
    // }
}

/// Decrypts the given message.
pub fn decrypt(
    policy: &dyn Policy,
    sink: &mut dyn Write,
    ciphertext: &[u8],
    recipient: &openpgp::Cert,
    password: &openpgp::crypto::Password,
) -> openpgp::Result<()> {
    // Make a helper that that feeds the recipient's secret key to the
    // decryptor.
    let helper = Helper {
        policy,
        secret: recipient,
        password,
    };

    // Now, create a decryptor with a helper using the given Certs.
    let mut decryptor =
        DecryptorBuilder::from_bytes(ciphertext)?.with_policy(policy, None, helper)?;

    // Decrypt the data.
    io::copy(&mut decryptor, sink)?;
    Ok(())
}

struct Helper<'a> {
    #[allow(dead_code)]
    policy: &'a dyn Policy,
    secret: &'a openpgp::Cert,
    password: &'a openpgp::crypto::Password,
}

impl<'a> VerificationHelper for Helper<'a> {
    fn get_certs(&mut self, _ids: &[openpgp::KeyHandle]) -> openpgp::Result<Vec<openpgp::Cert>> {
        // Return public keys for signature verification here.
        Ok(Vec::new())
    }

    fn check(&mut self, _structure: MessageStructure) -> openpgp::Result<()> {
        // Implement your signature verification policy here.
        Ok(())
    }
}

impl<'a> DecryptionHelper for Helper<'a> {
    fn decrypt<D>(
        &mut self,
        pkesks: &[openpgp::packet::PKESK],
        _skesks: &[openpgp::packet::SKESK],
        sym_algo: Option<SymmetricAlgorithm>,
        mut decrypt: D,
    ) -> openpgp::Result<Option<openpgp::Fingerprint>>
    where
        D: FnMut(SymmetricAlgorithm, &SessionKey) -> bool,
    {
        // The encryption key is the first and only subkey.
        // println!(
        //     "{}",
        //     self.secret
        //         .keys()
        //         // .unencrypted_secret()
        //         .secret()
        //         // .with_policy(self.policy, None)
        //         // .for_transport_encryption()
        //         .count()
        // );
        let key = self
            .secret
            .keys()
            // .unencrypted_secret()
            .secret()
            // .with_policy(self.policy, None)
            // .for_transport_encryption()
            .nth(0)
            .expect("failed to get encryption key!")
            .key()
            .clone();

        // The secret key is not encrypted.
        let mut pair = key.decrypt_secret(self.password)?.into_keypair().unwrap();

        pkesks[0]
            .decrypt(&mut pair, sym_algo)
            .map(|(algo, session_key)| decrypt(algo, &session_key));

        // XXX: In production code, return the Fingerprint of the
        // recipient's Cert here
        Ok(None)
    }
}

// fn save_data(path: &path::Path, data: &Vec<u8>) {
//     let display = path.display();

//     if path.exists() == false {
//         File::create(&path).unwrap();
//     }

//     let mut file = match File::open(&path) {
//         Err(why) => panic!("couldn't open {}: {}", display, why),
//         Ok(file) => file,
//     };

//     match file.write_all(&data) {
//         Err(why) => panic!("couldn't write to {}: {}", display, why),
//         Ok(_) => println!("successfully wrote to {}", display),
//     }
//     file.sync_all().unwrap();
// }
