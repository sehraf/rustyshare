// use openssl::rsa::Rsa;

use openpgp::cert::prelude::*;
use openpgp::crypto::SessionKey;
use openpgp::parse::{stream::*, Parse};
use openpgp::policy::Policy;
use openpgp::policy::StandardPolicy as P;
use sequoia_openpgp as openpgp;
// use openpgp::serialize::stream::*;
use openpgp::types::SymmetricAlgorithm;

// use rustls;

// use pem;
use openssl::pkey::PKey;

// use std::fs;
use std::fs::File;
use std::io::{self, Read, Write};
use std::path;

pub struct SslKey {
    // password: String,
    public_key: Vec<u8>,
    private_key: Vec<u8>,
}

impl SslKey {
    pub fn new() -> SslKey {
        SslKey {
            // password: String::new(),
            public_key: Vec::new(),
            private_key: Vec::new(),
        }
    }

    #[allow(dead_code)]
    pub fn public_key(&self) -> &Vec<u8> {
        &self.public_key
    }
    #[allow(dead_code)]
    pub fn private_key(&self) -> &Vec<u8> {
        &self.private_key
    }
}

impl SslKey {
    pub fn load_encrypted(
        &self,
        pgp: &Cert,
        localtion_path: &path::Path,
        pw: &str,
    ) -> Result<(openssl::x509::X509, PKey<openssl::pkey::Private>), std::io::Error> {
        // decrypt (ssl)key passphrase
        let full_path = localtion_path.join("keys/");
        let password = SslKey::decrypt_passphrase(&full_path, pgp, pw).unwrap();

        // user_cert.pem
        let mut user_cert_file = File::open(&full_path.join("user_cert.pem"))?;
        let mut user_cert = Vec::new();
        user_cert_file.read_to_end(&mut user_cert)?;

        // user_pk.pem
        let mut user_pk_file = File::open(&full_path.join("user_pk.pem"))?;
        let mut user_pk = Vec::new();
        user_pk_file.read_to_end(&mut user_pk)?;

        let user_cert = openssl::x509::X509::from_pem(&user_cert).unwrap();
        let user_pk = PKey::private_key_from_pem_passphrase(&user_pk, password.as_ref()).unwrap();

        {
            // let pkey = user_pk.private_key_to_der().unwrap();
            // let base64 = base64::encode(&pkey);

            // println!("ssl pw: {:?}", base64::encode(&password));
            // println!("ssl key: {:?}", base64);

            // let path = path::Path::new("/tmp/key.der");
            // let mut file = File::create(&path).unwrap_or_else(|_| {
            //     File::open(&path).unwrap()
            // });
            // file.write(b"-----BEGIN RSA PRIVATE KEY-----\n").unwrap();
            // file.write(&base64.into_bytes()).unwrap();
            // file.write(b"-----END RSA PRIVATE KEY-----\n").unwrap();
        }

        Ok((user_cert, user_pk))
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
        decrypt(p, &mut plaintext, &msg, &key, &pw).unwrap();

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
        password: password,
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
            .unwrap()
            .key()
            .clone();

        // The secret key is not encrypted.
        let mut pair = key
            .decrypt_secret(self.password)
            .unwrap()
            .into_keypair()
            .unwrap();

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
