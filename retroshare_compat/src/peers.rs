use serde::{Deserialize, Serialize};

use crate::basics::{PgpFingerprint, PgpId, SslId, PgpIdHex};

// struct RsPeerDetails : RsSerializable
// {
// 	RsPeerDetails();

// 	/* Auth details */
// 	bool isOnlyGPGdetail;
// 	RsPeerId id;
// 	RsPgpId gpg_id;

// 	std::string name;
// 	std::string email;
// 	std::string location;
// 	std::string org;

// 	RsPgpId issuer;

// 	RsPgpFingerprint fpr; /* pgp fingerprint */
// 	std::string authcode; 	// TODO: 2015/12/31 (cyril) what is this used for ?????
// 	std::list<RsPgpId> gpgSigners;

// 	uint32_t trustLvl;
// 	uint32_t validLvl;

//     bool skip_pgp_signature_validation;
// 	bool ownsign; /* we have signed the remote peer GPG key */
// 	bool hasSignedMe; /* the remote peer has signed my GPG key */
// 	bool accept_connection;

//     /* Peer permission flags. What services the peer can use (Only valid if friend).*/
//     ServicePermissionFlags service_perm_flags ;

//     /* Network details (only valid if friend) */
// 	uint32_t state;
// 	bool actAsServer;

// 	// TODO: 2015/12/31 to take advantage of multiple connection this must be
// 	// replaced by a set of addresses
// 	std::string connectAddr ; // current address if connected.
// 	uint16_t connectPort ;

// 	// Hidden Node details.
// 	bool isHiddenNode;
// 	std::string hiddenNodeAddress;
// 	uint16_t hiddenNodePort;
// 	uint32_t hiddenType;

// 	// Filled in for Standard Node.
// 	std::string localAddr;
// 	uint16_t localPort;
// 	std::string extAddr;
// 	uint16_t extPort;
// 	std::string dyndns;
// 	std::list<std::string> ipAddressList;

// 	uint32_t netMode;
// 	/* vis State */
// 	uint16_t vs_disc;
// 	uint16_t vs_dht;

// 	/* basic stats */
// 	uint32_t lastConnect;           /* how long ago */
// 	uint32_t lastUsed;              /* how long ago since last used: signature verif, connect attempt, etc */
// 	uint32_t connectState;          /* RS_PEER_CONNECTSTATE_... */
// 	std::string connectStateString; /* Additional string like ip address */
// 	uint32_t connectPeriod;
// 	bool foundDHT;

// 	/* have we been denied */
// 	bool wasDeniedConnection;
// 	rstime_t deniedTS;

// 	/* linkType */
// 	uint32_t linkType;

// 	/// @see RsSerializable
// 	virtual void serial_process( RsGenericSerializer::SerializeJob j,
// 	                             RsGenericSerializer::SerializeContext& ctx )
// 	{
// 		RS_SERIAL_PROCESS(isOnlyGPGdetail);
// 		RS_SERIAL_PROCESS(id);
// 		RS_SERIAL_PROCESS(gpg_id);
// 		RS_SERIAL_PROCESS(name);
// 		RS_SERIAL_PROCESS(email);
// 		RS_SERIAL_PROCESS(location);
// 		RS_SERIAL_PROCESS(org);
// 		RS_SERIAL_PROCESS(issuer);
// 		RS_SERIAL_PROCESS(fpr);
// 		RS_SERIAL_PROCESS(authcode);
// 		RS_SERIAL_PROCESS(gpgSigners);
// 		RS_SERIAL_PROCESS(trustLvl);
// 		RS_SERIAL_PROCESS(validLvl);
// 		RS_SERIAL_PROCESS(ownsign);
// 		RS_SERIAL_PROCESS(hasSignedMe);
// 		RS_SERIAL_PROCESS(accept_connection);
// 		RS_SERIAL_PROCESS(service_perm_flags);
// 		RS_SERIAL_PROCESS(state);
// 		RS_SERIAL_PROCESS(actAsServer);
// 		RS_SERIAL_PROCESS(connectAddr);
// 		RS_SERIAL_PROCESS(connectPort);
// 		RS_SERIAL_PROCESS(isHiddenNode);
// 		RS_SERIAL_PROCESS(hiddenNodeAddress);
// 		RS_SERIAL_PROCESS(hiddenNodePort);
// 		RS_SERIAL_PROCESS(hiddenType);
// 		RS_SERIAL_PROCESS(localAddr);
// 		RS_SERIAL_PROCESS(localPort);
// 		RS_SERIAL_PROCESS(extAddr);
// 		RS_SERIAL_PROCESS(extPort);
// 		RS_SERIAL_PROCESS(dyndns);
// 		RS_SERIAL_PROCESS(ipAddressList);
// 		RS_SERIAL_PROCESS(netMode);
// 		RS_SERIAL_PROCESS(vs_disc);
// 		RS_SERIAL_PROCESS(vs_dht);
// 		RS_SERIAL_PROCESS(lastConnect);
// 		RS_SERIAL_PROCESS(lastUsed);
// 		RS_SERIAL_PROCESS(connectState);
// 		RS_SERIAL_PROCESS(connectStateString);
// 		RS_SERIAL_PROCESS(connectPeriod);
// 		RS_SERIAL_PROCESS(foundDHT);
// 		RS_SERIAL_PROCESS(wasDeniedConnection);
// 		RS_SERIAL_PROCESS(deniedTS);
// 		RS_SERIAL_PROCESS(linkType);
// 	}
// };

#[derive(Serialize, Debug, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct PeerDetails {
    pub is_only_gpg_detail: bool,
    #[serde(with = "hex")]
    pub id: SslId,
    #[serde(rename(serialize = "gpg_id", deserialize = "gpg_id"))]
    #[serde(with = "hex")]
    pub pgp_id: PgpId,

    pub name: String,
    pub email: String,
    pub location: String,
    pub org: String,

    #[serde(with = "hex")]
    pub issuer: PgpId,
    #[serde(with = "hex")]
    pub fpr: PgpFingerprint,
    pub gpg_signers: Vec<PgpIdHex>,
}

impl PeerDetails {
    pub fn set_peer_id(mut self, id: SslId) -> Self {
        self.id = id;
        self
    }

    pub fn set_name(mut self, name: &str) -> Self {
        self.name = name.to_string();
        self
    }
}
