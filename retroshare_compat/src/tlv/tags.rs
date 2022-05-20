
pub const TLV_IP_ADDR_INFO: u16 = 0x1070;
pub const TLV_IP_ADDR_SET_TAG: u16 = 0x1071;
pub const TLV_IP_ADDR_TAG: u16 = 0x1072;
pub const TLV_IP_ADDR_TAG_IPV4: u16 = 0x0085;
pub const TLV_IP_ADDR_TAG_IPV6: u16 = 0x0086;

// pub const TLV_TYPE_KEYSIGNATURE: u16 = 0x1050;
// pub const TLV_TYPE_KEYSIGNATURESET: u16 = 0x1051;
// pub const TLV_TYPE_KEYSIGNATURETYPE: u16 = 0x1052;

pub const RSTLV_KEY_TYPE_MASK: u32 = 0x000f;
pub const RSTLV_KEY_TYPE_PUBLIC_ONLY: u32 = 0x0001;
pub const RSTLV_KEY_TYPE_FULL: u32 = 0x0002;

// pub const TLV_TYPE_STR_GROUPID: u16 = 0x00a0;

// pub const TLV_TYPE_SECURITY_KEY: u16 = 0x1040;
// pub const TLV_TYPE_SECURITYKEYSET: u16 = 0x1041;

// pub const TLV_TYPE_PEERSET: u16 = 0x1021;
// pub const TLV_TYPE_HASHSET: u16 = 0x1022;
// pub const TLV_TYPE_PGPIDSET: u16 = 0x1023;
// pub const TLV_TYPE_GXSIDSET: u16 = 0x1025;
// pub const TLV_TYPE_GXSCIRCLEIDSET: u16 = 0x1026;
// pub const TLV_TYPE_NODEGROUPIDSET: u16 = 0x1027;
// pub const TLV_TYPE_GXSMSGIDSET: u16 = 0x1028;



pub const TLV_SERVICE_INFO_TAG_MAP: u16 = 0x0001;
pub const TLV_SERVICE_INFO_TAG_PAIR: u16 = 0x0001;
pub const TLV_SERVICE_INFO_TAG_KEY: u16 = 0x0001;
pub const TLV_SERVICE_INFO_TAG_VALUE: u16 = 0x0001;


// #################################
// From rstlvbase.h
// #################################

/* TLV HEADER SIZE (Reference) *******************************/
pub const TLV_HEADER_TYPE_SIZE  : u32= 2;
pub const TLV_HEADER_LEN_SIZE   : u32= 4;
// pub const TLV_HEADER_SIZE       : u32= TLV_HEADER_TYPE_SIZE + TLV_HEADER_LEN_SIZE;
/* TLV HEADER SIZE (Reference) *******************************/

pub const TLV_TYPE_UINT32_SIZE  : u16= 0x0030;
pub const TLV_TYPE_UINT32_POP   : u16= 0x0031;
pub const TLV_TYPE_UINT32_AGE   : u16= 0x0032;
pub const TLV_TYPE_UINT32_OFFSET: u16= 0x0033;
pub const TLV_TYPE_UINT32_SERID : u16= 0x0034;
pub const TLV_TYPE_UINT32_BW    : u16= 0x0035;
pub const TLV_TYPE_UINT32_PARAM : u16= 0x0030;

pub const TLV_TYPE_UINT64_SIZE  : u16= 0x0040;
pub const TLV_TYPE_UINT64_OFFSET: u16= 0x0041;

pub const TLV_TYPE_STR_PEERID   : u16= 0x0050;
pub const TLV_TYPE_STR_NAME     : u16= 0x0051;
pub const TLV_TYPE_STR_PATH     : u16= 0x0052;
pub const TLV_TYPE_STR_KEY      : u16= 0x0053;
pub const TLV_TYPE_STR_VALUE    : u16= 0x0054;
pub const TLV_TYPE_STR_COMMENT  : u16= 0x0055;
pub const TLV_TYPE_STR_TITLE    : u16= 0x0056;
pub const TLV_TYPE_STR_MSG      : u16= 0x0057;
pub const TLV_TYPE_STR_SUBJECT  : u16= 0x0058;
pub const TLV_TYPE_STR_LINK     : u16= 0x0059;
pub const TLV_TYPE_STR_GENID    : u16= 0x005a;
pub const TLV_TYPE_STR_GPGID    : u16= 0x005b; /* depreciated */
pub const TLV_TYPE_STR_PGPID    : u16= 0x005b; /* same as GPG */
pub const TLV_TYPE_STR_LOCATION : u16= 0x005c;
pub const TLV_TYPE_STR_CERT_GPG : u16= 0x005d; 
pub const TLV_TYPE_STR_PGPCERT  : u16= 0x005d; /* same as CERT_GPG */
pub const TLV_TYPE_STR_CERT_SSL : u16= 0x005e;
pub const TLV_TYPE_STR_VERSION  : u16= 0x005f;
pub const TLV_TYPE_STR_PARAM    : u16= 0x0054; /* same as VALUE ---- TO FIX */

/* Hashs are always strings */
pub const TLV_TYPE_STR_HASH_SHA1: u16= 0x0070;
pub const TLV_TYPE_STR_HASH_ED2K: u16= 0x0071;

pub const TLV_TYPE_IPV4_LOCAL   : u16= 0x0080;
pub const TLV_TYPE_IPV4_REMOTE  : u16= 0x0081;
pub const TLV_TYPE_IPV4_LAST    : u16= 0x0082;
pub const TLV_TYPE_STR_DYNDNS   : u16= 0x0083;
pub const TLV_TYPE_STR_DOMADDR  : u16= 0x0084;

// rearrange these in the future.
pub const TLV_TYPE_IPV4         : u16= 0x0085;
pub const TLV_TYPE_IPV6         : u16= 0x0086;

/*** MORE STRING IDS ****/
pub const TLV_TYPE_STR_GROUPID  : u16= 0x00a0;
pub const TLV_TYPE_STR_MSGID    : u16= 0x00a1;
pub const TLV_TYPE_STR_PARENTID : u16= 0x00a2;
pub const TLV_TYPE_STR_THREADID : u16= 0x00a3;
pub const TLV_TYPE_STR_KEYID    : u16= 0x00a4;

/* even MORE string Ids for GXS services */

pub const TLV_TYPE_STR_CAPTION  : u16= 0x00b1;
pub const TLV_TYPE_STR_CATEGORY : u16= 0x00b2;
pub const TLV_TYPE_STR_DESCR    : u16= 0x00b3;
pub const TLV_TYPE_STR_SIGN     : u16= 0x00b4;
pub const TLV_TYPE_STR_HASH_TAG : u16= 0x00b5;
pub const TLV_TYPE_STR_WIKI_PAGE: u16= 0x00b6;
pub const TLV_TYPE_STR_DATE     : u16= 0x00b7;
pub const TLV_TYPE_STR_PIC_TYPE : u16= 0x00b8;
pub const TLV_TYPE_STR_PIC_AUTH : u16= 0x00b9;
pub const TLV_TYPE_STR_GXS_ID   : u16= 0x00ba;


	/**** Binary Types ****/
pub const TLV_TYPE_CERT_XPGP_DER: u16= 0x0100;
pub const TLV_TYPE_CERT_X509    : u16= 0x0101;
pub const TLV_TYPE_CERT_OPENPGP : u16= 0x0102;

pub const TLV_TYPE_KEY_EVP_PKEY : u16= 0x0110; /* Used (Generic - Distrib) */
pub const TLV_TYPE_KEY_PRIV_RSA : u16= 0x0111; /* not used yet             */
pub const TLV_TYPE_KEY_PUB_RSA  : u16= 0x0112; /* not used yet             */

pub const TLV_TYPE_SIGN_RSA_SHA1: u16= 0x0120; /* Used (Distrib/Forums)    */

pub const TLV_TYPE_BIN_IMAGE    : u16= 0x0130; /* Used (Generic - Forums)  */
pub const TLV_TYPE_BIN_FILEDATA : u16= 0x0140; /* Used - ACTIVE!           */
pub const TLV_TYPE_BIN_SERIALISE: u16= 0x0150; /* Used (Generic - Distrib) */
pub const TLV_TYPE_BIN_GENERIC  : u16= 0x0160; /* Used (DSDV Data)         */
pub const TLV_TYPE_BIN_ENCRYPTED: u16= 0x0170; /* Encrypted data           */


	/**** Compound Types ****/
pub const TLV_TYPE_FILEITEM     : u16= 0x1000;
pub const TLV_TYPE_FILESET      : u16= 0x1001;
pub const TLV_TYPE_FILEDATA     : u16= 0x1002;

pub const TLV_TYPE_KEYVALUE     : u16= 0x1010;
pub const TLV_TYPE_KEYVALUESET  : u16= 0x1011;

pub const TLV_TYPE_STRINGSET    : u16= 0x1020; /* dummy non-existant */
pub const TLV_TYPE_PEERSET      : u16= 0x1021;
pub const TLV_TYPE_HASHSET      : u16= 0x1022;

pub const TLV_TYPE_PGPIDSET     : u16= 0x1023;
pub const TLV_TYPE_RECOGNSET    : u16= 0x1024;
pub const TLV_TYPE_GXSIDSET     : u16= 0x1025;
pub const TLV_TYPE_GXSCIRCLEIDSET: u16= 0x1026;
pub const TLV_TYPE_NODEGROUPIDSET: u16= 0x1027;
pub const TLV_TYPE_GXSMSGIDSET  : u16= 0x1028;

pub const TLV_TYPE_SERVICESET   : u16= 0x1030; 

// *_deprectate should not be used anymore!! 
// We use 1040 for both public and private keys, so that transmitting them still works (backward compatibility), and so that
// signatures are kept. But the two different classes will check that the flags are correct when deserialising.

pub const TLV_TYPE_SECURITY_KEY  : u16= 0x1040;
pub const TLV_TYPE_SECURITYKEYSET: u16= 0x1041;

pub const TLV_TYPE_KEYSIGNATURE    : u16= 0x1050;
pub const TLV_TYPE_KEYSIGNATURESET : u16= 0x1051;
pub const TLV_TYPE_KEYSIGNATURETYPE: u16= 0x1052;

pub const TLV_TYPE_IMAGE        : u16= 0x1060;

pub const TLV_TYPE_ADDRESS_INFO : u16= 0x1070;
pub const TLV_TYPE_ADDRESS_SET  : u16= 0x1071;
pub const TLV_TYPE_ADDRESS      : u16= 0x1072;

pub const TLV_TYPE_DSDV_ENDPOINT: u16= 0x1080;
pub const TLV_TYPE_DSDV_ENTRY   : u16= 0x1081;
pub const TLV_TYPE_DSDV_ENTRY_SET: u16= 0x1082;

#[allow(non_upper_case_globals)]
pub const TLV_TYPE_BAN_ENTRY_dep: u16= 0x1090;
pub const TLV_TYPE_BAN_ENTRY    : u16= 0x1092;
pub const TLV_TYPE_BAN_LIST     : u16= 0x1091;

pub const TLV_TYPE_MSG_ADDRESS  : u16= 0x10A0;
pub const TLV_TYPE_MSG_ID       : u16= 0x10A1;


pub const RSTLV_IMAGE_TYPE_PNG: u32= 0x0001;
pub const RSTLV_IMAGE_TYPE_JPG: u32= 0x0002;