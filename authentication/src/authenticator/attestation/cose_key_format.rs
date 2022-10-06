pub struct COSEKeyCommonParameters {
    kty: KeyType,
    kid: String,
    alg: COSEAlgorithms,
    key_ops: Vec<KeyOperations>,
    base_IV: String,
}

pub enum KeyType {
    OKP = 1,
    EC2 = 2,
    Symmetric = 4,
}

pub enum COSEAlgorithms {
    EdDSA = -8,
    ES256 = -7,
}

pub enum EllipticCurve {
    Ed25519 = 6,
}

pub enum KeyOperations {
    Sign = 1,
    Verify = 2,
    Encrypt = 3,
    Decrypt = 4,
    WrapKey = 5,
    UnwrapKey = 6,
    DeriveKey = 7,
    DeriveBits = 8,
    MACCreate = 9,
    MACVerify = 10,
}

pub struct OctetKeyPair {
    crv: EllipticCurve,
    x: [u8; 32],
    d: [u8; 32],
}
