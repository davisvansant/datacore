use crate::api::supporting_data_structures::COSEAlgorithmIdentifier;

pub struct PackedAttestationStatementSyntax {
    alg: COSEAlgorithmIdentifier,
    sig: Vec<u8>,
    x5c: Vec<Vec<u8>>,
}

impl PackedAttestationStatementSyntax {
    pub async fn build() -> PackedAttestationStatementSyntax {
        let alg = 3;
        let sig = Vec::with_capacity(0);
        let mut x5c = Vec::with_capacity(0);
        let attestnCert = Vec::with_capacity(0);

        x5c.push(attestnCert);

        PackedAttestationStatementSyntax { alg, sig, x5c }
    }
}
