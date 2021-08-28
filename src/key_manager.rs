// Copyright 2021 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::{Error, Result};
use blsttc::{SecretKeyShare};
pub use blsttc::{PublicKey, PublicKeySet, Signature};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use blsbs::{BlindSignerShare, Slip, Envelope, SignedEnvelopeShare, SignatureExaminer};

// #[derive(Debug, Clone, Hash, PartialEq, Eq, Deserialize, Serialize)]
// pub struct NodeSignature {
//     index: u64,
//     sig: SignatureShare,
// }

// impl NodeSignature {
//     pub fn new(index: u64, sig: SignatureShare) -> Self {
//         Self { index, sig }
//     }

//     pub fn threshold_crypto(&self) -> (u64, &SignatureShare) {
//         (self.index, &self.sig)
//     }
// }

pub trait KeyManager {
    type Error: std::error::Error;
    fn sign_envelope(&self, envelope: Envelope) -> Result<SignedEnvelopeShare, Self::Error>;
    fn public_key_set(&self) -> Result<PublicKeySet, Self::Error>;
    fn verify_slip(
        &self,
        slip: &Slip,
        key: &PublicKey,
        signature: &Signature,
    ) -> Result<(), Self::Error>;
    fn verify_envelope(
        &self,
        envelope: &Envelope,
        key: &PublicKey,
        signature: &Signature,
    ) -> Result<(), Self::Error>;
    fn verify_known_key(&self, key: &PublicKey) -> Result<(), Self::Error>;
}

// #[derive(Debug, Clone, Serialize, Deserialize)]
#[derive(Debug, Clone)]
pub struct SimpleSigner {
    blind_signer_share: BlindSignerShare,
}

#[cfg(feature = "dkg")]
impl From<bls_dkg::outcome::Outcome> for SimpleSigner {
    fn from(outcome: bls_dkg::outcome::Outcome) -> Self {
        
        Self {
            blind_signer_share: BlindSignerShare::new(outcome.secret_key_share, outcome.index, outcome.public_key_set),
        }
    }
}

impl SimpleSigner {
    pub fn new(public_key_set: PublicKeySet, secret_key_share: (u64, SecretKeyShare)) -> Self {
        Self {
            blind_signer_share: BlindSignerShare::new(secret_key_share.1, secret_key_share.0, public_key_set),
        }
    }

    fn public_key_set(&self) -> &PublicKeySet {
        self.blind_signer_share.public_key_set()
    }

    fn sign_envelope(&self, envelope: Envelope) -> Result<SignedEnvelopeShare> {
        self.blind_signer_share.sign_envelope(envelope).map_err(|e| Error::from(e))
    }

    // fn sign<M: AsRef<[u8]>>(&self, msg: M) -> blsttc::SignatureShare {
    //     self.blind_signer_share.sign(msg)
    // }
}

// #[derive(Debug, Clone, Serialize, Deserialize)]
#[derive(Debug, Clone)]
pub struct SimpleKeyManager {
    signer: SimpleSigner,
    genesis_key: PublicKey,
    cache: Keys,
}

impl SimpleKeyManager {
    pub fn new(signer: SimpleSigner, genesis_key: PublicKey) -> Self {
        let public_key_set = signer.public_key_set();
        let mut cache = Keys::default();
        cache.add_known_key(genesis_key);
        cache.add_known_key(public_key_set.public_key());
        Self {
            signer,
            genesis_key,
            cache,
        }
    }
}

impl KeyManager for SimpleKeyManager {
    type Error = crate::Error;

    fn public_key_set(&self) -> Result<PublicKeySet> {
        Ok(self.signer.public_key_set().clone())
    }

    fn sign_envelope(&self, envelope: Envelope) -> Result<SignedEnvelopeShare> {
        self.signer.sign_envelope(envelope)
    }

    fn verify_slip(&self, slip: &Slip, key: &PublicKey, signature: &Signature) -> Result<()> {
        self.cache.verify_slip(slip, key, signature)
    }

    fn verify_envelope(&self, envelope: &Envelope, key: &PublicKey, signature: &Signature) -> Result<()> {
        self.cache.verify_envelope(envelope, key, signature)
    }

    fn verify_known_key(&self, key: &PublicKey) -> Result<()> {
        self.cache.verify_known_key(key)
    }
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
struct Keys(HashSet<PublicKey>);

impl From<Vec<PublicKey>> for Keys {
    fn from(keys: Vec<PublicKey>) -> Self {
        Self(keys.into_iter().collect())
    }
}

impl Keys {
    pub fn add_known_key(&mut self, key: PublicKey) {
        self.0.insert(key);
    }

    fn verify_slip(&self, slip: &Slip, key: &PublicKey, sig: &Signature) -> Result<()> {
        self.verify_known_key(key)?;
        let is_verified = SignatureExaminer::verify_signature_on_slip(slip, sig, key);
        if is_verified {
            Ok(())
        } else {
            Err(Error::FailedSignature)
        }
    }

    fn verify_envelope(&self, envelope: &Envelope, key: &PublicKey, sig: &Signature) -> Result<()> {
        self.verify_known_key(key)?;
        let is_verified = SignatureExaminer::verify_signature_on_envelope(envelope, sig, key);
        if is_verified {
            Ok(())
        } else {
            Err(Error::FailedSignature)
        }
    }

    fn verify_known_key(&self, key: &PublicKey) -> Result<()> {
        if self.0.contains(key) {
            Ok(())
        } else {
            Err(Error::UnrecognisedAuthority)
        }
    }
}
