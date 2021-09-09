// Copyright 2021 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.
use blsbs::Slip;
use blsttc::PublicKey;
use rand::Rng;
use serde::{Deserialize, Serialize};
use tiny_keccak::{Hasher, Sha3};

use crate::{DbcContentHash, Denomination, Hash, Result};

///    owner + blinding_factor = owner_blinded
///    encrypt(owner, blinding_factor) = blinding_factor_encrypted
///    owner = owner_blinded - blinding_factor
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct DbcContent {
    owner: PublicKey,

    // temporary: to prevent collision if owner key is re-used.
    nonce: [u8; 32],

    // this is only a hint, DBC recipient(s) must validate Mint's sig and check
    // Denomination of mint's pubkey.
    // idea:  denonomination.amount() == derivation index of pubkey.
    denomination: Denomination,
}

impl DbcContent {
    pub fn new(owner: PublicKey, denomination: Denomination) -> Self {
        Self {
            nonce: rand::thread_rng().gen::<[u8; 32]>(),
            owner,
            denomination,
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut b: Vec<u8> = vec![];
        b.extend(self.nonce);
        b.extend(self.owner.to_bytes());
        b.extend(self.denomination.to_be_bytes());
        b
    }

    pub fn from_bytes(bytes: [u8; 32 + 48 + 2]) -> Result<Self> {
        let mut nonce: [u8; 32] = Default::default();
        nonce.copy_from_slice(&bytes);

        let mut o: [u8; 48] = [0; 48];
        o.copy_from_slice(&bytes[32..32 + 48]);
        let owner = PublicKey::from_bytes(o)?;

        let mut d: [u8; 2] = Default::default();
        d.copy_from_slice(&bytes[32 + 48..]);
        let denomination = Denomination::from_be_bytes(d)?;

        Ok(Self {
            nonce,
            owner,
            denomination,
        })
    }

    pub fn slip(&self) -> Slip {
        let mut slip: Slip = Default::default();
        slip.extend(self.owner.to_bytes());
        slip.extend(self.nonce);
        slip.extend(self.denomination.to_be_bytes());
        slip
    }

    pub fn hash(&self) -> DbcContentHash {
        let mut sha3 = Sha3::v256();
        sha3.update(&self.owner.to_bytes());
        sha3.update(&self.nonce);
        sha3.update(&self.denomination.to_be_bytes());

        let mut hash = [0; 32];
        sha3.finalize(&mut hash);
        Hash(hash)
    }

    pub fn owner(&self) -> &PublicKey {
        &self.owner
    }

    pub fn denomination(&self) -> Denomination {
        self.denomination
    }
}
