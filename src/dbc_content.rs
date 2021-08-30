// Copyright 2021 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.
use blsbs::Slip;
use rand::Rng;
use serde::{Deserialize, Serialize};
use tiny_keccak::{Hasher, Sha3};

use crate::{DbcContentHash, Denomination, Hash};

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct DbcContent {
    nonce: [u8; 32],
    // this is only a hint, DBC recipient(s) must validate Mint's sig and check
    // Denomination of mint's pubkey.
    // idea:  denonomination.amount() == derivation index of pubkey.
    denomination: Denomination,
}

impl DbcContent {
    pub fn new(denomination: Denomination) -> Self {
        Self {
            nonce: rand::thread_rng().gen::<[u8; 32]>(),
            denomination,
        }
    }

    pub fn new_with_nonce(nonce: [u8; 32], denomination: Denomination) -> Self {
        Self {
            nonce,
            denomination,
        }
    }

    pub fn slip(&self) -> Slip {
        let mut slip: Slip = Default::default();
        slip.extend(self.denomination.to_be_bytes());
        slip
    }

    pub fn hash(&self) -> DbcContentHash {
        let mut sha3 = Sha3::v256();
        sha3.update(&self.nonce);
        sha3.update(&self.denomination.to_be_bytes());

        let mut hash = [0; 32];
        sha3.finalize(&mut hash);
        Hash(hash)
    }

    pub fn denomination(&self) -> Denomination {
        self.denomination
    }
}
