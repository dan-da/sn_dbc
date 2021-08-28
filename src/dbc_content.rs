// Copyright 2021 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.
use crate::{Error, Result};
use blsbs::Slip;
use rand::Rng;
use serde::{Deserialize, Serialize};
use std::convert::TryFrom;
use tiny_keccak::{Hasher, Sha3};

use crate::{DbcContentHash, Hash};

#[derive(Clone, Debug, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Denomination {
    One,
    Ten,
    Hundred,
    Thousand,
    TenThousand,
    HundredThousand,
    Million,
    TenMillion,
    HundredMillion,
    Billion,
    TenBillion,
    HundredBillion,
    Trillion,
    TenTrillion,
    HundredTrillion,
    Quadrillion,
    TenQuadrillion,
    HundredQuadrillion,
    Quintillion,
    TenQuintillion,
    Genesis,
}

impl Denomination {
    fn to_be_bytes(self) -> [u8; 1] {
        (self as u8).to_be_bytes()
    }
}

impl TryFrom<u64> for Denomination {
    type Error = Error;

    fn try_from(n: u64) -> Result<Self> {
        match n {
            1u64 => Ok(Self::One),
            10u64 => Ok(Self::Ten),
            100u64 => Ok(Self::Hundred),
            1000u64 => Ok(Self::Thousand),
            10000u64 => Ok(Self::TenThousand),
            100000u64 => Ok(Self::HundredThousand),
            1000000u64 => Ok(Self::Million),
            10000000u64 => Ok(Self::TenMillion),
            100000000u64 => Ok(Self::HundredMillion),
            1000000000u64 => Ok(Self::Billion),
            10000000000u64 => Ok(Self::TenBillion),
            100000000000u64 => Ok(Self::HundredBillion),
            1000000000000u64 => Ok(Self::Trillion),
            10000000000000u64 => Ok(Self::TenTrillion),
            100000000000000u64 => Ok(Self::HundredTrillion),
            1000000000000000u64 => Ok(Self::Quadrillion),
            10000000000000000u64 => Ok(Self::TenQuadrillion),
            100000000000000000u64 => Ok(Self::HundredQuadrillion),
            1000000000000000000u64 => Ok(Self::Quintillion),
            10000000000000000000u64 => Ok(Self::TenQuintillion),
            u64::MAX => Ok(Self::Genesis),
            _ => Err(Error::UnknownDenomination),
        }
    }
}

pub type Amount = Denomination; // For now.

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct DbcContent {
    nonce: [u8; 32],
    // this is only a hint, DBC recipient(s) must validate Mint's sig and check
    // Denomination of mint's pubkey.
    // idea:  amount == derivation index of pubkey.
    amount: Denomination,
}

impl DbcContent {
    pub fn new(amount: Denomination) -> Self {
        Self {
            nonce: rand::thread_rng().gen::<[u8; 32]>(),
            amount,
        }
    }

    pub fn new_with_nonce(nonce: [u8; 32], amount: Denomination) -> Self {
        Self { nonce, amount }
    }

    pub fn slip(&self) -> Slip {
        let mut slip: Slip = Default::default();
        slip.extend(self.amount.to_be_bytes());
        slip
    }

    pub fn hash(&self) -> DbcContentHash {
        let mut sha3 = Sha3::v256();
        sha3.update(&self.nonce);
        sha3.update(&self.amount.to_be_bytes());

        let mut hash = [0; 32];
        sha3.finalize(&mut hash);
        Hash(hash)
    }
}
