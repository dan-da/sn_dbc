// Copyright 2021 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.
use crate::{Error, Result};
use serde::{Deserialize, Serialize};
use std::convert::TryFrom;

pub type Amount = u64;

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
    pub fn to_be_bytes(self) -> [u8; 1] {
        (self as u8).to_be_bytes()
    }

    pub fn amount(&self) -> Amount {
        match *self {
            Self::One => 1u64,
            Self::Ten => 10u64,
            Self::Hundred => 100u64,
            Self::Thousand => 1000u64,
            Self::TenThousand => 10000u64,
            Self::HundredThousand => 100000u64,
            Self::Million => 1000000u64,
            Self::TenMillion => 10000000u64,
            Self::HundredMillion => 100000000u64,
            Self::Billion => 1000000000u64,
            Self::TenBillion => 10000000000u64,
            Self::HundredBillion => 100000000000u64,
            Self::Trillion => 1000000000000u64,
            Self::TenTrillion => 10000000000000u64,
            Self::HundredTrillion => 100000000000000u64,
            Self::Quadrillion => 1000000000000000u64,
            Self::TenQuadrillion => 10000000000000000u64,
            Self::HundredQuadrillion => 100000000000000000u64,
            Self::Quintillion => 1000000000000000000u64,
            Self::TenQuintillion => 10000000000000000000u64,
            Self::Genesis => u64::MAX,
        }
    }

    pub fn all() -> Vec<Self> {
        vec![
            Self::One,
            Self::Ten,
            Self::Hundred,
            Self::Thousand,
            Self::TenThousand,
            Self::HundredThousand,
            Self::Million,
            Self::TenMillion,
            Self::HundredMillion,
            Self::Billion,
            Self::TenBillion,
            Self::HundredBillion,
            Self::Trillion,
            Self::TenTrillion,
            Self::HundredTrillion,
            Self::Quadrillion,
            Self::TenQuadrillion,
            Self::HundredQuadrillion,
            Self::Quintillion,
            Self::TenQuintillion,
            Self::Genesis,
        ]
    }

    pub fn make_change(target_amount: Amount) -> Vec<Self> {
        let denoms = Self::all();

        // This is the greedy coin algo.
        // It is simple, but can fail for certain denom sets and target amounts as
        // it picks more coins than necessary.
        // Eg for denoms: [1, 15, 25] and target amount = 30, it picks
        // [25,1,1,1,1,1] instead of [15,15].
        // To avoid this, the denom set must be chosen carefully.
        // See https://stackoverflow.com/questions/13557979/why-does-the-greedy-coin-change-algorithm-not-work-for-some-coin-sets
        let mut remaining = target_amount;
        let mut chosen = vec![];
        for denom in denoms.iter().rev() {
            let amount = denom.amount();
            let n = remaining / amount;
            if n > 0 {
                for _i in 0..n {
                    chosen.push(*denom);
                }
                remaining %= amount;
                if remaining == 0 {
                    break;
                }
            }
        }
        chosen
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

#[cfg(test)]
mod tests {
    use super::*;
    use quickcheck_macros::quickcheck;

    #[quickcheck]
    fn make_change(amounts: Vec<Amount>) -> Result<()> {
        let mut max_coins = 0usize;
        let mut max_coins_amt: Amount = Default::default();
        for amt in amounts.into_iter() {
            let coins = Denomination::make_change(amt);
            // println!("amount: {}, coins len: {}, coins: {:?}", amt, coins.len(), coins);
            let sum: Amount = coins.iter().map(|c| c.amount()).sum();
            assert_eq!(sum, amt);
            if coins.len() > max_coins {
                max_coins = coins.len();
                max_coins_amt = amt;
            }
        }
        println!("max coins: {}, for amount: {}", max_coins, max_coins_amt);

        Ok(())
    }
}
