// Copyright 2022 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.
use thiserror::Error;

use crate::KeyImage;

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

/// Specialisation of `std::Result`.
pub type Result<T, E = Error> = std::result::Result<T, E>;

#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[allow(clippy::large_enum_variant)]
#[derive(Error, Debug, Clone)]
#[non_exhaustive]
/// Node error variants.
pub enum Error {
    #[error("Failed signature check.")]
    FailedSignature,

    #[error("Unrecognised authority.")]
    UnrecognisedAuthority,

    #[error("Invalid SpentProof Signature for {0:?}.  Error: {1}")]
    InvalidSpentProofSignature(KeyImage, String),

    #[error("Transaction hash does not match the transaction signed by spentbook")]
    InvalidTransactionHash,

    #[error("Dbc Content is not a member of transaction outputs")]
    DbcContentNotPresentInTransactionOutput,

    #[error("OutputProof not found in transaction outputs")]
    OutputProofNotFound,

    #[error("public key is not unique across all transaction outputs")]
    PublicKeyNotUniqueAcrossOutputs,

    #[error("The number of SpentProof does not match the number of input MlsagSignature")]
    SpentProofInputLenMismatch,

    #[error("A SpentProof KeyImage does not match an MlsagSignature KeyImage")]
    SpentProofInputKeyImageMismatch,

    #[error("We need at least one spent proof share for {0:?} to build a SpentProof")]
    MissingSpentProofShare(KeyImage),

    #[error("Decryption failed")]
    DecryptionBySecretKeyFailed,

    #[error("Invalid AmountSecret bytes")]
    AmountSecretsBytesInvalid,

    #[error("Amount Commitments do not match")]
    AmountCommitmentsDoNotMatch,

    #[error("Secret key unavailable")]
    SecretKeyUnavailable,

    #[error("Public key not found")]
    PublicKeyNotFound,

    #[error("Insufficient decoys available for all inputs")]
    InsufficientDecoys,

    #[error("Secret key does not match public key")]
    SecretKeyDoesNotMatchPublicKey,

    // temporary.  should be part of (future) spentbook module.
    #[error("Key image has already been spent")]
    SpentbookKeyImageAlreadySpent,

    // temporary.  should be part of (future) spentbook module.
    #[error("The transaction input has {0:?} public keys but found {1:?} matching outputs in spentbook.")]
    SpentbookRingSizeMismatch(usize, usize),

    #[error("Bls error: {0}")]
    Blsttc(#[from] blsttc::error::Error),

    /// blst_ringct error.
    #[error("ringct error: {0}")]
    RingCt(#[from] blst_ringct::Error),

    #[cfg_attr(feature = "serde", serde(skip))]
    #[error("Infallible.  Can never fail")]
    Infallible(#[from] std::convert::Infallible),
}
