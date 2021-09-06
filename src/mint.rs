// Copyright 2021 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

// Code required to mint Dbcs
// The in the most basic terms means
// a valid input DBC can be split into
// 1 or more DBCs as long as
// input is vaid
// Outputs <= input value

use crate::{
    Amount, Dbc, DbcContent, DbcContentHash, DbcEnvelope, DbcTransaction, Denomination, Error,
    Hash, KeyManager, PublicKeySet, Result,
};
// use serde::{Deserialize, Serialize};
use blsbs::{SignedEnvelopeShare, SlipPreparer};
use std::{
    collections::{BTreeMap, BTreeSet, HashSet},
    iter::FromIterator,
};

// pub type MintNodeSignatures = BTreeMap<Envelope, (PublicKeySet, SignedEnvelopeShare)>;

pub const GENESIS_DBC_INPUT: Hash = Hash([0u8; 32]);

pub trait SpendBook: std::fmt::Debug + Clone {
    type Error: std::error::Error;

    fn lookup(&self, dbc_hash: &DbcContentHash) -> Result<Option<&DbcTransaction>, Self::Error>;
    fn log(
        &mut self,
        dbc_hash: DbcContentHash,
        transaction: DbcTransaction,
    ) -> Result<(), Self::Error>;
}

// #[derive(Debug, Default, Clone, Serialize, Deserialize)]
#[derive(Debug, Default, Clone)]
pub struct SimpleSpendBook {
    pub transactions: BTreeMap<DbcContentHash, DbcTransaction>,
}

impl SpendBook for SimpleSpendBook {
    type Error = std::convert::Infallible;

    fn lookup(&self, dbc_hash: &DbcContentHash) -> Result<Option<&DbcTransaction>, Self::Error> {
        Ok(self.transactions.get(dbc_hash))
    }

    fn log(
        &mut self,
        dbc_hash: DbcContentHash,
        transaction: DbcTransaction,
    ) -> Result<(), Self::Error> {
        self.transactions.insert(dbc_hash, transaction);
        Ok(())
    }
}

impl<'a> IntoIterator for &'a SimpleSpendBook {
    type Item = (&'a DbcContentHash, &'a DbcTransaction);
    type IntoIter = std::collections::btree_map::Iter<'a, DbcContentHash, DbcTransaction>;

    fn into_iter(self) -> Self::IntoIter {
        self.transactions.iter()
    }
}

impl IntoIterator for SimpleSpendBook {
    type Item = (DbcContentHash, DbcTransaction);
    type IntoIter = std::collections::btree_map::IntoIter<DbcContentHash, DbcTransaction>;

    fn into_iter(self) -> Self::IntoIter {
        self.transactions.into_iter()
    }
}

impl SimpleSpendBook {
    pub fn new() -> Self {
        Self {
            transactions: Default::default(),
        }
    }
}

// #[derive(Eq, PartialEq, Debug, Clone, Deserialize, Serialize)]
#[derive(Eq, PartialEq, Debug, Clone)]
pub struct ReissueTransaction {
    pub inputs: HashSet<Dbc>,
    pub outputs: HashSet<DbcEnvelope>,
}

impl ReissueTransaction {
    pub fn blinded(&self) -> DbcTransaction {
        DbcTransaction {
            inputs: BTreeSet::from_iter(self.inputs.iter().map(|i| i.name())),
            outputs: self.outputs.clone(),
        }
    }

    pub fn validate<K: KeyManager>(&self, verifier: &K) -> Result<()> {
        self.validate_balance()?;
        self.validate_input_dbcs(verifier)?;
        self.validate_outputs()?;
        Ok(())
    }

    fn validate_balance(&self) -> Result<()> {
        let inputs: Amount = self
            .inputs
            .iter()
            .map(|d| d.content.denomination().amount())
            .sum();
        let outputs: Amount = self.outputs.iter().map(|d| d.denomination.amount()).sum();

        if inputs != outputs {
            Err(Error::DbcReissueRequestDoesNotBalance)
        } else {
            Ok(())
        }
    }

    fn validate_input_dbcs<K: KeyManager>(&self, verifier: &K) -> Result<()> {
        if self.inputs.is_empty() {
            return Err(Error::TransactionMustHaveAnInput);
        }

        for input in self.inputs.iter() {
            input.confirm_valid(verifier)?;
        }

        Ok(())
    }

    fn validate_outputs(&self) -> Result<()> {
        // Todo: outputs are opaque to mint.  anything to do here?

        Ok(())
    }
}

// #[derive(Eq, PartialEq, Debug, Clone, Deserialize, Serialize)]
#[derive(Eq, PartialEq, Debug, Clone)]
pub struct ReissueRequest {
    pub transaction: ReissueTransaction,
}

// #[derive(Eq, PartialEq, Debug, Clone, Deserialize, Serialize)]
#[derive(Eq, PartialEq, Debug, Clone)]
pub struct ReissueShare {
    pub dbc_transaction: DbcTransaction,
    pub signed_envelope_shares: Vec<SignedEnvelopeShare>, // fixme: Vec does not guarantee uniqueness.
    pub public_key_set: PublicKeySet,
    // pub mint_node_signatures: MintNodeSignatures,
}

// #[derive(Debug, Clone, Deserialize, Serialize)]
#[derive(Debug, Clone)]
pub struct MintNode<K, S>
where
    K: KeyManager,
    S: SpendBook,
{
    pub(crate) key_manager: K,
    pub spendbook: S,
}

impl<K: KeyManager, S: SpendBook> MintNode<K, S> {
    pub fn new(key_manager: K, spendbook: S) -> Self {
        Self {
            key_manager,
            spendbook,
        }
    }

    pub fn issue_genesis_dbc(
        &mut self,
    ) -> Result<(
        DbcContent,
        DbcTransaction,
        SlipPreparer,
        PublicKeySet,
        Vec<SignedEnvelopeShare>,
    )> {
        let slip_preparer = SlipPreparer::from_fr(1); // deterministic/known
        let content = DbcContent::new_with_nonce(GENESIS_DBC_INPUT.0, Denomination::Genesis); // deterministic/known
        let envelope = slip_preparer.place_slip_in_envelope(&content.slip());
        let dbc_envelope = DbcEnvelope {
            envelope,
            denomination: content.denomination(),
        };

        let transaction = DbcTransaction {
            inputs: BTreeSet::from_iter([GENESIS_DBC_INPUT]),
            outputs: HashSet::from_iter([dbc_envelope.clone()]),
        };

        match self
            .spendbook
            .lookup(&GENESIS_DBC_INPUT)
            .map_err(|e| Error::SpendBook(e.to_string()))?
        {
            Some(tx) if tx != &transaction => return Err(Error::GenesisInputAlreadySpent),
            _ => (),
        }

        self.spendbook
            .log(GENESIS_DBC_INPUT, transaction.clone())
            .map_err(|e| Error::SpendBook(e.to_string()))?;

        let signed_envelope_shares = vec![self
            .key_manager
            .sign_envelope(dbc_envelope.envelope, dbc_envelope.denomination)
            .map_err(|e| Error::Signing(e.to_string()))?];

        let public_key_set = self
            .key_manager
            .public_key_set()
            .map_err(|e| Error::Signing(e.to_string()))?;

        Ok((
            content,
            transaction,
            slip_preparer,
            public_key_set,
            signed_envelope_shares,
        ))
    }

    pub fn is_spent(&self, dbc_hash: DbcContentHash) -> Result<bool> {
        Ok(self
            .spendbook
            .lookup(&dbc_hash)
            .map_err(|e| Error::SpendBook(e.to_string()))?
            .is_some())
    }

    pub fn key_manager(&self) -> &K {
        &self.key_manager
    }

    pub fn reissue(
        &mut self,
        reissue_req: ReissueRequest,
        inputs_belonging_to_mint: BTreeSet<DbcContentHash>,
    ) -> Result<ReissueShare> {
        reissue_req.transaction.validate(self.key_manager())?;
        let dbc_transaction = reissue_req.transaction.blinded();

        if !inputs_belonging_to_mint.is_subset(&dbc_transaction.inputs) {
            // fixme:  better error name?
            return Err(Error::FilteredInputNotPresent);
        }

        // todo: validate that each input has mint's sig and detect
        // amount(s) from Mint Sig.

        let public_key_set = self
            .key_manager
            .public_key_set()
            .map_err(|e| Error::Signing(e.to_string()))?;

        // Validate that each input has not yet been spent.
        for input in inputs_belonging_to_mint.iter() {
            if let Some(dbc_transaction) = self
                .spendbook
                .lookup(input)
                .map_err(|e| Error::SpendBook(e.to_string()))?
                .cloned()
            {
                // This input has already been spent, return the spend transaction to the user
                // fixme:  shouldn't we already have full mint sig from the spendbook?
                //         we shouldn't need to sign again with a sigshare.
                let signed_envelope_shares = self.sign_output_envelopes(&dbc_transaction)?;
                return Err(Error::DbcAlreadySpent {
                    dbc_transaction,
                    public_key_set,
                    signed_envelope_shares,
                });
            }
        }

        let signed_envelope_shares = self.sign_output_envelopes(&dbc_transaction)?;

        for input in reissue_req
            .transaction
            .inputs
            .iter()
            .filter(|&i| inputs_belonging_to_mint.contains(&i.name()))
        {
            self.spendbook
                .log(input.name(), dbc_transaction.clone())
                .map_err(|e| Error::SpendBook(e.to_string()))?;
        }

        let reissue_share = ReissueShare {
            dbc_transaction,
            signed_envelope_shares,
            public_key_set,
        };

        Ok(reissue_share)
    }

    fn sign_output_envelopes(
        &self,
        transaction: &DbcTransaction,
    ) -> Result<Vec<SignedEnvelopeShare>> {
        transaction
            .outputs
            .iter()
            .map(|e| {
                self.key_manager
                    .sign_envelope(e.envelope.clone(), e.denomination)
                    .map_err(|e| Error::Signing(e.to_string()))
            })
            .collect::<Result<_>>()
    }

    // Used in testing / benchmarking
    pub fn snapshot_spendbook(&self) -> S {
        self.spendbook.clone()
    }

    // Used in testing / benchmarking
    pub fn reset_spendbook(&mut self, spendbook: S) {
        self.spendbook = spendbook
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Serialize;
    // use quickcheck_macros::quickcheck;

    use crate::{
        Amount,
        // tests::{TinyInt, TinyVec},
        DbcBuilder,
        Output, //  SimpleKeyManager, SimpleSigner,
        SimpleKeyManager,
        SimpleSigner,
        TransactionBuilder,
    };

    /// Serialize anything serializable as big endian bytes
    fn to_be_bytes<T: Serialize>(sk: &T) -> Vec<u8> {
        bincode::serialize(&sk).unwrap()
    }

    fn genesis() -> Result<(
        Dbc,
        MintNode<SimpleKeyManager, SimpleSpendBook>,
        bls_dkg::outcome::Outcome,
    )> {
        let genesis_owner = crate::bls_dkg_id();

        let key_manager = SimpleKeyManager::new(
            SimpleSigner::from(genesis_owner.clone()),
            genesis_owner.public_key_set.public_key(),
        );
        let mut genesis_node = MintNode::new(key_manager, SimpleSpendBook::new());

        let (
            gen_dbc_content,
            _gen_dbc_trans,
            slip_preparer,
            mint_public_key_set,
            signed_envelope_shares,
        ) = genesis_node.issue_genesis_dbc().unwrap();

        let ses = &signed_envelope_shares[0];

        let mint_signature = mint_public_key_set
            .combine_signatures(vec![(
                ses.signature_share_index(),
                &ses.signature_share_for_slip(slip_preparer.blinding_factor())?,
            )])
            .unwrap();

        let denom_idx = gen_dbc_content.denomination().amount().to_be_bytes();
        let mint_derived_pks = mint_public_key_set.derive_child(&denom_idx);

        let genesis_dbc = Dbc {
            content: gen_dbc_content,
            mint_public_key: mint_derived_pks.public_key(),
            mint_signature,
        };

        Ok((genesis_dbc, genesis_node, genesis_owner))
    }

    // #[quickcheck]
    #[test]
    fn prop_genesis() -> Result<(), Error> {
        let (genesis_dbc, genesis_node, _genesis_owner) = genesis()?;

        assert_eq!(genesis_dbc.denomination(), Denomination::Genesis);
        assert!(genesis_dbc
            .confirm_valid(genesis_node.key_manager())
            .is_ok());

        Ok(())
    }

    // #[quickcheck]
    #[test]
    fn reissue_genesis() -> Result<(), Error> {
        let (genesis_dbc, mut genesis_node, _genesis_owner) = genesis()?;

        assert!(genesis_dbc
            .confirm_valid(genesis_node.key_manager())
            .is_ok());

        let (tx, outputs_content) = TransactionBuilder::default()
            .add_input(genesis_dbc.clone())
            .add_output(Output {
                denomination: Denomination::Genesis,
            })
            .build()?;

        let rr = ReissueRequest {
            transaction: tx.clone(),
        };

        let rs = genesis_node.reissue(rr, BTreeSet::from_iter([genesis_dbc.name()]))?;

        let dbcs = DbcBuilder::new(tx)
            .add_outputs_content(outputs_content)
            .add_reissue_share(rs)
            .build()?;

        // Just to give us a rough idea of the DBC size.
        // note that bincode typically adds some bytes.
        // todo: add a Dbc::to_bytes() method.
        let bytes = to_be_bytes(&dbcs[0]);
        println!("Dbc outputs count: {:?}", dbcs.len());
        println!("Dbc size: {:?}", bytes.len());

        assert_eq!(dbcs.len(), 1);
        assert_ne!(dbcs[0].name(), genesis_dbc.name());
        assert_eq!(dbcs[0].denomination(), genesis_dbc.denomination());

        Ok(())
    }

    #[test]
    fn reissue_genesis_multi_output() -> Result<(), Error> {
        let (genesis_dbc, mut genesis_node, _genesis_owner) = genesis()?;

        assert!(genesis_dbc
            .confirm_valid(genesis_node.key_manager())
            .is_ok());

        let pay_amt = Amount::MAX - 1;
        let pay_denoms = Denomination::make_change(pay_amt);
        println!("pay: {:#?}", pay_denoms);
        let pay_outputs: Vec<Output> = pay_denoms
            .iter()
            .map(|d| Output { denomination: *d })
            .collect();
        let change_amt = Denomination::Genesis.amount() - pay_amt;
        let change_denoms = Denomination::make_change(change_amt);
        let change_outputs: Vec<Output> = change_denoms
            .iter()
            .map(|d| Output { denomination: *d })
            .collect();
        println!("change: {:#?}", change_denoms);

        let num_outputs = pay_outputs.len() + change_outputs.len();

        let (tx, outputs_content) = TransactionBuilder::default()
            .add_input(genesis_dbc.clone())
            .add_outputs(pay_outputs)
            .add_outputs(change_outputs)
            .build()?;

        let rr = ReissueRequest {
            transaction: tx.clone(),
        };

        let rs = genesis_node.reissue(rr, BTreeSet::from_iter([genesis_dbc.name()]))?;

        let dbcs = DbcBuilder::new(tx)
            .add_outputs_content(outputs_content)
            .add_reissue_share(rs)
            .build()?;

        // Just to give us a rough idea of the DBC size.
        // note that bincode typically adds some bytes.
        // todo: add a Dbc::to_bytes() method.
        let bytes = to_be_bytes(&dbcs[0]);
        println!("Dbc outputs count: {:?}", dbcs.len());
        println!("Dbc size: {:?}", bytes.len());

        let outputs_sum: Amount = dbcs.iter().map(|d| d.denomination().amount()).sum();

        assert_eq!(dbcs.len(), num_outputs);
        assert_ne!(dbcs[0].name(), genesis_dbc.name());
        assert_eq!(outputs_sum, Denomination::Genesis.amount());

        Ok(())
    }

    /*

        #[quickcheck]
        fn prop_splitting_the_genesis_dbc(output_amounts: TinyVec<TinyInt>) -> Result<(), Error> {
            let output_amounts =
                Vec::from_iter(output_amounts.into_iter().map(TinyInt::coerce::<Amount>));
            let n_outputs = output_amounts.len();
            let output_amount = output_amounts.iter().sum();

            let genesis_owner = crate::bls_dkg_id();
            let genesis_key = genesis_owner.public_key_set.public_key();
            let key_manager =
                SimpleKeyManager::new(SimpleSigner::from(genesis_owner.clone()), genesis_key);
            let mut genesis_node = Mint::new(key_manager.clone(), SimpleSpendBook::new());

            let (gen_dbc_content, gen_dbc_tx, (gen_key_set, gen_node_sig)) =
                genesis_node.issue_genesis_dbc(output_amount)?;
            let genesis_sig = gen_key_set.combine_signatures(vec![gen_node_sig.threshold_crypto()])?;

            let genesis_dbc = Dbc {
                content: gen_dbc_content,
                transaction: gen_dbc_tx,
                transaction_sigs: BTreeMap::from_iter([(
                    GENESIS_DBC_INPUT,
                    (genesis_key, genesis_sig),
                )]),
            };
            let gen_dbc_name = genesis_dbc.name();

            let genesis_amount_secrets =
                DbcHelper::decrypt_amount_secrets(&genesis_owner, &genesis_dbc.content)?;

            let output_owner = crate::bls_dkg_id();
            let output_owner_pk = output_owner.public_key_set.public_key();

            let (reissue_tx, _output_owners) = crate::TransactionBuilder::default()
                .add_input(genesis_dbc, genesis_amount_secrets)
                .add_outputs(output_amounts.iter().map(|a| crate::Output {
                    amount: *a,
                    owner: output_owner_pk,
                }))
                .build()?;

            let sig_share = genesis_owner
                .secret_key_share
                .sign(&reissue_tx.blinded().hash());

            let sig = genesis_owner
                .public_key_set
                .combine_signatures(vec![(genesis_owner.index, &sig_share)])?;

            let reissue_req = ReissueRequest {
                transaction: reissue_tx.clone(),
                input_ownership_proofs: HashMap::from_iter([(gen_dbc_name, (genesis_key, sig))]),
            };

            let reissue_share =
                match genesis_node.reissue(reissue_req, BTreeSet::from_iter([gen_dbc_name])) {
                    Ok(rs) => {
                        // Verify that at least one output was present.
                        assert_ne!(n_outputs, 0);
                        rs
                    }
                    Err(Error::DbcReissueRequestDoesNotBalance) => {
                        // Verify that no outputs were present and we got correct validation error.
                        assert_eq!(n_outputs, 0);
                        return Ok(());
                    }
                    Err(e) => return Err(e),
                };

            // Aggregate ReissueShare to build output DBCs
            let mut dbc_builder = DbcBuilder::new(reissue_tx);
            dbc_builder = dbc_builder.add_reissue_share(reissue_share);
            let output_dbcs = dbc_builder.build()?;

            for dbc in output_dbcs.iter() {
                let dbc_amount = DbcHelper::decrypt_amount(&output_owner, &dbc.content)?;
                assert!(output_amounts.iter().any(|a| *a == dbc_amount));
                assert!(dbc.confirm_valid(&key_manager).is_ok());
            }

            assert_eq!(
                output_dbcs
                    .iter()
                    .map(|dbc| { DbcHelper::decrypt_amount(&output_owner, &dbc.content) })
                    .sum::<Result<Amount, _>>()?,
                output_amount
            );

            Ok(())
        }

        #[test]
        fn test_double_spend_protection() -> Result<()> {
            let genesis_owner = crate::bls_dkg_id();
            let genesis_key = genesis_owner.public_key_set.public_key();
            let key_manager =
                SimpleKeyManager::new(SimpleSigner::from(genesis_owner.clone()), genesis_key);
            let mut genesis_node = Mint::new(key_manager, SimpleSpendBook::new());

            let (gen_dbc_content, gen_dbc_tx, (gen_key_set, gen_node_sig)) =
                genesis_node.issue_genesis_dbc(1000)?;
            let genesis_sig = gen_key_set.combine_signatures(vec![gen_node_sig.threshold_crypto()])?;

            let genesis_dbc = Dbc {
                content: gen_dbc_content,
                transaction: gen_dbc_tx,
                transaction_sigs: BTreeMap::from_iter([(
                    GENESIS_DBC_INPUT,
                    (genesis_key, genesis_sig),
                )]),
            };
            let gen_dbc_name = genesis_dbc.name();

            let genesis_amount_secrets =
                DbcHelper::decrypt_amount_secrets(&genesis_owner, &genesis_dbc.content)?;

            let output_owner = crate::bls_dkg_id();
            let (reissue_tx, _output_owners) = crate::TransactionBuilder::default()
                .add_input(genesis_dbc.clone(), genesis_amount_secrets)
                .add_output(crate::Output {
                    amount: 1000,
                    owner: output_owner.public_key_set.public_key(),
                })
                .build()?;

            let sig_share = genesis_node
                .key_manager
                .sign(&reissue_tx.blinded().hash())?;

            let sig = genesis_node
                .key_manager
                .public_key_set()?
                .combine_signatures(vec![sig_share.threshold_crypto()])?;

            let reissue_req = ReissueRequest {
                transaction: reissue_tx,
                input_ownership_proofs: HashMap::from_iter([(gen_dbc_name, (genesis_key, sig))]),
            };

            let reissue_share =
                genesis_node.reissue(reissue_req, BTreeSet::from_iter([gen_dbc_name]))?;
            let t = reissue_share.dbc_transaction;
            let s = reissue_share.mint_node_signatures;

            let (double_spend_reissue_tx, _output_owners) = crate::TransactionBuilder::default()
                .add_input(genesis_dbc, genesis_amount_secrets)
                .add_output(crate::Output {
                    amount: 1000,
                    owner: output_owner.public_key_set.public_key(),
                })
                .build()?;

            let node_share = genesis_node
                .key_manager
                .sign(&double_spend_reissue_tx.blinded().hash())?;

            let sig = genesis_node
                .key_manager
                .public_key_set()?
                .combine_signatures(vec![node_share.threshold_crypto()])?;

            let double_spend_reissue_req = ReissueRequest {
                transaction: double_spend_reissue_tx,
                input_ownership_proofs: HashMap::from_iter([(gen_dbc_name, (genesis_key, sig))]),
            };

            let res = genesis_node.reissue(
                double_spend_reissue_req,
                BTreeSet::from_iter([gen_dbc_name]),
            );

            println!("res {:?}", res);
            assert!(matches!(
                res,
                Err(Error::DbcAlreadySpent { transaction, transaction_sigs }) if transaction == t && transaction_sigs == s
            ));

            Ok(())
        }

        #[quickcheck]
        fn prop_dbc_transaction_many_to_many(
            // the amount of each input transaction
            input_amounts: TinyVec<TinyInt>,
            // The amount for each transaction output
            output_amounts: TinyVec<TinyInt>,
            // Controls which output dbc's will receive extra parent hashes
            extra_output_parents: TinyVec<TinyInt>,
            // Include a valid ownership proof for the following inputs
            input_owner_proofs: TinyVec<TinyInt>,
            // Include an invalid ownership proof for the following inputs
            invalid_input_owner_proofs: TinyVec<TinyInt>,
        ) -> Result<(), Error> {
            let input_amounts =
                Vec::from_iter(input_amounts.into_iter().map(TinyInt::coerce::<Amount>));

            let output_amounts =
                Vec::from_iter(output_amounts.into_iter().map(TinyInt::coerce::<Amount>));

            let extra_output_parents = Vec::from_iter(
                extra_output_parents
                    .into_iter()
                    .map(TinyInt::coerce::<usize>),
            );

            let inputs_to_create_owner_proofs =
                BTreeSet::from_iter(input_owner_proofs.into_iter().map(TinyInt::coerce::<usize>));

            let inputs_to_create_invalid_owner_proofs = BTreeSet::from_iter(
                invalid_input_owner_proofs
                    .into_iter()
                    .map(TinyInt::coerce::<usize>),
            );

            let genesis_owner = crate::bls_dkg_id();
            let genesis_key = genesis_owner.public_key_set.public_key();
            let key_manager = SimpleKeyManager::new(
                SimpleSigner::from(genesis_owner.clone()),
                genesis_owner.public_key_set.public_key(),
            );
            let mut genesis_node = Mint::new(key_manager, SimpleSpendBook::new());

            let genesis_amount: Amount = input_amounts.iter().sum();
            let (gen_dbc_content, gen_dbc_tx, (_gen_key, gen_node_sig)) =
                genesis_node.issue_genesis_dbc(genesis_amount)?;

            let genesis_sig = genesis_node
                .key_manager
                .public_key_set()?
                .combine_signatures(vec![gen_node_sig.threshold_crypto()])?;

            let genesis_dbc = Dbc {
                content: gen_dbc_content,
                transaction: gen_dbc_tx,
                transaction_sigs: BTreeMap::from_iter([(
                    GENESIS_DBC_INPUT,
                    (genesis_key, genesis_sig),
                )]),
            };
            let gen_dbc_name = genesis_dbc.name();

            let genesis_amount_secrets =
                DbcHelper::decrypt_amount_secrets(&genesis_owner, &genesis_dbc.content)?;

            let owner_amounts_and_keys = BTreeMap::from_iter(input_amounts.iter().copied().map(|a| {
                let owner = crate::bls_dkg_id();
                (owner.public_key_set.public_key(), (a, owner))
            }));

            let (reissue_tx, output_owner_pks) = crate::TransactionBuilder::default()
                .add_input(genesis_dbc, genesis_amount_secrets)
                .add_outputs(
                    owner_amounts_and_keys
                        .clone()
                        .into_iter()
                        .map(|(owner, (amount, _))| crate::Output { amount, owner }),
                )
                .build()?;

            let owners =
                BTreeMap::from_iter(output_owner_pks.into_iter().map(|(dbc_hash, owner_pk)| {
                    let (_, owner) = &owner_amounts_and_keys[&owner_pk];
                    (dbc_hash, owner)
                }));

            let sig_share = genesis_node
                .key_manager
                .sign(&reissue_tx.blinded().hash())?;
            let sig = genesis_node
                .key_manager
                .public_key_set()?
                .combine_signatures(vec![sig_share.threshold_crypto()])?;

            let reissue_req = ReissueRequest {
                transaction: reissue_tx,
                input_ownership_proofs: HashMap::from_iter([(gen_dbc_name, (genesis_key, sig))]),
            };

            let reissue_share =
                match genesis_node.reissue(reissue_req.clone(), BTreeSet::from_iter([gen_dbc_name])) {
                    Ok(rs) => {
                        // Verify that at least one input (output in this tx) was present.
                        assert!(!input_amounts.is_empty());
                        rs
                    }
                    Err(Error::DbcReissueRequestDoesNotBalance) => {
                        // Verify that no inputs (outputs in this tx) were present and we got correct validation error.
                        assert!(input_amounts.is_empty());
                        return Ok(());
                    }
                    Err(e) => return Err(e),
                };

            // Aggregate ReissueShare to build output DBCs
            let mut dbc_builder = DbcBuilder::new(reissue_req.transaction);
            dbc_builder = dbc_builder.add_reissue_share(reissue_share);
            let output_dbcs = dbc_builder.build()?;

            let input_dbcs = output_dbcs
                .into_iter()
                .map(|dbc| {
                    let owner = &owners[&dbc.name()];
                    let amount_secrets = DbcHelper::decrypt_amount_secrets(owner, &dbc.content)?;
                    Ok((dbc, amount_secrets))
                })
                .collect::<Result<Vec<(Dbc, crate::AmountSecrets)>>>()?;

            let outputs_owner = crate::bls_dkg_id();

            let (mut reissue_tx, _) = crate::TransactionBuilder::default()
                .add_inputs(input_dbcs)
                .add_outputs(output_amounts.iter().map(|amount| crate::Output {
                    amount: *amount,
                    owner: outputs_owner.public_key_set.public_key(),
                }))
                .build()?;

            let mut dbcs_with_fuzzed_parents = BTreeSet::new();

            for (out_idx, mut out_dbc_content) in std::mem::take(&mut reissue_tx.outputs)
                .into_iter()
                .enumerate()
            {
                let extra_random_parents = Vec::from_iter(
                    extra_output_parents
                        .iter()
                        .filter(|idx| **idx == out_idx)
                        .map(|_| rand::random::<Hash>()),
                );
                if !extra_random_parents.is_empty() {
                    dbcs_with_fuzzed_parents.insert(out_dbc_content.hash());
                }
                out_dbc_content.parents.extend(extra_random_parents);
                reissue_tx.outputs.insert(out_dbc_content);
            }

            let dbcs_with_valid_ownership_proofs = inputs_to_create_owner_proofs
                .into_iter()
                .filter_map(|input_num| reissue_tx.inputs.iter().nth(input_num))
                .map(|dbc| {
                    let owner = &owners[&dbc.name()];
                    let sig_share = owner.secret_key_share.sign(&reissue_tx.blinded().hash());
                    let owner_key_set = &owner.public_key_set;
                    let sig = owner_key_set.combine_signatures(vec![(owner.index, &sig_share)])?;
                    Ok((dbc.name(), (owner_key_set.public_key(), sig)))
                })
                .collect::<Result<HashMap<_, _>, Error>>()?;

            let dbcs_with_invalid_ownership_proofs = inputs_to_create_invalid_owner_proofs
                .into_iter()
                .filter_map(|input_num| reissue_tx.inputs.iter().nth(input_num))
                .map(|dbc| {
                    let random_owner = crate::bls_dkg_id();
                    let sig_share = random_owner
                        .secret_key_share
                        .sign(&reissue_tx.blinded().hash());
                    let owner_key_set = random_owner.public_key_set;
                    let sig =
                        owner_key_set.combine_signatures(vec![(random_owner.index, &sig_share)])?;

                    Ok((dbc.name(), (owner_key_set.public_key(), sig)))
                })
                .collect::<Result<HashMap<_, _>, Error>>()?;

            let input_ownership_proofs = HashMap::from_iter(
                dbcs_with_valid_ownership_proofs
                    .clone()
                    .into_iter()
                    .chain(dbcs_with_invalid_ownership_proofs.clone().into_iter()),
            );

            let dbc_output_amounts = reissue_tx
                .outputs
                .iter()
                .map(|o| DbcHelper::decrypt_amount(&outputs_owner, o))
                .collect::<Result<Vec<_>, _>>()?;
            let output_total_amount: Amount = dbc_output_amounts.iter().sum();

            let reissue_req = ReissueRequest {
                transaction: reissue_tx,
                input_ownership_proofs,
            };

            let many_to_many_result = genesis_node.reissue(
                reissue_req.clone(),
                BTreeSet::from_iter(reissue_req.transaction.blinded().inputs),
            );

            match many_to_many_result {
                Ok(rs) => {
                    assert_eq!(genesis_amount, output_total_amount);
                    assert_eq!(dbcs_with_fuzzed_parents.len(), 0);
                    assert!(
                        input_amounts.is_empty()
                            || BTreeSet::from_iter(dbcs_with_invalid_ownership_proofs.keys())
                                .intersection(&BTreeSet::from_iter(owners.keys()))
                                .next()
                                .is_none()
                    );
                    assert!(
                        BTreeSet::from_iter(owners.keys()).is_subset(&BTreeSet::from_iter(
                            dbcs_with_valid_ownership_proofs.keys()
                        ))
                    );

                    // The output amounts should correspond to the output_amounts
                    assert_eq!(
                        BTreeSet::from_iter(dbc_output_amounts),
                        BTreeSet::from_iter(output_amounts)
                    );

                    // Aggregate ReissueShare to build output DBCs
                    let mut dbc_builder = DbcBuilder::new(reissue_req.transaction);
                    dbc_builder = dbc_builder.add_reissue_share(rs);
                    let output_dbcs = dbc_builder.build()?;

                    for dbc in output_dbcs.iter() {
                        let dbc_confirm_result = dbc.confirm_valid(&genesis_node.key_manager);
                        assert!(dbc_confirm_result.is_ok());
                    }

                    assert_eq!(
                        output_dbcs
                            .iter()
                            .map(|dbc| { DbcHelper::decrypt_amount(&outputs_owner, &dbc.content) })
                            .sum::<Result<Amount, _>>()?,
                        output_total_amount
                    );
                }
                Err(Error::DbcReissueRequestDoesNotBalance { .. }) => {
                    if genesis_amount == output_total_amount {
                        // This can correctly occur if there are 0 outputs and inputs sum to zero.
                        //
                        // The error occurs because there is no output with a commitment
                        // to match against the input commitment, and also no way to
                        // know that the input amount is zero.
                        assert!(output_amounts.is_empty());
                        assert_eq!(input_amounts.iter().sum::<Amount>(), 0);
                        assert!(!input_amounts.is_empty());
                    }
                }
                Err(Error::TransactionMustHaveAnInput) => {
                    assert_eq!(input_amounts.len(), 0);
                }
                Err(Error::DbcContentParentsDifferentFromTransactionInputs) => {
                    assert_ne!(dbcs_with_fuzzed_parents.len(), 0)
                }
                Err(Error::MissingInputOwnerProof) => {
                    assert!(
                        !BTreeSet::from_iter(owners.keys()).is_subset(&BTreeSet::from_iter(
                            dbcs_with_valid_ownership_proofs.keys()
                        ))
                    );
                }
                Err(Error::FailedSignature) => {
                    assert_ne!(dbcs_with_invalid_ownership_proofs.len(), 0);
                }
                Err(Error::FailedUnblinding) => {
                    assert_ne!(dbcs_with_invalid_ownership_proofs.len(), 0);
                }
                err => panic!("Unexpected reissue err {:#?}", err),
            }

            Ok(())
        }

        #[quickcheck]
        #[ignore]
        fn prop_in_progress_transaction_can_be_continued_across_churn() {
            todo!()
        }

        #[quickcheck]
        #[ignore]
        fn prop_reject_invalid_prefix() {
            todo!();
        }

        #[test]
        fn test_inputs_are_validated() -> Result<(), Error> {
            let genesis_owner = crate::bls_dkg_id();
            let key_manager = SimpleKeyManager::new(
                SimpleSigner::from(genesis_owner.clone()),
                genesis_owner.public_key_set.public_key(),
            );
            let mut genesis_node = Mint::new(key_manager, SimpleSpendBook::new());

            let input_owner = crate::bls_dkg_id();
            let input_content = DbcContent::new(
                Default::default(),
                100,
                input_owner.public_key_set.public_key(),
                DbcContent::random_blinding_factor(),
            )?;
            let input_content_hashes = BTreeSet::from_iter([input_content.hash()]);

            let fraudulant_reissue_result = genesis_node.reissue(
                ReissueRequest {
                    transaction: ReissueTransaction {
                        inputs: HashSet::from_iter([Dbc {
                            content: input_content,
                            transaction: DbcTransaction {
                                inputs: Default::default(),
                                outputs: input_content_hashes.clone(),
                            },
                            transaction_sigs: Default::default(),
                        }]),
                        outputs: HashSet::from_iter([DbcContent::new(
                            input_content_hashes.clone(),
                            100,
                            crate::bls_dkg_id().public_key_set.public_key(),
                            DbcContent::random_blinding_factor(),
                        )?]),
                    },
                    input_ownership_proofs: HashMap::default(),
                },
                input_content_hashes,
            );
            assert!(fraudulant_reissue_result.is_err());

            Ok(())
        }
    */
}
