use blsbs::{Envelope, Fr, SignedEnvelopeShare, SlipPreparer};
use blsttc::{IntoFr, PublicKeySet, SecretKeyShare, Signature, SignatureShare};
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::iter::FromIterator;

use crate::{
    Amount, Dbc, DbcContent, DbcContentHash, DbcEnvelope, Denomination, Error, Hash,
    ReissueRequest, ReissueShare, ReissueTransaction, Result,
};

///! Unblinded data for creating sn_dbc::DbcContent
pub struct Output {
    pub denomination: Denomination,
    pub owner: blsttc::PublicKey,
}

#[derive(Default)]
pub struct TransactionBuilder {
    pub inputs: HashSet<Dbc>,
    pub outputs: Vec<Output>,
}

impl TransactionBuilder {
    pub fn add_input(mut self, dbc: Dbc) -> Self {
        self.inputs.insert(dbc);
        self
    }

    pub fn add_inputs(mut self, inputs: impl IntoIterator<Item = Dbc>) -> Self {
        self.inputs.extend(inputs);
        self
    }

    pub fn add_output(mut self, output: Output) -> Self {
        self.outputs.push(output);
        self
    }

    pub fn add_outputs(mut self, outputs: impl IntoIterator<Item = Output>) -> Self {
        self.outputs.extend(outputs);
        self
    }

    pub fn inputs_hashes(&self) -> BTreeSet<Hash> {
        self.inputs
            .iter()
            .map(|dbc| dbc.name())
            .collect::<BTreeSet<_>>()
    }

    pub fn inputs_amount_sum(&self) -> Amount {
        self.inputs.iter().map(|s| s.denomination().amount()).sum()
    }

    pub fn outputs_amount_sum(&self) -> Amount {
        self.outputs.iter().map(|o| o.denomination.amount()).sum()
    }

    // Note: The HashMap output is necessary because Envelope, SignedEnvelopeShare do not
    //       contain the Slip itself, so we must keep DbcContent around.
    //       If they were to contain an encrypted Slip, we would not need this.
    pub fn build(
        self,
    ) -> Result<(
        ReissueTransaction,
        HashMap<DbcEnvelope, (SlipPreparer, DbcContent)>,
    )> {
        let outputs_content = self
            .outputs
            .iter()
            .map(|o| DbcContent::new(o.owner, o.denomination))
            .collect::<HashSet<_>>();

        let map = outputs_content
            .iter()
            .map(|c| {
                let slip_preparer = SlipPreparer::new()?;
                let envelope = slip_preparer.place_slip_in_envelope(&c.slip());
                let dbc_envelope = DbcEnvelope {
                    envelope,
                    denomination: c.denomination(),
                };
                Ok((dbc_envelope, (slip_preparer, c.clone()))) // todo: avoid this clone.
            })
            .collect::<Result<HashMap<_, _>>>()?;

        let outputs: HashSet<DbcEnvelope> = HashSet::from_iter(map.keys().cloned());

        let rt = ReissueTransaction {
            inputs: self.inputs,
            outputs,
        };
        Ok((rt, map))
    }
}

/// Builds a ReissueRequest from a ReissueTransaction and
/// any number of (input) DBC hashes with associated ownership share(s).
#[derive(Default)]
pub struct ReissueRequestBuilder {
    pub reissue_transaction: Option<ReissueTransaction>,
    #[allow(clippy::type_complexity)]
    pub signers_by_dbc: HashMap<DbcContentHash, BTreeMap<PublicKeySet, (Fr, SecretKeyShare)>>,
}

impl ReissueRequestBuilder {
    /// Create a new ReissueRequestBuilder from a ReissueTransaction
    pub fn new(reissue_transaction: ReissueTransaction) -> Self {
        Self {
            reissue_transaction: Some(reissue_transaction),
            signers_by_dbc: Default::default(),
        }
    }

    /// Set the ReissueTransaction
    pub fn set_reissue_transaction(mut self, reissue_transaction: ReissueTransaction) -> Self {
        self.reissue_transaction = Some(reissue_transaction);
        self
    }

    /// Add a single signer share for a DBC hash
    pub fn add_dbc_signer<FR: IntoFr>(
        mut self,
        dbc: DbcContentHash,
        public_key_set: PublicKeySet,
        share_index: FR,
        secret_key_share: SecretKeyShare,
    ) -> Self {
        let entry = self.signers_by_dbc.entry(dbc).or_insert_with(BTreeMap::new);
        (*entry).insert(public_key_set, (share_index.into_fr(), secret_key_share));
        self
    }

    /// Add a list of signer shares for a DBC hash
    pub fn add_dbc_signers<FR: IntoFr>(
        mut self,
        dbc: DbcContentHash,
        public_key_set: PublicKeySet,
        secret_key_shares: Vec<(FR, SecretKeyShare)>,
    ) -> Self {
        let entry = self.signers_by_dbc.entry(dbc).or_insert_with(BTreeMap::new);
        for (idx, secret_key_share) in secret_key_shares.into_iter() {
            (*entry).insert(public_key_set.clone(), (idx.into_fr(), secret_key_share));
        }
        self
    }

    pub fn num_signers_by_dbc(&self, hash: DbcContentHash) -> usize {
        match self.signers_by_dbc.get(&hash) {
            Some(s) => s.len(),
            None => 0,
        }
    }

    /// Aggregates SecretKeyShares for all DBC owners in a ReissueTransaction
    /// in order to combine signature shares into Signatures, thereby
    /// creating the ownership proofs necessary to construct
    /// a ReissueRequest.
    pub fn build(self) -> Result<ReissueRequest> {
        let transaction = match self.reissue_transaction {
            Some(rt) => rt,
            None => return Err(Error::NoReissueTransaction),
        };

        let mut input_ownership_proofs: HashMap<DbcContentHash, Signature> = Default::default();

        for (dbc, signers) in self.signers_by_dbc.iter() {
            let pks_set: HashSet<PublicKeySet> = signers.iter().map(|s| s.0.clone()).collect();
            if pks_set.len() != 1 {
                return Err(Error::ReissueRequestPublicKeySetMismatch);
            }
            let owner_public_key_set = match pks_set.iter().next() {
                Some(pks) => pks,
                None => return Err(Error::ReissueRequestPublicKeySetMismatch),
            };

            let sig_shares: BTreeMap<Fr, SignatureShare> = signers
                .iter()
                .map(|s| {
                    let idx = s.1 .0;
                    let sks = &s.1 .1;
                    let sig_share = sks.sign(dbc);
                    (idx, sig_share)
                })
                .collect();

            let sig_shares_ref: BTreeMap<Fr, &SignatureShare> = sig_shares
                .iter()
                .map(|(idx, share)| (*idx, share))
                .collect();

            let signature = owner_public_key_set.combine_signatures(sig_shares_ref)?;
            input_ownership_proofs.insert(*dbc, signature);
        }

        let rr = ReissueRequest {
            transaction,
            input_ownership_proofs,
        };
        Ok(rr)
    }
}

/// A Builder for aggregating ReissueShare (Mint::reissue() results)
/// from multiple mint nodes and combining signatures to
/// generate the final Dbc outputs.
#[derive(Default)]
pub struct DbcBuilder {
    pub reissue_transaction: Option<ReissueTransaction>,
    pub reissue_shares: Vec<ReissueShare>,

    // Note: this is necessary because Envelope, SignedEnvelopeShare do not
    //       contain the Slip itself, so we must keep DbcContent around.
    //       If they were to contain an encrypted Slip, we would not need this.
    pub outputs_content: HashMap<DbcEnvelope, (SlipPreparer, DbcContent)>,

    pub disable_output_validation: bool,
}

impl DbcBuilder {
    /// Create a new DbcBuilder from a ReissueTransaction
    pub fn new(reissue_transaction: ReissueTransaction) -> Self {
        Self {
            reissue_transaction: Some(reissue_transaction),
            reissue_shares: Default::default(),
            outputs_content: Default::default(),
            disable_output_validation: Default::default(),
        }
    }

    /// Disable validation of output DBCs (enabled by default)
    pub fn disable_output_validation(mut self) -> Self {
        self.disable_output_validation = true;
        self
    }

    /// Enable validation of output DBCs.  (enabled by default)
    pub fn enable_output_validation(mut self) -> Self {
        self.disable_output_validation = false;
        self
    }

    /// Add an output DbcContent
    pub fn add_output_content(
        mut self,
        dbc_envelope: DbcEnvelope,
        slip_preparer: SlipPreparer,
        content: DbcContent,
    ) -> Self {
        self.outputs_content
            .insert(dbc_envelope, (slip_preparer, content));
        self
    }

    /// Add multiple DbcContent
    pub fn add_outputs_content(
        mut self,
        contents: impl IntoIterator<Item = (DbcEnvelope, (SlipPreparer, DbcContent))>,
    ) -> Self {
        self.outputs_content.extend(contents);
        self
    }

    /// Add a ReissueShare from Mint::reissue()
    pub fn add_reissue_share(mut self, reissue_share: ReissueShare) -> Self {
        self.reissue_shares.push(reissue_share);
        self
    }

    /// Set the ReissueTransaction
    pub fn set_reissue_transaction(mut self, reissue_transaction: ReissueTransaction) -> Self {
        self.reissue_transaction = Some(reissue_transaction);
        self
    }

    /// Build the output DBCs
    ///
    /// Note that the result Vec may be empty if the ReissueTransaction
    /// has not been set or no ReissueShare has been added.
    pub fn build(self) -> Result<Vec<Dbc>> {
        if self.reissue_shares.is_empty() {
            return Err(Error::NoReissueShares);
        }

        if self.outputs_content.is_empty() {
            return Err(Error::NoOutputsContent);
        }

        let reissue_transaction = match self.reissue_transaction {
            Some(rt) => rt,
            None => return Err(Error::NoReissueTransaction),
        };

        let mut signed_envelope_shares: HashMap<Envelope, Vec<SignedEnvelopeShare>> =
            Default::default();
        let mut pk_set: HashSet<PublicKeySet> = Default::default();

        // walk through ReissueShare from each MintNode and:
        //  - generate a share list per output DBC/envelope.
        //  - aggregate PublicKeySet in order to verify they are all the same.
        //  - perform other validations
        for rs in self.reissue_shares.iter() {
            // Make a list of SignedEnvelopeShare (sigshare from each Mint Node) per DBC
            for share in rs.signed_envelope_shares.iter() {
                // fixme: remove clone.  Envelope could be Hash<Envelope>
                let share_list = signed_envelope_shares
                    .entry(share.envelope.clone())
                    .or_insert_with(Vec::new);
                (*share_list).push(share.clone())
            }

            let pub_key_sets: HashSet<PublicKeySet> =
                HashSet::from_iter([rs.public_key_set.clone()]);

            // add pubkeyset to HashSet, so we can verify there is only one distinct PubKeySet
            pk_set = &pk_set | &pub_key_sets; // union the sets together.

            // Verify transaction returned to us by the Mint matches our request
            if reissue_transaction.blinded() != rs.dbc_transaction {
                return Err(Error::ReissueShareDbcTransactionMismatch);
            }

            // Verify that mint sig count matches output count.
            if rs.signed_envelope_shares.len() != reissue_transaction.outputs.len() {
                return Err(Error::ReissueShareMintNodeSignaturesLenMismatch);
            }

            // Verify that each output DbcEnvelope has a corresponding output SignedEnvelopeShare
            for dbc_envelope in reissue_transaction.outputs.iter() {
                // todo: do this in a more rusty way.
                let mut found = false;
                for ses in rs.signed_envelope_shares.iter() {
                    if ses.envelope == dbc_envelope.envelope {
                        found = true;
                        break;
                    }
                }
                if !found {
                    return Err(Error::ReissueShareMintNodeSignatureNotFoundForInput);
                }
            }
        }

        // verify that PublicKeySet for all Dbc in all ReissueShare match.
        if pk_set.len() != 1 {
            return Err(Error::ReissueSharePublicKeySetMismatch);
        }
        let mint_public_key_set = match pk_set.iter().next() {
            Some(pks) => pks,
            None => return Err(Error::ReissueSharePublicKeySetMismatch),
        };

        // Generate final output Dbcs
        let mut output_dbcs: Vec<Dbc> = Default::default();
        for (dbc_envelope, (slip_preparer, content)) in self.outputs_content {
            // Transform Vec<SignedEnvelopeShare> to BTreeMap<Fr, SignatureShare>
            let mut mint_sig_shares: BTreeMap<Fr, SignatureShare> = Default::default();
            for ses in signed_envelope_shares
                .get(&dbc_envelope.envelope)
                .unwrap()
                .iter()
            {
                mint_sig_shares.insert(
                    ses.signature_share_index(),
                    ses.signature_share_for_slip(slip_preparer.blinding_factor())?,
                );
            }

            let denom_idx = dbc_envelope.denomination.to_be_bytes();

            let mint_derived_pks = mint_public_key_set.derive_child(&denom_idx);

            // Combine signatures from all the mint nodes to obtain Mint's Signature.
            let mint_sig = mint_derived_pks.combine_signatures(&mint_sig_shares)?;

            // Form the final output DBCs, with Mint's Signature for each.
            let dbc = Dbc {
                content,
                mint_public_key: mint_derived_pks.public_key(),
                mint_signature: mint_sig,
            };

            if !self.disable_output_validation {
                dbc.confirm_valid()?;
            }

            output_dbcs.push(dbc);
        }

        // sort outputs by name
        output_dbcs.sort_by_key(|d| d.name());

        Ok(output_dbcs)
    }
}
