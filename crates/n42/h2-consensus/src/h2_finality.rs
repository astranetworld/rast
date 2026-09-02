//! Read-only verification of chain-bound gov5 H2-v4 consensus traffic.

use alloy_primitives::B256;
use crate::ValidatorSet;
use n42_h2_wire::h2_v4::{
    H2V4Envelope, commit_signing_message, new_view_signing_message, proposal_signing_message,
    timeout_signing_message, vote_signing_message,
};
use n42_h2_wire::h2_wire::{
    H2Decide, H2Message, H2MessageKind, H2QuorumCertificate, H2TimeoutCertificate,
};
use n42_h2_primitives::BlsSignature;
use n42_h2_primitives::bls::AggregateSignature;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct H2V4FinalityProof {
    pub view: u64,
    pub block_hash: alloy_primitives::B256,
    pub changes_hash: alloy_primitives::B256,
}

#[derive(Debug, thiserror::Error, Eq, PartialEq)]
pub enum H2V4FinalityError {
    #[error("H2-v4 message is not a Decide")]
    NotDecide,
    #[error("H2-v4 Decide does not match its CommitQC")]
    DecideQcMismatch,
    #[error("H2-v4 signer bitmap is not canonical for validator set size {expected}")]
    InvalidBitmap { expected: usize },
    #[error("H2-v4 CommitQC has {actual} signers; quorum requires {required}")]
    InsufficientQuorum { actual: usize, required: usize },
    #[error("H2-v4 CommitQC signature is invalid")]
    InvalidSignature,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct H2V4ShadowProof {
    pub kind: H2MessageKind,
    pub view: u64,
}

#[derive(Debug, thiserror::Error, Eq, PartialEq)]
pub enum H2V4ShadowError {
    #[error("H2-v4 {component} fields are inconsistent")]
    FieldMismatch { component: &'static str },
    #[error("H2-v4 {kind} sender {index} is not in validator set of size {set_size}")]
    InvalidSender {
        kind: &'static str,
        index: u32,
        set_size: u32,
    },
    #[error("H2-v4 {kind} sender {actual} is not the expected leader {expected}")]
    WrongLeader {
        kind: &'static str,
        actual: u32,
        expected: u32,
    },
    #[error("H2-v4 {component} signer bitmap is not canonical for validator set size {expected}")]
    InvalidBitmap {
        component: &'static str,
        expected: usize,
    },
    #[error("H2-v4 {component} has {actual} signers; quorum requires {required}")]
    InsufficientQuorum {
        component: &'static str,
        actual: usize,
        required: usize,
    },
    #[error("H2-v4 {component} signature is invalid")]
    InvalidSignature { component: &'static str },
    #[error("H2-v4 {component} is not the canonical genesis QC")]
    InvalidGenesisQc { component: &'static str },
}

/// Verifies an H2-v4 Decide as a finality proof. This function is deliberately
/// side-effect free: observers may use the result as a sync target, but it
/// never enters the voting state machine.
pub fn verify_h2_v4_decide(
    envelope: &H2V4Envelope,
    validator_set: &ValidatorSet,
) -> Result<H2V4FinalityProof, H2V4FinalityError> {
    let H2Message::Decide(decide) = &envelope.message else {
        return Err(H2V4FinalityError::NotDecide);
    };
    verify_decide_fields(decide)?;

    let signer_indices = signer_indices(&decide.commit_qc, validator_set.len() as usize)?;
    let required = validator_set.quorum_size();
    if signer_indices.len() < required {
        return Err(H2V4FinalityError::InsufficientQuorum {
            actual: signer_indices.len(),
            required,
        });
    }
    let public_keys = validator_set
        .public_keys_for_signers(&signer_indices)
        .map_err(|_| H2V4FinalityError::InvalidBitmap {
            expected: validator_set.len() as usize,
        })?;
    let signature_bytes: [u8; 96] = decide
        .commit_qc
        .aggregate_signature
        .as_slice()
        .try_into()
        .map_err(|_| H2V4FinalityError::InvalidSignature)?;
    let signature = BlsSignature::from_bytes(&signature_bytes)
        .map_err(|_| H2V4FinalityError::InvalidSignature)?;
    let message = commit_signing_message(
        envelope.identity,
        decide.view,
        decide.block_hash,
        envelope.changes_hash,
    );
    AggregateSignature::verify_h2_v4_aggregate(&message, &signature, &public_keys)
        .map_err(|_| H2V4FinalityError::InvalidSignature)?;

    Ok(H2V4FinalityProof {
        view: decide.view,
        block_hash: decide.block_hash,
        changes_hash: envelope.changes_hash,
    })
}

fn verify_decide_fields(decide: &H2Decide) -> Result<(), H2V4FinalityError> {
    if decide.view != decide.commit_qc.view || decide.block_hash != decide.commit_qc.block_hash {
        return Err(H2V4FinalityError::DecideQcMismatch);
    }
    Ok(())
}

/// Cryptographically validates one H2-v4 message without mutating consensus
/// state. This is the admission gate for mixed-client shadow traffic: sender
/// signatures, quorum certificates, timeout certificates, leader selection,
/// and wrapper identities are checked under the Gov5 H2-v4 POP domain.
pub fn verify_h2_v4_shadow_message(
    envelope: &H2V4Envelope,
    validator_set: &ValidatorSet,
) -> Result<H2V4ShadowProof, H2V4ShadowError> {
    verify_h2_v4_shadow_message_with_tenure(envelope, validator_set, 1)
}

/// [`verify_h2_v4_shadow_message`] on a chain whose validators lead
/// `leader_tenure` consecutive views (`hotstuff.leaderTenure`); the leader
/// rule is the only check that depends on it.
pub fn verify_h2_v4_shadow_message_with_tenure(
    envelope: &H2V4Envelope,
    validator_set: &ValidatorSet,
    leader_tenure: u64,
) -> Result<H2V4ShadowProof, H2V4ShadowError> {
    let identity = envelope.identity;
    let changes_hash = envelope.changes_hash;
    let (kind, view) = match &envelope.message {
        H2Message::Proposal(proposal) => {
            verify_leader("Proposal", proposal.view, proposal.proposer, validator_set, leader_tenure)?;
            verify_single_signature(
                "Proposal",
                proposal.proposer,
                &proposal.signature,
                &proposal_signing_message(
                    identity,
                    proposal.view,
                    proposal.block_hash,
                    changes_hash,
                ),
                validator_set,
            )?;
            verify_embedded_qc(
                "Proposal JustifyQC",
                &proposal.justify_qc,
                identity,
                changes_hash,
                validator_set,
                true,
            )?;
            if let Some(prepare_qc) = &proposal.prepare_qc {
                verify_qc(
                    "Proposal PrepareQC",
                    prepare_qc,
                    &[
                        vote_signing_message(identity, prepare_qc.view, prepare_qc.block_hash)
                            .as_slice(),
                    ],
                    validator_set,
                )?;
            }
            (H2MessageKind::Proposal, proposal.view)
        }
        H2Message::Vote(vote) => {
            verify_single_signature(
                "Vote",
                vote.voter,
                &vote.signature,
                &vote_signing_message(identity, vote.view, vote.block_hash),
                validator_set,
            )?;
            if let Some(high_tc) = &vote.high_tc {
                verify_tc(
                    "Vote HighTC",
                    high_tc,
                    identity,
                    changes_hash,
                    validator_set,
                )?;
            }
            (H2MessageKind::Vote, vote.view)
        }
        H2Message::CommitVote(vote) => {
            verify_single_signature(
                "CommitVote",
                vote.voter,
                &vote.signature,
                &commit_signing_message(identity, vote.view, vote.block_hash, changes_hash),
                validator_set,
            )?;
            if let Some(high_tc) = &vote.high_tc {
                verify_tc(
                    "CommitVote HighTC",
                    high_tc,
                    identity,
                    changes_hash,
                    validator_set,
                )?;
            }
            (H2MessageKind::CommitVote, vote.view)
        }
        H2Message::PrepareQc(prepare) => {
            if prepare.view != prepare.qc.view || prepare.block_hash != prepare.qc.block_hash {
                return Err(H2V4ShadowError::FieldMismatch {
                    component: "PrepareQC",
                });
            }
            let message = vote_signing_message(identity, prepare.view, prepare.block_hash);
            verify_qc(
                "PrepareQC",
                &prepare.qc,
                &[message.as_slice()],
                validator_set,
            )?;
            (H2MessageKind::PrepareQc, prepare.view)
        }
        H2Message::Timeout(timeout) => {
            verify_single_signature(
                "Timeout",
                timeout.sender,
                &timeout.signature,
                &timeout_signing_message(identity, timeout.view),
                validator_set,
            )?;
            verify_embedded_qc(
                "Timeout HighQC",
                &timeout.high_qc,
                identity,
                changes_hash,
                validator_set,
                true,
            )?;
            if let Some(high_tc) = &timeout.high_tc {
                verify_tc(
                    "Timeout HighTC",
                    high_tc,
                    identity,
                    changes_hash,
                    validator_set,
                )?;
            }
            (H2MessageKind::Timeout, timeout.view)
        }
        H2Message::NewView(new_view) => {
            verify_leader("NewView", new_view.view, new_view.leader, validator_set, leader_tenure)?;
            if new_view.view == 0
                || new_view.timeout_certificate.view.checked_add(1) != Some(new_view.view)
            {
                return Err(H2V4ShadowError::FieldMismatch {
                    component: "NewView TimeoutCertificate",
                });
            }
            verify_single_signature(
                "NewView",
                new_view.leader,
                &new_view.signature,
                &new_view_signing_message(identity, new_view.view),
                validator_set,
            )?;
            verify_tc(
                "NewView TimeoutCertificate",
                &new_view.timeout_certificate,
                identity,
                changes_hash,
                validator_set,
            )?;
            (H2MessageKind::NewView, new_view.view)
        }
        H2Message::Decide(decide) => {
            if decide.view != decide.commit_qc.view
                || decide.block_hash != decide.commit_qc.block_hash
            {
                return Err(H2V4ShadowError::FieldMismatch {
                    component: "Decide CommitQC",
                });
            }
            let message =
                commit_signing_message(identity, decide.view, decide.block_hash, changes_hash);
            verify_qc(
                "Decide CommitQC",
                &decide.commit_qc,
                &[message.as_slice()],
                validator_set,
            )?;
            (H2MessageKind::Decide, decide.view)
        }
    };
    Ok(H2V4ShadowProof { kind, view })
}

fn verify_leader(
    kind: &'static str,
    view: u64,
    actual: u32,
    validator_set: &ValidatorSet,
    leader_tenure: u64,
) -> Result<(), H2V4ShadowError> {
    let set_size = validator_set.len();
    if set_size == 0 {
        return Err(H2V4ShadowError::InvalidSender {
            kind,
            index: actual,
            set_size,
        });
    }
    let expected = ((view / leader_tenure.max(1)) % u64::from(set_size)) as u32;
    if actual != expected {
        return Err(H2V4ShadowError::WrongLeader {
            kind,
            actual,
            expected,
        });
    }
    Ok(())
}

fn verify_single_signature(
    component: &'static str,
    index: u32,
    signature: &BlsSignature,
    message: &[u8],
    validator_set: &ValidatorSet,
) -> Result<(), H2V4ShadowError> {
    let public_key =
        validator_set
            .get_public_key(index)
            .map_err(|_| H2V4ShadowError::InvalidSender {
                kind: component,
                index,
                set_size: validator_set.len(),
            })?;
    AggregateSignature::verify_h2_v4_aggregate(message, signature, &[public_key])
        .map_err(|_| H2V4ShadowError::InvalidSignature { component })
}

fn verify_embedded_qc(
    component: &'static str,
    qc: &H2QuorumCertificate,
    identity: n42_h2_wire::h2_v4::H2V4ChainIdentity,
    changes_hash: B256,
    validator_set: &ValidatorSet,
    allow_genesis: bool,
) -> Result<(), H2V4ShadowError> {
    if qc.view == 0 {
        if allow_genesis && is_canonical_genesis_qc(qc) {
            return Ok(());
        }
        return Err(H2V4ShadowError::InvalidGenesisQc { component });
    }
    let vote = vote_signing_message(identity, qc.view, qc.block_hash);
    let commit = commit_signing_message(identity, qc.view, qc.block_hash, changes_hash);
    verify_qc(
        component,
        qc,
        &[vote.as_slice(), commit.as_slice()],
        validator_set,
    )
}

fn verify_tc(
    component: &'static str,
    tc: &H2TimeoutCertificate,
    identity: n42_h2_wire::h2_v4::H2V4ChainIdentity,
    changes_hash: B256,
    validator_set: &ValidatorSet,
) -> Result<(), H2V4ShadowError> {
    let synthetic_qc = H2QuorumCertificate {
        view: tc.view,
        block_hash: B256::ZERO,
        aggregate_signature: tc.aggregate_signature.clone(),
        signers_bitmap: tc.signers_bitmap.clone(),
    };
    let message = timeout_signing_message(identity, tc.view);
    verify_qc(
        component,
        &synthetic_qc,
        &[message.as_slice()],
        validator_set,
    )?;
    verify_embedded_qc(
        component,
        &tc.high_qc,
        identity,
        changes_hash,
        validator_set,
        true,
    )
}

fn verify_qc(
    component: &'static str,
    qc: &H2QuorumCertificate,
    messages: &[&[u8]],
    validator_set: &ValidatorSet,
) -> Result<(), H2V4ShadowError> {
    let signer_indices = canonical_signer_indices(qc, validator_set.len() as usize).ok_or(
        H2V4ShadowError::InvalidBitmap {
            component,
            expected: validator_set.len() as usize,
        },
    )?;
    let required = validator_set.quorum_size();
    if signer_indices.len() < required {
        return Err(H2V4ShadowError::InsufficientQuorum {
            component,
            actual: signer_indices.len(),
            required,
        });
    }
    let public_keys = validator_set
        .public_keys_for_signers(&signer_indices)
        .map_err(|_| H2V4ShadowError::InvalidBitmap {
            component,
            expected: validator_set.len() as usize,
        })?;
    let signature_bytes: [u8; 96] = qc
        .aggregate_signature
        .as_slice()
        .try_into()
        .map_err(|_| H2V4ShadowError::InvalidSignature { component })?;
    let signature = BlsSignature::from_bytes(&signature_bytes)
        .map_err(|_| H2V4ShadowError::InvalidSignature { component })?;
    if messages.iter().any(|message| {
        AggregateSignature::verify_h2_v4_aggregate(message, &signature, &public_keys).is_ok()
    }) {
        Ok(())
    } else {
        Err(H2V4ShadowError::InvalidSignature { component })
    }
}

fn is_canonical_genesis_qc(qc: &H2QuorumCertificate) -> bool {
    qc.view == 0
        && qc.block_hash == B256::ZERO
        && qc.aggregate_signature.is_empty()
        && qc.signers_bitmap == [0, 0]
}

fn signer_indices(
    qc: &H2QuorumCertificate,
    expected_count: usize,
) -> Result<Vec<u32>, H2V4FinalityError> {
    canonical_signer_indices(qc, expected_count).ok_or(H2V4FinalityError::InvalidBitmap {
        expected: expected_count,
    })
}

fn canonical_signer_indices(qc: &H2QuorumCertificate, expected_count: usize) -> Option<Vec<u32>> {
    let bitmap = &qc.signers_bitmap;
    let encoded_count = bitmap
        .get(..2)
        .and_then(|bytes| <[u8; 2]>::try_from(bytes).ok())
        .map(u16::from_le_bytes)
        .map(usize::from);
    let byte_count = expected_count.div_ceil(8);
    if encoded_count != Some(expected_count) || bitmap.len() != 2 + byte_count {
        return None;
    }
    if !expected_count.is_multiple_of(8) {
        let used_mask = (1u16 << (expected_count % 8)) as u8 - 1;
        if bitmap.last().is_some_and(|last| last & !used_mask != 0) {
            return None;
        }
    }
    Some(
        (0..expected_count)
            .filter(|index| bitmap[2 + index / 8] & (1 << (index % 8)) != 0)
            .map(|index| index as u32)
            .collect(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::{Address, B256};
    use crate::ValidatorInfo;
    use n42_h2_wire::h2_v4::{
        H2V4ChainIdentity, decode_envelope, new_view_signing_message, proposal_signing_message,
        timeout_signing_message, vote_signing_message,
    };
    use n42_h2_wire::h2_wire::{
        H2NewView, H2PrepareQc, H2Proposal, H2Timeout, H2TimeoutCertificate, H2Vote,
    };
    use n42_h2_primitives::{BlsPublicKey, BlsSecretKey};
    use serde::Deserialize;

    #[derive(Deserialize)]
    struct Fixture {
        schema: String,
        chain_id: u64,
        genesis_hash: String,
        changes_hash: String,
        validator_public_keys: Vec<String>,
        envelope_hex: String,
    }

    fn fixture() -> (H2V4Envelope, ValidatorSet) {
        let fixture: Fixture =
            serde_json::from_str(include_str!("../testdata/h2_v4_finality_v1.json")).unwrap();
        assert_eq!(fixture.schema, "n42-h2-v4-finality-v1");
        let identity = H2V4ChainIdentity {
            chain_id: fixture.chain_id,
            genesis_hash: B256::from_slice(&hex::decode(fixture.genesis_hash).unwrap()),
        };
        let envelope =
            decode_envelope(&hex::decode(fixture.envelope_hex).unwrap(), identity).unwrap();
        assert_eq!(
            envelope.changes_hash,
            B256::from_slice(&hex::decode(fixture.changes_hash).unwrap())
        );
        let validators = fixture
            .validator_public_keys
            .iter()
            .enumerate()
            .map(|(index, encoded)| {
                let bytes: [u8; 48] = hex::decode(encoded).unwrap().try_into().unwrap();
                ValidatorInfo {
                    address: Address::with_last_byte(index as u8 + 1),
                    bls_public_key: BlsPublicKey::from_bytes(&bytes).unwrap(),
                    p2p_peer_id: None,
                }
            })
            .collect::<Vec<_>>();
        (envelope, ValidatorSet::new(&validators, 1))
    }

    fn shadow_validators() -> (Vec<BlsSecretKey>, ValidatorSet) {
        let keys = (1..=4)
            .map(|seed| BlsSecretKey::key_gen(&[seed; 32]).unwrap())
            .collect::<Vec<_>>();
        let validators = keys
            .iter()
            .enumerate()
            .map(|(index, key)| ValidatorInfo {
                address: Address::with_last_byte(index as u8 + 1),
                bls_public_key: key.public_key(),
                p2p_peer_id: None,
            })
            .collect::<Vec<_>>();
        let validator_set = ValidatorSet::new(&validators, 1);
        (keys, validator_set)
    }

    fn signer_bitmap(count: usize, signers: &[usize]) -> Vec<u8> {
        let mut bitmap = Vec::with_capacity(2 + count.div_ceil(8));
        bitmap.extend_from_slice(&(count as u16).to_le_bytes());
        bitmap.resize(2 + count.div_ceil(8), 0);
        for signer in signers {
            bitmap[2 + signer / 8] |= 1 << (signer % 8);
        }
        bitmap
    }

    fn aggregate_qc(
        keys: &[BlsSecretKey],
        identity: H2V4ChainIdentity,
        changes_hash: B256,
        view: u64,
        block_hash: B256,
        commit: bool,
    ) -> H2QuorumCertificate {
        let message = if commit {
            commit_signing_message(identity, view, block_hash, changes_hash).to_vec()
        } else {
            vote_signing_message(identity, view, block_hash).to_vec()
        };
        let signatures = keys[..3]
            .iter()
            .map(|key| key.sign_h2_v4(&message))
            .collect::<Vec<_>>();
        let refs = signatures.iter().collect::<Vec<_>>();
        H2QuorumCertificate {
            view,
            block_hash,
            aggregate_signature: AggregateSignature::aggregate(&refs)
                .unwrap()
                .to_bytes()
                .to_vec(),
            signers_bitmap: signer_bitmap(keys.len(), &[0, 1, 2]),
        }
    }

    fn aggregate_tc(
        keys: &[BlsSecretKey],
        identity: H2V4ChainIdentity,
        view: u64,
    ) -> H2TimeoutCertificate {
        let message = timeout_signing_message(identity, view);
        let signatures = keys[..3]
            .iter()
            .map(|key| key.sign_h2_v4(&message))
            .collect::<Vec<_>>();
        let refs = signatures.iter().collect::<Vec<_>>();
        H2TimeoutCertificate {
            view,
            aggregate_signature: AggregateSignature::aggregate(&refs)
                .unwrap()
                .to_bytes()
                .to_vec(),
            signers_bitmap: signer_bitmap(keys.len(), &[0, 1, 2]),
            high_qc: H2QuorumCertificate {
                view: 0,
                block_hash: B256::ZERO,
                aggregate_signature: Vec::new(),
                signers_bitmap: vec![0, 0],
            },
        }
    }

    #[test]
    fn verifies_gov5_finality_fixture_and_binds_domain() {
        let (envelope, validator_set) = fixture();
        let proof = verify_h2_v4_decide(&envelope, &validator_set).unwrap();
        assert_eq!(proof.view, 9001);
        assert_eq!(proof.block_hash, B256::repeat_byte(0x44));

        let mut wrong_changes = envelope.clone();
        wrong_changes.changes_hash[0] ^= 1;
        assert_eq!(
            verify_h2_v4_decide(&wrong_changes, &validator_set),
            Err(H2V4FinalityError::InvalidSignature)
        );

        let mut insufficient = envelope;
        let H2Message::Decide(decide) = &mut insufficient.message else {
            unreachable!()
        };
        decide.commit_qc.signers_bitmap[2] = 0b0000_0011;
        assert_eq!(
            verify_h2_v4_decide(&insufficient, &validator_set),
            Err(H2V4FinalityError::InsufficientQuorum {
                actual: 2,
                required: 3,
            })
        );
    }

    #[test]
    fn shadow_verifies_all_seven_h2_v4_message_kinds() {
        let (keys, validator_set) = shadow_validators();
        let identity = H2V4ChainIdentity {
            chain_id: 94,
            genesis_hash: B256::repeat_byte(0x11),
        };
        let changes_hash = B256::repeat_byte(0x22);
        let view = 5;
        let block_hash = B256::repeat_byte(0x44);
        let genesis_qc = H2QuorumCertificate {
            view: 0,
            block_hash: B256::ZERO,
            aggregate_signature: Vec::new(),
            signers_bitmap: vec![0, 0],
        };
        let prepare_qc = aggregate_qc(&keys, identity, changes_hash, view, block_hash, false);
        let commit_qc = aggregate_qc(&keys, identity, changes_hash, view, block_hash, true);
        let tc = aggregate_tc(&keys, identity, 7);

        let proposal = H2Message::Proposal(H2Proposal {
            view,
            block_hash,
            justify_qc: genesis_qc.clone(),
            proposer: 1,
            signature: keys[1].sign_h2_v4(&proposal_signing_message(
                identity,
                view,
                block_hash,
                changes_hash,
            )),
            prepare_qc: None,
            tx_root_hash: B256::repeat_byte(0x55),
        });
        let vote = H2Message::Vote(H2Vote {
            view,
            block_hash,
            voter: 2,
            signature: keys[2].sign_h2_v4(&vote_signing_message(identity, view, block_hash)),
            high_tc: None,
        });
        let commit_vote = H2Message::CommitVote(H2Vote {
            view,
            block_hash,
            voter: 3,
            signature: keys[3].sign_h2_v4(&commit_signing_message(
                identity,
                view,
                block_hash,
                changes_hash,
            )),
            high_tc: None,
        });
        let prepare = H2Message::PrepareQc(H2PrepareQc {
            view,
            block_hash,
            qc: prepare_qc,
        });
        let timeout = H2Message::Timeout(H2Timeout {
            view: 6,
            high_qc: genesis_qc,
            sender: 2,
            signature: keys[2].sign_h2_v4(&timeout_signing_message(identity, 6)),
            high_tc: None,
        });
        let new_view = H2Message::NewView(H2NewView {
            view: 8,
            timeout_certificate: tc,
            leader: 0,
            signature: keys[0].sign_h2_v4(&new_view_signing_message(identity, 8)),
        });
        let decide = H2Message::Decide(H2Decide {
            view,
            block_hash,
            commit_qc,
        });

        for message in [
            proposal,
            vote,
            commit_vote,
            prepare,
            timeout,
            new_view,
            decide,
        ] {
            let expected_kind = message.kind();
            let envelope = H2V4Envelope {
                identity,
                changes_hash,
                message,
            };
            assert_eq!(
                verify_h2_v4_shadow_message(&envelope, &validator_set)
                    .unwrap()
                    .kind,
                expected_kind
            );
        }
    }

    #[test]
    fn shadow_rejects_wrong_leader_and_cross_changes_hash_replay() {
        let (keys, validator_set) = shadow_validators();
        let identity = H2V4ChainIdentity {
            chain_id: 94,
            genesis_hash: B256::repeat_byte(0x11),
        };
        let changes_hash = B256::repeat_byte(0x22);
        let view = 5;
        let block_hash = B256::repeat_byte(0x44);
        let mut envelope = H2V4Envelope {
            identity,
            changes_hash,
            message: H2Message::Proposal(H2Proposal {
                view,
                block_hash,
                justify_qc: H2QuorumCertificate {
                    view: 0,
                    block_hash: B256::ZERO,
                    aggregate_signature: Vec::new(),
                    signers_bitmap: vec![0, 0],
                },
                proposer: 1,
                signature: keys[1].sign_h2_v4(&proposal_signing_message(
                    identity,
                    view,
                    block_hash,
                    changes_hash,
                )),
                prepare_qc: None,
                tx_root_hash: B256::ZERO,
            }),
        };
        envelope.changes_hash[0] ^= 1;
        assert_eq!(
            verify_h2_v4_shadow_message(&envelope, &validator_set),
            Err(H2V4ShadowError::InvalidSignature {
                component: "Proposal"
            })
        );

        let H2Message::Proposal(proposal) = &mut envelope.message else {
            unreachable!()
        };
        proposal.proposer = 0;
        assert_eq!(
            verify_h2_v4_shadow_message(&envelope, &validator_set),
            Err(H2V4ShadowError::WrongLeader {
                kind: "Proposal",
                actual: 0,
                expected: 1,
            })
        );
    }

    /// Byte-exact contract with gov5; see the equivalent check in
    /// `n42-network::h2_v4` for why the raw bytes are hashed rather than the
    /// parsed JSON.
    #[test]
    fn vendored_finality_fixture_matches_the_gov5_contract() {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(include_bytes!("../testdata/h2_v4_finality_v1.json").as_slice());
        assert_eq!(
            hex::encode(hasher.finalize()),
            "feacd6d0d2dc3babcbe3440384021ee9291b68103baaf7d47cd0ff1c6b703488",
            "h2_v4_finality_v1.json no longer matches the fixture gov5 pins"
        );
    }
}
