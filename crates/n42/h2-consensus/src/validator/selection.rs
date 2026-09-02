use super::set::ValidatorSet;
use n42_h2_primitives::consensus::ViewNumber;

/// Leader selection strategy based on round-robin rotation.
///
/// The leader for view `v` is `v % n` where `n` is the validator set size.
/// This is deterministic and requires no communication—every honest node
/// can independently compute who the leader is for any view.
#[derive(Debug, Clone)]
pub struct LeaderSelector;

impl LeaderSelector {
    /// Returns the leader's validator index for the given view.
    ///
    /// # Panics
    /// Panics if the validator set is empty. Returning a synthetic validator
    /// index would let a malformed release configuration appear to have a
    /// leader and fail open.
    pub fn leader_for_view(view: ViewNumber, validator_set: &ValidatorSet) -> u32 {
        Self::leader_for_view_with_tenure(view, 1, validator_set)
    }

    /// The leader for view `v` when every validator leads `tenure` consecutive
    /// views: `(v / tenure) % n`. A tenure of 1 is the round-robin above, and
    /// 0 is read as 1 rather than dividing by it.
    ///
    /// # Panics
    /// Panics if the validator set is empty, for the reason given on
    /// [`Self::leader_for_view`].
    pub fn leader_for_view_with_tenure(
        view: ViewNumber,
        tenure: u64,
        validator_set: &ValidatorSet,
    ) -> u32 {
        assert!(
            !validator_set.is_empty(),
            "leader_for_view called with empty validator set"
        );
        ((view / tenure.max(1)) % validator_set.len() as u64) as u32
    }

    /// Checks if the given validator is the leader for the given view.
    pub fn is_leader(validator_index: u32, view: ViewNumber, validator_set: &ValidatorSet) -> bool {
        Self::leader_for_view(view, validator_set) == validator_index
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::Address;
    use crate::ValidatorInfo;
    use n42_h2_primitives::BlsSecretKey;

    fn test_key(seed: u8) -> BlsSecretKey {
        BlsSecretKey::key_gen(&[seed; 32]).expect("deterministic test key should be valid")
    }

    /// Helper: create a ValidatorSet with `n` deterministic validators.
    fn make_validator_set(n: usize) -> ValidatorSet {
        let infos: Vec<_> = (0..n)
            .map(|i| {
                let sk = test_key(0x30 + i as u8);
                ValidatorInfo {
                    address: Address::with_last_byte(i as u8),
                    bls_public_key: sk.public_key(),
                    p2p_peer_id: None,
                }
            })
            .collect();
        let f = ((n as u32).saturating_sub(1)) / 3;
        ValidatorSet::new(&infos, f)
    }

    #[test]
    fn test_round_robin() {
        let vs = make_validator_set(4);

        let expected = [0u32, 1, 2, 3, 0, 1, 2, 3];
        for (view, &expected_leader) in expected.iter().enumerate() {
            let leader = LeaderSelector::leader_for_view(view as u64, &vs);
            assert_eq!(leader, expected_leader);
        }
    }

    #[test]
    fn a_tenure_holds_the_leader_for_consecutive_views() {
        let vs = make_validator_set(3);
        // Tenure 1 is the round-robin, view by view.
        for view in 0..9u64 {
            assert_eq!(
                LeaderSelector::leader_for_view_with_tenure(view, 1, &vs),
                LeaderSelector::leader_for_view(view, &vs)
            );
        }
        // Tenure 4: views 0-3 -> 0, 4-7 -> 1, 8-11 -> 2, 12-15 -> 0 again.
        let expected = [0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 0, 0, 0, 0];
        for (view, leader) in expected.iter().enumerate() {
            assert_eq!(LeaderSelector::leader_for_view_with_tenure(view as u64, 4, &vs), *leader, "view {view}");
        }
        // Tenure 0 is read as 1 rather than dividing by it.
        assert_eq!(LeaderSelector::leader_for_view_with_tenure(5, 0, &vs), 2);
    }

    #[test]
    fn test_is_leader() {
        let vs = make_validator_set(4);

        // View 0: validator 0 is leader
        assert!(LeaderSelector::is_leader(0, 0, &vs));
        assert!(!LeaderSelector::is_leader(1, 0, &vs));
        assert!(!LeaderSelector::is_leader(2, 0, &vs));
        assert!(!LeaderSelector::is_leader(3, 0, &vs));

        // View 1: validator 1 is leader
        assert!(!LeaderSelector::is_leader(0, 1, &vs));
        assert!(LeaderSelector::is_leader(1, 1, &vs));

        // View 5: validator 1 is leader (5 % 4 = 1)
        assert!(LeaderSelector::is_leader(1, 5, &vs));
        assert!(!LeaderSelector::is_leader(0, 5, &vs));
    }

    #[test]
    #[should_panic(expected = "leader_for_view called with empty validator set")]
    fn test_leader_for_view_empty_set() {
        let vs = ValidatorSet::new(&[], 0);
        let _leader = LeaderSelector::leader_for_view(5, &vs);
    }

    #[test]
    fn test_leader_for_view_single_validator() {
        let vs = make_validator_set(1);
        for view in 0..10u64 {
            let leader = LeaderSelector::leader_for_view(view, &vs);
            assert_eq!(leader, 0);
        }
    }
}
