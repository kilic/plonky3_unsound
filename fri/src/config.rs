use core::marker::PhantomData;

use p3_challenger::{CanObserve, GrindingChallenger};
use p3_commit::{DirectMmcs, Mmcs};
use p3_field::{ExtensionField, PrimeField64, TwoAdicField};

pub trait FriConfig {
    type Val: PrimeField64;
    type Challenge: ExtensionField<Self::Val> + TwoAdicField;

    type InputMmcs: Mmcs<Self::Val>;
    type CommitPhaseMmcs: DirectMmcs<Self::Challenge>;

    type Challenger: GrindingChallenger<Self::Val>
        + CanObserve<<Self::CommitPhaseMmcs as Mmcs<Self::Challenge>>::Commitment>;

    fn commit_phase_mmcs(&self) -> &Self::CommitPhaseMmcs;

    fn num_queries(&self) -> usize;

    fn log_blowup(&self) -> usize;

    fn blowup(&self) -> usize {
        1 << self.log_blowup()
    }

    fn proof_of_work_bits(&self) -> usize;
}

pub struct FriConfigImpl<Val, Challenge, InputMmcs, CommitPhaseMmcs, Challenger> {
    log_blowup: usize,
    num_queries: usize,
    proof_of_work_bits: usize,
    commit_phase_mmcs: CommitPhaseMmcs,
    _phantom: PhantomData<(Val, Challenge, InputMmcs, Challenger)>,
}

impl<Val, Challenge, InputMmcs, CommitPhaseMmcs, Challenger>
    FriConfigImpl<Val, Challenge, InputMmcs, CommitPhaseMmcs, Challenger>
{
    pub fn new(
        log_blowup: usize,
        num_queries: usize,
        proof_of_work_bits: usize,
        commit_phase_mmcs: CommitPhaseMmcs,
    ) -> Self {
        Self {
            log_blowup,
            num_queries,
            commit_phase_mmcs,
            proof_of_work_bits,
            _phantom: PhantomData,
        }
    }
}

impl<Val, Challenge, InputMmcs, CommitPhaseMmcs, Challenger> FriConfig
    for FriConfigImpl<Val, Challenge, InputMmcs, CommitPhaseMmcs, Challenger>
where
    Val: PrimeField64,
    Challenge: ExtensionField<Val> + TwoAdicField,
    InputMmcs: Mmcs<Val>,
    CommitPhaseMmcs: DirectMmcs<Challenge>,
    Challenger:
        GrindingChallenger<Val> + CanObserve<<CommitPhaseMmcs as Mmcs<Challenge>>::Commitment>,
{
    type Val = Val;
    type Challenge = Challenge;
    type InputMmcs = InputMmcs;
    type CommitPhaseMmcs = CommitPhaseMmcs;
    type Challenger = Challenger;

    fn commit_phase_mmcs(&self) -> &CommitPhaseMmcs {
        &self.commit_phase_mmcs
    }

    fn num_queries(&self) -> usize {
        self.num_queries
    }

    fn log_blowup(&self) -> usize {
        self.log_blowup
    }

    fn proof_of_work_bits(&self) -> usize {
        self.proof_of_work_bits
    }
}
