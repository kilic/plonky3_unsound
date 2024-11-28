use std::fmt::Debug;
use std::marker::PhantomData;

use p3_air::{Air, AirBuilder, BaseAir};
use p3_challenger::{HashChallenger, SerializingChallenger32, SerializingChallenger64};
use p3_circle::CirclePcs;
use p3_commit::ExtensionMmcs;
use p3_dft::Radix2DitParallel;
use p3_field::extension::BinomialExtensionField;
use p3_field::{Field, FieldAlgebra};
use p3_fri::{FriConfig, TwoAdicFriPcs};
use p3_goldilocks::Goldilocks;
use p3_keccak::Keccak256Hash;
use p3_matrix::dense::RowMajorMatrix;
use p3_matrix::Matrix;
use p3_merkle_tree::MerkleTreeMmcs;
use p3_mersenne_31::Mersenne31;
use p3_symmetric::{CompressionFunctionFromHasher, SerializingHasher64};
use p3_uni_stark::{prove, verify, StarkConfig};
use tracing_forest::util::LevelFilter;
use tracing_forest::ForestLayer;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::{EnvFilter, Registry};

pub struct MulAir {
    pub num_steps: usize,
}

impl<F: Field> BaseAir<F> for MulAir {
    fn width(&self) -> usize {
        4
    }
}

impl<AB: AirBuilder> Air<AB> for MulAir {
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local = main.row_slice(0);
        let ab = local[0] * local[1];
        let cd = local[2] * local[3];

        builder.when_transition().assert_eq(ab, cd);
    }
}

pub fn generate_mul_trace<F: Field>(num_steps: usize) -> RowMajorMatrix<F> {
    let values = (0..num_steps)
        // bad witness
        .flat_map(|_| vec![F::ZERO, F::ZERO, F::ONE, F::ONE])
        // good witness
        // .flat_map(|_| vec![F::ZERO, F::ZERO, F::ONE, F::ZERO])
        .collect();
    RowMajorMatrix::new(values, 4)
}

#[test]
fn test() {
    type Val = Goldilocks;
    type Challenge = BinomialExtensionField<Val, 2>;

    type ByteHash = Keccak256Hash;
    type FieldHash = SerializingHasher64<ByteHash>;
    type MyCompress = CompressionFunctionFromHasher<ByteHash, 2, 32>;
    type ValMmcs = MerkleTreeMmcs<Val, u8, FieldHash, MyCompress, 32>;
    type ChallengeMmcs = ExtensionMmcs<Val, Challenge, ValMmcs>;
    type Challenger = SerializingChallenger64<Val, HashChallenger<u8, ByteHash, 32>>;
    
    type Dft = Radix2DitParallel<Val>;
    type Pcs = TwoAdicFriPcs<Val, Dft, ValMmcs, ChallengeMmcs>;
    // type Pcs = CirclePcs<Val, ValMmcs, ChallengeMmcs>;
    type MyConfig = StarkConfig<Pcs, Challenge, Challenger>;

    let byte_hash = ByteHash {};
    let field_hash = FieldHash::new(Keccak256Hash {});
    let compress = MyCompress::new(byte_hash);
    let val_mmcs = ValMmcs::new(field_hash, compress);
    let challenge_mmcs = ChallengeMmcs::new(val_mmcs.clone());
    let fri_config = FriConfig {
        log_blowup: 1,
        num_queries: 3,
        proof_of_work_bits: 16,
        mmcs: challenge_mmcs,
    };
    let pcs = Pcs::new(Dft::default(), val_mmcs, fri_config);
    let stark = MyConfig::new(pcs);

    let num_steps = 8;
    let air = MulAir { num_steps };
    let trace = generate_mul_trace::<Val>(num_steps);

    let mut challenger = Challenger::from_hasher(vec![], byte_hash);
    let proof = prove(&stark, &air, &mut challenger, trace, &vec![]);

    let mut challenger = Challenger::from_hasher(vec![], byte_hash);
    verify(&stark, &air, &mut challenger, &proof, &vec![]).unwrap()
}
