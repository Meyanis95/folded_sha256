#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(clippy::upper_case_acronyms)]
mod circuit;
mod utils;

use std::time::Instant;

use ark_ff::{BigInteger, PrimeField};
use ark_r1cs_std::fields::fp::FpVar;
use ark_r1cs_std::uint32::UInt32;
use ark_r1cs_std::uint8::UInt8;
use ark_relations::r1cs::{ConstraintSystemRef, SynthesisError};
use ark_std::marker::PhantomData;

use ark_bn254::{constraints::GVar, Bn254, Fr, G1Projective as Projective};
use ark_grumpkin::{constraints::GVar as GVar2, Projective as Projective2};

use ark_std::rand;
use folding_schemes::commitment::{kzg::KZG, pedersen::Pedersen};
use folding_schemes::folding::nova::{Nova, PreprocessorParam};
use folding_schemes::frontend::FCircuit;
use folding_schemes::transcript::poseidon::poseidon_canonical_config;
use folding_schemes::{Error, FoldingScheme};

pub const STATE_LEN: usize = 8;

type State = [u32; STATE_LEN];

const H: State = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];

fn bigint_to_u32<F: PrimeField>(x: F) -> u32 {
    let bigint = x.into_bigint();
    let bytes = bigint.to_bytes_le();
    let mut array = [0u8; 4];
    let len = bytes.len().min(4);
    array[..len].copy_from_slice(&bytes[..len]);
    u32::from_le_bytes(array)
}

#[derive(Clone, Copy, Debug)]
pub struct FoldedSha256FCircuit<F: PrimeField> {
    _f: PhantomData<F>,
}
impl<F: PrimeField> FCircuit<F> for FoldedSha256FCircuit<F> {
    type Params = ();

    fn new(_params: Self::Params) -> Result<Self, Error> {
        Ok(Self { _f: PhantomData })
    }

    fn state_len(&self) -> usize {
        8
    }
    fn external_inputs_len(&self) -> usize {
        64
    }

    fn step_native(
        &self,
        _i: usize,
        z_i: Vec<F>,
        _external_inputs: Vec<F>,
    ) -> Result<Vec<F>, Error> {
        // z_i is the state of our sha2 algo
        // external_inputs is the message block to be compressed

        // Convert z_i to Vec<u32>
        let z_to_u32: Vec<u32> = z_i.iter().map(|&x| bigint_to_u32(x)).collect::<Vec<u32>>();

        // Convert Vec<u32> to [u32; 8]
        let mut z_to_u32_array: [u32; 8] = [0; 8];
        z_to_u32_array.copy_from_slice(&z_to_u32);

        let updated_state = utils::update_state_ref(
            z_to_u32,
            _external_inputs
                .iter()
                // we only need to take the most significant byte of each input
                .map(|x| x.into_bigint().to_bytes_le()[0])
                .collect(),
        )
        .unwrap();
        let out: Vec<F> = updated_state.iter().map(|&x| F::from(x)).collect();

        Ok(out)
    }

    fn generate_step_constraints(
        &self,
        _cs: ConstraintSystemRef<F>,
        _i: usize,
        z_i: Vec<FpVar<F>>,
        _external_inputs: Vec<FpVar<F>>,
    ) -> Result<Vec<FpVar<F>>, SynthesisError> {
        // z_i is the state of our sha2 algo
        // external_inputs is the message block to be compressed
        let mut state: Vec<UInt32<F>> = vec![
            UInt32::from_fp(&z_i[0].clone()).unwrap().0,
            UInt32::from_fp(&z_i[1].clone()).unwrap().0,
            UInt32::from_fp(&z_i[2].clone()).unwrap().0,
            UInt32::from_fp(&z_i[3].clone()).unwrap().0,
            UInt32::from_fp(&z_i[4].clone()).unwrap().0,
            UInt32::from_fp(&z_i[5].clone()).unwrap().0,
            UInt32::from_fp(&z_i[6].clone()).unwrap().0,
            UInt32::from_fp(&z_i[7].clone()).unwrap().0,
        ];

        let data: Vec<UInt8<F>> = _external_inputs
            .iter()
            .map(|x| UInt8::from_fp(&x.clone()).unwrap().0)
            .collect();

        let h = circuit::one_compression_round(&mut state, &data).unwrap();

        let result = h.iter().map(|x| x.to_fp().unwrap()).collect();

        Ok(result)
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use ark_r1cs_std::{alloc::AllocVar, R1CSVar};
    use ark_relations::r1cs::ConstraintSystem;
    use utils::sha256_msg_block_sequence;

    // test to check that the MultiInputsFCircuit computes the same values inside and outside the circuit
    #[test]
    fn test_f_circuit() {
        let cs = ConstraintSystem::<Fr>::new_ref();

        let circuit = FoldedSha256FCircuit::<Fr>::new(()).unwrap();
        let z_i = vec![
            Fr::from(1_u32),
            Fr::from(1_u32),
            Fr::from(1_u32),
            Fr::from(1_u32),
            Fr::from(1_u32),
            Fr::from(1_u32),
            Fr::from(1_u32),
            Fr::from(1_u32),
        ];

        let external_inputs = vec![Fr::from(155_u8); 64];

        let z_i1 = circuit
            .step_native(0, z_i.clone(), external_inputs.clone())
            .unwrap();

        let z_iVar = Vec::<FpVar<Fr>>::new_witness(cs.clone(), || Ok(z_i)).unwrap();
        let externalInputsVar =
            Vec::<FpVar<Fr>>::new_witness(cs.clone(), || Ok(external_inputs)).unwrap();
        let computed_z_i1Var = circuit
            .generate_step_constraints(cs.clone(), 0, z_iVar.clone(), externalInputsVar)
            .unwrap();
        assert_eq!(computed_z_i1Var.value().unwrap(), z_i1);
    }
}

fn main() {
    let num_steps = 10;
    let initial_state = vec![
        Fr::from(H[0]),
        Fr::from(H[1]),
        Fr::from(H[2]),
        Fr::from(H[3]),
        Fr::from(H[4]),
        Fr::from(H[5]),
        Fr::from(H[6]),
        Fr::from(H[7]),
    ];

    let external_inputs = vec![Fr::from(0_u8); 64];

    let F_circuit = FoldedSha256FCircuit::<Fr>::new(()).unwrap();

    let poseidon_config = poseidon_canonical_config::<Fr>();
    let mut rng = rand::rngs::OsRng;

    /// The idea here is that eventually we could replace the next line chunk that defines the
    /// `type N = Nova<...>` by using another folding scheme that fulfills the `FoldingScheme`
    /// trait, and the rest of our code would be working without needing to be updated.
    type N = Nova<
        Projective,
        GVar,
        Projective2,
        GVar2,
        FoldedSha256FCircuit<Fr>,
        KZG<'static, Bn254>,
        Pedersen<Projective2>,
        false,
    >;

    println!("Prepare Nova ProverParams & VerifierParams");
    let nova_preprocess_params = PreprocessorParam::new(poseidon_config, F_circuit);
    let nova_params = N::preprocess(&mut rng, &nova_preprocess_params).unwrap();

    println!("Initialize FoldingScheme");
    let mut folding_scheme = N::init(&nova_params, F_circuit, initial_state.clone()).unwrap();

    // compute a step of the IVC
    for i in 0..num_steps {
        let start = Instant::now();
        folding_scheme
            .prove_step(rng, external_inputs.clone(), None)
            .unwrap();
        println!("Nova::prove_step {}: {:?}", i, start.elapsed());
    }

    println!("Run the Nova's IVC verifier");
    let ivc_proof = folding_scheme.ivc_proof();
    N::verify(
        nova_params.1, // Nova's verifier params
        ivc_proof,
    )
    .unwrap();
}
