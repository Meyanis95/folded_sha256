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
use utils::sha256_msg_block_sequence;

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

        // Convert external_inputs to Vec<u8>
        let _external_inputs_to_u8: Vec<u8> = _external_inputs
            .iter()
            // we only need to take the most significant byte for each input
            .map(|x| x.into_bigint().to_bytes_le()[0])
            .collect();

        let updated_state = utils::update_state_ref(z_to_u32, _external_inputs_to_u8).unwrap();

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
        println!("generate_step_constraints");
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

        // THe circuit is outputting the right state, so the issue might be in type conversion
        let h = circuit::one_compression_round(&mut state, &data).unwrap();

        let h_to_fp_var: Vec<FpVar<F>> = h.iter().map(|x| x.to_fp().unwrap()).collect();

        Ok(h_to_fp_var)
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use ark_r1cs_std::{alloc::AllocVar, R1CSVar};
    use ark_relations::r1cs::ConstraintSystem;

    // test to check that the MultiInputsFCircuit computes the same values inside and outside the circuit
    #[test]
    fn test_f_circuit() {
        let cs = ConstraintSystem::<Fr>::new_ref();

        let circuit = FoldedSha256FCircuit::<Fr>::new(()).unwrap();
        let z_i = vec![
            Fr::from(H[0]),
            Fr::from(H[1]),
            Fr::from(H[2]),
            Fr::from(H[3]),
            Fr::from(H[4]),
            Fr::from(H[5]),
            Fr::from(H[6]),
            Fr::from(H[7]),
        ];

        let input: Vec<u8> = b"abc".to_vec();
        let block_sequence = sha256_msg_block_sequence(input)[0].to_vec();
        let external_inputs: Vec<ark_ff::Fp<ark_ff::MontBackend<ark_bn254::FrConfig, 4>, 4>> =
            block_sequence.iter().map(|x| Fr::from(x.clone())).collect();

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

    #[test]
    fn test_sha256_correctness() {
        let circuit = FoldedSha256FCircuit::<Fr>::new(()).unwrap();
        let z_i: Vec<ark_ff::Fp<ark_ff::MontBackend<ark_bn254::FrConfig, 4>, 4>> = vec![
            Fr::from(H[0]),
            Fr::from(H[1]),
            Fr::from(H[2]),
            Fr::from(H[3]),
            Fr::from(H[4]),
            Fr::from(H[5]),
            Fr::from(H[6]),
            Fr::from(H[7]),
        ];

        let input: Vec<u8> = b"abc".to_vec();
        let block_sequence = sha256_msg_block_sequence(input);

        let external_inputs: Vec<ark_ff::Fp<ark_ff::MontBackend<ark_bn254::FrConfig, 4>, 4>> =
            block_sequence[0]
                .iter()
                .map(|x| Fr::from(x.clone()))
                .collect();

        let z_i1 = circuit
            .step_native(0, z_i.clone(), external_inputs.clone())
            .unwrap();

        // Convert the final state to a hexadecimal string
        let final_hash = z_i1
            .iter()
            .flat_map(|x| {
                let bytes = x.into_bigint().to_bytes_be();
                // Take the last 4 bytes to avoid leading zeros
                bytes[bytes.len() - 4..].to_vec()
            })
            .collect::<Vec<u8>>();

        let hex_string = final_hash
            .iter()
            .map(|byte| format!("{:02x}", byte))
            .collect::<String>();

        assert_eq!(
            hex_string,
            // Corresponding sha256 hash of "abc"
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }
}

fn main() {
    let input: Vec<u8> = b"abc".to_vec();
    let block_sequence = sha256_msg_block_sequence(input);

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

    // let external_inputs = vec![Fr::from(0_u8); 64];

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
    for (i, external_inputs_at_step) in block_sequence.iter().enumerate() {
        let start = Instant::now();
        folding_scheme
            .prove_step(
                rng,
                external_inputs_at_step
                    .clone()
                    .iter()
                    .map(|x| Fr::from(x.clone()))
                    .collect(),
                None,
            )
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

    // Convert the final state to a hexadecimal string
    // let final_hash = folding_scheme
    //     .z_i
    //     .iter()
    //     .flat_map(|x| {
    //         let bytes = x.into_bigint().to_bytes_be();
    //         // Take the last 4 bytes to avoid leading zeros
    //         bytes[bytes.len() - 4..].to_vec()
    //     })
    //     .collect::<Vec<u8>>();

    // let hex_string = final_hash
    //     .iter()
    //     .map(|byte| format!("{:02x}", byte))
    //     .collect::<String>();

    // println!("Final hash: {}", hex_string);
}
