#![allow(non_snake_case)]
use ark_groth16::Groth16;
use folded_sha256::folded_sha256::main::H;
use folded_sha256::folded_sha256::utils::sha256_msg_block_sequence;

use clap::{Arg, Command};
use folded_sha256::folded_sha256::main::FoldedSha256FCircuit;
use std::time::Instant;

use ark_bn254::{constraints::GVar, Bn254, Fr, G1Projective as G1};
use ark_grumpkin::{constraints::GVar as GVar2, Projective as G2};

use ark_std::rand;
use folding_schemes::{
    commitment::{kzg::KZG, pedersen::Pedersen},
    folding::{
        nova::{decider_eth::Decider as DeciderEth, Nova, PreprocessorParam},
        traits::CommittedInstanceOps,
    },
    frontend::FCircuit,
    transcript::poseidon::poseidon_canonical_config,
    Decider, FoldingScheme,
};

fn main() {
    let cmd = Command::new("Nova-based SHA256 circuit proof generation and verification")
    .bin_name("sha256")
    .arg(
        Arg::new("input_len_log")
            .value_name("Log2 of the test input length")
            .default_value("6")
            .value_parser(clap::value_parser!(usize))
            .long_help("Base 2 log of the test input length. For example, the value of 8 corresponds to 256 bytes of input. ")   
    )
    .after_help("This command generates a proof that the hash of 2^(input_log_len) zero bytes");

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

    let m = cmd.get_matches();
    let log_input_len = *m.get_one::<usize>("input_len_log").unwrap();
    let input_len = 1 << log_input_len;
    println!("Input Length: {:?}", input_len);

    println!("Nova-based SHA256 compression function iterations");
    println!("=========================================================");

    let F_circuit = FoldedSha256FCircuit::<Fr>::new(()).unwrap();

    let poseidon_config = poseidon_canonical_config::<Fr>();
    let mut rng = rand::rngs::OsRng;

    type N = Nova<
        G1,
        GVar,
        G2,
        GVar2,
        FoldedSha256FCircuit<Fr>,
        KZG<'static, Bn254>,
        Pedersen<G2>,
        false,
    >;
    pub type D = DeciderEth<
        G1,
        GVar,
        G2,
        GVar2,
        FoldedSha256FCircuit<Fr>,
        KZG<'static, Bn254>,
        Pedersen<G2>,
        Groth16<Bn254>,
        N,
    >;

    let param_gen_timer = Instant::now();
    println!("Prepare Nova ProverParams & VerifierParams");
    let nova_preprocess_params = PreprocessorParam::new(poseidon_config, F_circuit);
    let nova_params = N::preprocess(&mut rng, &nova_preprocess_params).unwrap();

    println!("Initialize FoldingScheme");
    let mut folding_scheme = N::init(&nova_params, F_circuit, initial_state.clone()).unwrap();
    let param_gen_time = param_gen_timer.elapsed();
    println!("PublicParams::setup, took {:?} ", param_gen_time);

    // prepare the Decider prover & verifier params
    println!("Generating the Decider Public Parameters");
    let preprocess_timer = Instant::now();
    let (decider_pp, decider_vp) =
        D::preprocess(&mut rng, nova_params, folding_scheme.clone()).unwrap();
    println!(
        "Nova::Decider preprocess, took: {:?}",
        preprocess_timer.elapsed()
    );

    let input: Vec<u8> = vec![0u8; input_len]; // All the input bytes are zero
    let block_sequence = sha256_msg_block_sequence(input);

    // produce a recursive SNARK
    println!("Generating a RecursiveSNARK...");
    let proof_gen_timer = Instant::now();
    // compute a step of the IVC
    for (i, external_inputs_at_step) in block_sequence.iter().enumerate() {
        let step_start = Instant::now();
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
        println!("Nova::prove_step {}: {:?}", i, step_start.elapsed());
    }
    println!(
        "Total time taken by RecursiveSNARK::prove_steps: {:?}",
        proof_gen_timer.elapsed()
    );

    // verify the recursive SNARK
    // println!("Run the Nova's IVC verifier");
    // let start = Instant::now();
    // let ivc_proof = folding_scheme.ivc_proof();
    // N::verify(
    //     nova_params.1, // Nova's verifier params
    //     ivc_proof,
    // )
    // .unwrap();
    // println!("RecursiveSNARK::verify took {:?}", start.elapsed());

    println!("Run the Nova's Decider Prover");
    let start = Instant::now();
    let proof = D::prove(rng, decider_pp, folding_scheme.clone()).unwrap();
    println!("generated Decider proof: {:?}", start.elapsed());

    let verified = D::verify(
        decider_vp.clone(),
        folding_scheme.i,
        folding_scheme.z_0.clone(),
        folding_scheme.z_i.clone(),
        &folding_scheme.U_i.get_commitments(),
        &folding_scheme.u_i.get_commitments(),
        &proof,
    )
    .unwrap();
    assert!(verified);
    println!("Decider proof verification: {}", verified);
}
