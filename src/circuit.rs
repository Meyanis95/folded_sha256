use crate::utils;
use ark_bn254::Fr;
use ark_r1cs_std::{uint32::UInt32, uint8::UInt8};
use ark_relations::r1cs::SynthesisError;

pub const STATE_LEN: usize = 8;

type State = [u32; STATE_LEN];

pub type ConstraintF = Fr;

const H: State = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];

/// Updates the state of the SHA-256 compression function.
///
/// This function performs one round of the SHA-256 compression algorithm,
/// updating the provided state based on the input data. The state and data
/// are represented using `UInt32<ConstraintF>` and `UInt8<ConstraintF>`
/// respectively, which are types used in the context of zk-SNARKs and
/// cryptographic circuits.
///
/// # Arguments
///
/// * `state` - A mutable reference to an array of 8 `UInt32<ConstraintF>` elements
///   representing the current state of the SHA-256 compression function. Denoted as H in the sha2 spec.
/// * `data` - A slice of 64 `UInt8<ConstraintF>` elements representing the input
///   data block to be compressed. Representing the message schedule W.

pub fn one_compression_round(
    state: &mut [UInt32<ConstraintF>],
    data: &[UInt8<ConstraintF>],
) -> Result<Vec<UInt32<ConstraintF>>, SynthesisError> {
    assert_eq!(data.len(), 64);

    let mut w = vec![UInt32::constant(0); 64];
    for (word, chunk) in w.iter_mut().zip(data.chunks(4)) {
        *word = UInt32::from_bytes_be(chunk)?;
    }

    for i in 16..64 {
        let s0 = {
            let x1 = w[i - 15].rotate_right(7);
            let x2 = w[i - 15].rotate_right(18);
            let x3 = &w[i - 15] >> 3u8;
            x1 ^ &x2 ^ &x3
        };
        let s1 = {
            let x1 = w[i - 2].rotate_right(17);
            let x2 = w[i - 2].rotate_right(19);
            let x3 = &w[i - 2] >> 10u8;
            x1 ^ &x2 ^ &x3
        };
        w[i] = UInt32::wrapping_add_many(&[w[i - 16].clone(), s0, w[i - 7].clone(), s1])?;
    }

    let mut h = state.to_vec();
    for i in 0..64 {
        let ch = {
            let x1 = &h[4] & &h[5];
            let x2 = (!&h[4]) & &h[6];
            x1 ^ &x2
        };
        let ma = {
            let x1 = &h[0] & &h[1];
            let x2 = &h[0] & &h[2];
            let x3 = &h[1] & &h[2];
            x1 ^ &x2 ^ &x3
        };
        let s0 = {
            let x1 = h[0].rotate_right(2);
            let x2 = h[0].rotate_right(13);
            let x3 = h[0].rotate_right(22);
            x1 ^ &x2 ^ &x3
        };
        let s1 = {
            let x1 = h[4].rotate_right(6);
            let x2 = h[4].rotate_right(11);
            let x3 = h[4].rotate_right(25);
            x1 ^ &x2 ^ &x3
        };
        let t0 = UInt32::wrapping_add_many(&[
            h[7].clone(),
            s1,
            ch,
            UInt32::constant(utils::K[i]),
            w[i].clone(),
        ])?;
        let t1 = s0.wrapping_add(&ma);

        h[7] = h[6].clone();
        h[6] = h[5].clone();
        h[5] = h[4].clone();
        h[4] = h[3].wrapping_add(&t0);
        h[3] = h[2].clone();
        h[2] = h[1].clone();
        h[1] = h[0].clone();
        h[0] = t0.wrapping_add(&t1);
    }

    for (s, hi) in state.iter_mut().zip(h.iter()) {
        *s = s.wrapping_add(hi);
    }

    Ok(h.clone())
}
