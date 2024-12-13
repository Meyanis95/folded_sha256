use generic_array::{typenum::U64, GenericArray};

pub const K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

pub const BLOCK_LENGTH_BYTES: usize = 64;
pub const BLOCK_LENGTH: usize = 512;

pub fn update_state_ref(state: Vec<u32>, data: Vec<u8>) -> Result<Vec<u32>, &'static str> {
    assert_eq!(data.len(), 64);
    assert_eq!(state.len(), 8);

    // Create a 64-entry message schedule array w[0..63] of 32-bit words
    let mut w = [0u32; 64];
    for (word, chunk) in w.iter_mut().zip(data.chunks(4)) {
        *word = u32::from_be_bytes(chunk.try_into().map_err(|_| "Invalid chunk length")?);
    }

    // Copy chunk into first 16 words w[0..15] of the message schedule array
    for i in 16..64 {
        let s0 = {
            let x1 = w[i - 15].rotate_right(7);
            let x2 = w[i - 15].rotate_right(18);
            let x3 = w[i - 15] >> 3;
            x1 ^ x2 ^ x3
        };
        let s1 = {
            let x1 = w[i - 2].rotate_right(17);
            let x2 = w[i - 2].rotate_right(19);
            let x3 = w[i - 2] >> 10;
            x1 ^ x2 ^ x3
        };
        w[i] = w[i - 16]
            .wrapping_add(s0)
            .wrapping_add(w[i - 7])
            .wrapping_add(s1);
    }

    let mut h = state.clone();
    for i in 0..64 {
        let ch = (h[4] & h[5]) ^ ((!h[4]) & h[6]);
        let ma = (h[0] & h[1]) ^ (h[0] & h[2]) ^ (h[1] & h[2]);
        let s0 = h[0].rotate_right(2) ^ h[0].rotate_right(13) ^ h[0].rotate_right(22);
        let s1 = h[4].rotate_right(6) ^ h[4].rotate_right(11) ^ h[4].rotate_right(25);
        let t0 = h[7]
            .wrapping_add(s1)
            .wrapping_add(ch)
            .wrapping_add(K[i])
            .wrapping_add(w[i]);
        let t1 = s0.wrapping_add(ma);
        h[7] = h[6];
        h[6] = h[5];
        h[5] = h[4];
        h[4] = h[3].wrapping_add(t0);
        h[3] = h[2];
        h[2] = h[1];
        h[1] = h[0];
        h[0] = t0.wrapping_add(t1);
    }

    Ok(h.to_vec())
}

fn add_sha256_padding(input: Vec<u8>) -> Vec<u8> {
    let length_in_bits = (input.len() * 8) as u64;
    let mut padded_input = input;

    // appending a single '1' bit followed by 7 '0' bits
    // This is because the input is a byte vector
    padded_input.push(128u8);

    // Append zeros until the padded input (including 64-byte length)
    // is a multiple of 64 bytes. Note that input is always a byte vector.
    while (padded_input.len() + 8) % BLOCK_LENGTH_BYTES != 0 {
        padded_input.push(0u8);
    }
    padded_input.append(&mut length_in_bits.to_be_bytes().to_vec());
    padded_input
}

fn padded_input_to_blocks(input: Vec<u8>) -> Vec<GenericArray<u8, U64>> {
    assert!(input.len() % BLOCK_LENGTH_BYTES == 0);
    let mut input_clone = input.clone();
    let mut blocks: Vec<Vec<u8>> = vec![];

    let num_blocks = input.len() / BLOCK_LENGTH_BYTES;

    for i in (0..num_blocks).rev() {
        let block: Vec<u8> = input_clone.drain(i * BLOCK_LENGTH_BYTES..).collect();
        blocks.push(block);
    }

    // Reverse the order of the blocks as they were pushed in reverse order
    blocks.reverse();

    let blocks_ga_vec: Vec<GenericArray<u8, U64>> = blocks
        .iter()
        .map(|a| GenericArray::<u8, U64>::clone_from_slice(a))
        .collect();
    blocks_ga_vec
}

pub fn sha256_msg_block_sequence(input: Vec<u8>) -> Vec<[u8; BLOCK_LENGTH_BYTES]> {
    let padded_input = add_sha256_padding(input);
    let blocks_vec: Vec<GenericArray<u8, U64>> = padded_input_to_blocks(padded_input);
    let blocks_vec_bytes: Vec<[u8; BLOCK_LENGTH_BYTES]> = blocks_vec
        .into_iter()
        .map(|b| b.try_into().unwrap())
        .collect();
    blocks_vec_bytes
}
