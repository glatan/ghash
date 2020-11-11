mod edonr224;
mod edonr256;

pub use edonr224::EdonR224;
pub use edonr256::EdonR256;

mod consts;

use consts::*;

struct EdonR<T> {
    state: [T; 16],
}

impl EdonR<u32> {
    fn new(iv: [u32; 16]) -> Self {
        Self { state: iv }
    }
    fn compress(&mut self, message: &[u32; 16]) {
        let mut state_8 = [
            self.state[0],
            self.state[1],
            self.state[2],
            self.state[3],
            self.state[4],
            self.state[5],
            self.state[6],
            self.state[7],
        ];
        let mut state_16 = [
            self.state[8],
            self.state[9],
            self.state[10],
            self.state[11],
            self.state[12],
            self.state[13],
            self.state[14],
            self.state[15],
        ];
        let mut state_24;
        let mut state_32;
        // First row of quasigroup e-transformations
        state_24 = q256(
            &[
                message[15],
                message[14],
                message[13],
                message[12],
                message[11],
                message[10],
                message[9],
                message[8],
            ],
            &[
                message[0], message[1], message[2], message[3], message[4], message[5], message[6],
                message[7],
            ],
        );
        state_32 = q256(
            &state_24,
            &[
                message[8],
                message[9],
                message[10],
                message[11],
                message[12],
                message[13],
                message[14],
                message[15],
            ],
        );
        // Second row of quasigroup e-transformations
        state_24 = q256(&state_16, &state_24);
        state_32 = q256(&state_24, &state_32);
        // Third row of quasigroup e-transformations
        state_24 = q256(&state_24, &state_8);
        state_32 = q256(&state_32, &state_24);
        // Fourth row of quasigroup e-transformations
        state_8 = q256(
            &[
                message[7], message[6], message[5], message[4], message[3], message[2], message[1],
                message[0],
            ],
            &state_24,
        );
        state_16 = q256(&state_8, &state_32);
        self.state[0..8].copy_from_slice(&state_8);
        self.state[8..16].copy_from_slice(&state_16);
    }
}
