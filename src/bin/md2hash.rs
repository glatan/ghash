use std::vec;

const _STABLE: [u8; 256] = [
  41, 46, 67, 201, 162, 216, 124, 1, 61, 54, 84, 161, 236, 240, 6,
	19, 98, 167, 5, 243, 192, 199, 115, 140, 152, 147, 43, 217, 188,
	76, 130, 202, 30, 155, 87, 60, 253, 212, 224, 22, 103, 66, 111, 24,
	138, 23, 229, 18, 190, 78, 196, 214, 218, 158, 222, 73, 160, 251,
	245, 142, 187, 47, 238, 122, 169, 104, 121, 145, 21, 178, 7, 63,
	148, 194, 16, 137, 11, 34, 95, 33, 128, 127, 93, 154, 90, 144, 50,
	39, 53, 62, 204, 231, 191, 247, 151, 3, 255, 25, 48, 179, 72, 165,
	181, 209, 215, 94, 146, 42, 172, 86, 170, 198, 79, 184, 56, 210,
	150, 164, 125, 182, 118, 252, 107, 226, 156, 116, 4, 241, 69, 157,
	112, 89, 100, 113, 135, 32, 134, 91, 207, 101, 230, 45, 168, 2, 27,
	96, 37, 173, 174, 176, 185, 246, 28, 70, 97, 105, 52, 64, 126, 15,
	85, 71, 163, 35, 221, 81, 175, 58, 195, 92, 249, 206, 186, 197,
	234, 38, 44, 83, 13, 110, 133, 40, 132, 9, 211, 223, 205, 244, 65,
	129, 77, 82, 106, 220, 55, 200, 108, 193, 171, 250, 36, 225, 123,
	8, 12, 189, 177, 74, 120, 136, 149, 139, 227, 99, 232, 109, 233,
	203, 213, 254, 59, 0, 29, 57, 242, 239, 183, 14, 102, 88, 208, 228,
	166, 119, 114, 248, 235, 117, 75, 10, 49, 68, 80, 180, 143, 237,
  31, 26, 219, 153, 141, 51, 159, 17, 131, 20
];

const _BLOCKSIZE:usize = 16;

struct MD2_CTX {
	/*
		data {
			input + padding_byte : 16*n bytes
			+
			checksum : 16 bytes
		}
	*/
	data: Vec<u8>,
	state: Box<[u8; 48]>,
}

impl MD2_CTX {
	fn new(_input: Vec<u8>) -> MD2_CTX{
		MD2_CTX { 
			data: _input,
			state: Box::new([0; 48]),
		}
	}
	fn padding(&mut self) -> &mut MD2_CTX {
		/*
			_padding_byte: self.dataを16の整数倍長に調整するための値
			_padding_range: パディングバイトを追加する幅
		*/
		let _n = self.data.len();
		let _padding_byte = (_BLOCKSIZE - (_n % _BLOCKSIZE)) as u8;
		let _padding_range = _n..(_n + _padding_byte as usize);
		for _ in _padding_range {
			self.data.push(_padding_byte);
		}
		self
	}
	fn add_checks_sum(&mut self) -> &mut MD2_CTX {
		let mut _c = 0;
		let mut _C = vec![0; 16];
		let mut _l = 0;
		let _n = (self.data.len() / _BLOCKSIZE) as u8;

		for i in 0.._n {
			for j in 0..16 {
				_c = self.data[(i*16+j) as usize];
				_C[j as usize] ^= _STABLE[(_c ^ _l) as usize];
				_l = _C[j as usize];
				self.data.push(_C[j as usize]);
			}
		}
		self
	}
	fn round(&mut self) -> &mut MD2_CTX{
		let _n = (self.data.len() / _BLOCKSIZE) as u8;

		for i in 0.._n {
			for j in 0..16 {
				self.state[(j+16) as usize] = self.data[(i*16+j) as usize];
				self.state[(j+32) as usize] = self.state[(j+16) as usize] ^ self.state[j as usize];
			}
			let mut t = 0;
			for j in 0..18 {
				for k in 0..48 {
					self.state[k as usize] ^= _STABLE[t as usize];
					t = self.state[k as usize];
				}
				t = ((t as u16 + j as u16) % 256) as u8;
			}
		}
		self
	}
	fn print_hash(&mut self) {
		let hash: Vec<String> = self.state[0..16].iter()
															.map(|byte| format!("{:02x}", byte))
															.collect();
		println!("md2hash: \"{}\"", hash.connect(""));
	}
}

fn main() {
	let _sample: String = "a".to_string();
	println!("input_data: \"{}\"", _sample);
	let mut _input: Vec<u8> = _sample.as_bytes().to_vec();
	let _md2_ctx = MD2_CTX::new(_input)
										.padding()
										.add_checks_sum()
										.round()
										.print_hash();
}
