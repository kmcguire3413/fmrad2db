/*
	A randomly readable vector that automatically resizes as
	data is written into it. It supports reading and writing
    integers and byte arrays in different endianess.

	At the moment it is unoptimized, but if needed later it
	will support pre-allocation to a specific capacity, and
	do resizing per method instead of for each byte written.
*/
use std::iter::repeat;

pub struct SuperVec {
	pub data: Vec<u8>
}

impl SuperVec {
	pub fn new() -> SuperVec {
		SuperVec {
			data: Vec::new()
		}
	}
	pub fn get_data(self) -> Vec<u8> {
		self.data
	}
	pub fn from_vec(v8: &Vec<u8>) -> SuperVec {
		SuperVec {
			data: v8.to_vec()
		}
	}
	pub fn len(&self) -> usize {
		self.data.len()
	}
	pub fn writeu8(&mut self, o: usize, v: u8) {
		if o >= self.data.len() {
			let amt = (o - self.data.len()) + 1;
			self.data.extend(repeat(0).take(amt));
		}
		self.data[o] = v;
	}
	pub fn writeu16le(&mut self, o: usize, v: u16) {
		self.writeu8(o + 0, v as u8);
		self.writeu8(o + 1, (v >> 8) as u8);
	}
	pub fn writeu16be(&mut self, o: usize, v: u16) {
		self.writeu8(o + 1, v as u8);
		self.writeu8(o + 0, (v >> 8) as u8);
	}
	pub fn writeu32be(&mut self, o: usize, v: u32) {
		self.writeu16be(o + 2, v as u16);
		self.writeu16be(o + 0, (v >> 16) as u16);
	}
	pub fn writeu8i(&mut self, o: usize, v: &Vec<u8>) {
		self.writeu8is(o, v.as_slice());
	}
	pub fn writeu8is(&mut self, o: usize, v: &[u8]) {
		for x in 0..v.len() {
			self.writeu8(o + x, v[x]);
		}
	}
	pub fn readu8i(&self, o: usize, l: usize) -> Vec<u8> {
		let mut v8: Vec<u8> = Vec::new();
		for x in 0..l {
			v8.push(self.readu8(o + x));
		}
		v8
	}
	pub fn readu8(&self, o: usize) -> u8 {
		if o >= self.data.len() {
			/*
				An improvement would be to allow specification
				of the value to use for memory not allocated.
			*/
			0x00
		} else {
			self.data[o]
		}
	}
	pub fn readu16le(&self, o: usize) -> u16 {
		(self.readu8(o + 0) as u16) | ((self.readu8(o + 1) as u16) << 8)
	}
	pub fn readu16be(&self, o: usize) -> u16 {
		((self.readu8(o + 0) as u16) << 8) | self.readu8(o + 1) as u16
	}
	pub fn readu32be(&self, o: usize) -> u32 {
		((self.readu16be(o + 0) as u32) << 16) | self.readu16be(o + 2) as u32
	}
}
