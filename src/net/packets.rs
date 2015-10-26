use super::SuperVec;

/*
	This is a complete packet with the 802.3, IP4, and
	TCP stack. I plan to break these out into their own
	sections in order to facilitate code re-use but for
	the moment this serves the intended purpose very well.
*/
pub struct EthIp4TcpPacket {
	pub data:		SuperVec
}

impl EthIp4TcpPacket {
	pub fn from_vec(v8: &Vec<u8>) -> EthIp4TcpPacket {
		EthIp4TcpPacket {
			data: SuperVec::from_vec(v8)
		}
	}
	pub fn get_data(self) -> Vec<u8> {
		let mut data = self.data.get_data();
		// TODO: figure this bug out...
		//data.pop();
		data
	}
	pub fn empty() -> EthIp4TcpPacket {
		EthIp4TcpPacket { data: SuperVec::new() }
	}
	pub fn len(&self) -> usize {
		self.data.len()
	}
	/*
		Sets some common options that are easy to forget.
	*/
	pub fn default() -> EthIp4TcpPacket {
		let mut r = EthIp4TcpPacket { data: SuperVec::new() };
		r.write_eth_type(0x0800);
		r.write_ip_version(0x4);
		r.write_ip_hdrlen(5);
		r.write_ip_dsf(0);
		r.write_ip_ttl(0x40);
		r.write_ip_protocol(0x06);
		r.write_tcp_window_size(0x154);
		r.write_tcp_hdrlen(8);
		r.write_ip_total_length(52);
		r.data.writeu8(52 + 13, 0x00);
		r
	}
	pub fn compute_ip_checksum(&mut self) {
		let mut sum: u32;
		let ip_offset = self.read_ip_offset();
		let ip_hdrlen: usize = (self.read_ip_hdrlen() * 4) as usize;
		self.write_ip_checksum(0 as u16);
		sum = 0;
		for x in 0..(ip_hdrlen / 2) {
			sum += self.data.readu16be(ip_offset + x * 2) as u32;
		}

		while (sum >> 16) > 0 {
			sum = (sum & 0xffff) + (sum >> 16);
		}

		self.write_ip_checksum((!sum) as u16);
	}
	pub fn revind16(v: u16) -> u16 {
		(v << 8) | (v >> 8)
	}
	pub fn revind32(v: u32) -> u32 {
		let a = (v >> 24) & 0xff;
		let b = (v >> 16) & 0xff;
		let c = (v >> 8) & 0xff;
		let d = v & 0xff;

		(d << 24) | (c << 16) | (b << 8) | a
	}
	pub fn compute_tcp_checksum(&mut self) {
		let mut sum: u32;
		sum = 0;

		// source address (32)
		// destination address (32)
		// reserved (8)
		// protocol (8)
		// tcp segment length (16)

		let tcp_offset = self.read_tcp_offset();

		self.write_tcp_checksum(0 as u16);

		println!("ip_total_length:{}", self.read_ip_total_length());
		println!("tcp_offset:{}", tcp_offset);

		let ip_hdr_size = self.read_ip_hdrlen() as u32 * 4;

		let mut tcp_len: u32 = self.read_ip_total_length() as u32 - ip_hdr_size;

		let units: usize = (tcp_len / 2) as usize;

		for x in 0..units {
			sum += self.data.readu16be(tcp_offset + x * 2) as u32;
		}

		if tcp_len & 1 > 0 {
			println!("ODD BALL");
			let lastbyte = self.data.len() - 1;
			sum += (self.data.readu8(lastbyte) as u32) << 8;
		}

		sum += self.data.readu16be(0x1a) as u32; // src
		sum += self.data.readu16be(0x1c) as u32; // src
		sum += self.data.readu16be(0x1e) as u32; // dst
		sum += self.data.readu16be(0x20) as u32; // dst

		sum += self.data.readu8(0x17) as u32;

		println!("tcp_len:{}", tcp_len);

		sum += tcp_len as u32;

		while (sum >> 16) > 0 {
			sum = (sum & 0xffff) + (sum >> 16);
		}

		println!("sum:{}", sum );

		self.write_tcp_checksum((!sum) as u16);
	}
	pub fn arp_reply(sendermac: &Vec<u8>, targetmac: &Vec<u8>, senderip: u32, targetip: u32) -> EthIp4TcpPacket {
		let mut pkt = EthIp4TcpPacket::empty();

		pkt.data.writeu8i(0x00, targetmac);
		pkt.data.writeu8i(0x06, sendermac);
		pkt.data.writeu16be(0x0c, 0x0806); // Eth2.Type: ARP
		// Start ARP header.
		pkt.data.writeu16be(0x0e, 0x0001); // Hardware type: Ethernet
		pkt.data.writeu16be(0x10, 0x0800); // Protocol type: IP
		pkt.data.writeu8(0x12, 0x06);      // Hardware size: 6
		pkt.data.writeu8(0x13, 0x04);      // Protocol size: 4
		pkt.data.writeu16be(0x14, 0x02);   // Opcode: REPLY
		pkt.data.writeu8i(0x16, sendermac);
		pkt.data.writeu32be(0x1c, senderip);
		pkt.data.writeu8i(0x20, targetmac);
		pkt.data.writeu32be(0x26, targetip);
		pkt
	}
	pub fn read_arp_hw_type(&self) -> u16 {
		self.data.readu16be(0x0e)
	}

	pub fn read_arp_proto_type(&self) -> u16 {
		self.data.readu16be(0x10)
	}

	pub fn read_arp_opcode(&self) -> u16 {
		self.data.readu16be(0x14)
	}

	pub fn read_arp_target_ipv4(&self) -> u32 {
		self.data.readu32be(0x26)
	}

	pub fn read_arp_sender_ipv4(&self) -> u32 {
		self.data.readu32be(0x1c)
	}

	pub fn read_arp_sender_mac6(&self) -> Vec<u8> {
		self.data.readu8i(0x16, 6)
	}
	pub fn read_eth_mac_dst(&self) -> Vec<u8> {
		self.data.readu8i(0, 6)
	}
	pub fn write_eth_mac_dst(&mut self, mac: &Vec<u8>) {
		self.data.writeu8i(0, mac);
	}
	pub fn read_eth_mac_src(&self) -> Vec<u8> {
		self.data.readu8i(6, 6)
	}
	pub fn read_ip_offset(&self) -> usize {
		0x0e
	}
	pub fn read_tcp_offset(&self) -> usize {
		self.read_ip_offset() + (self.read_ip_hdrlen() as usize) * 4
	}
	pub fn write_eth_mac_src(&mut self, mac: &Vec<u8>) {
		self.data.writeu8i(6, mac);
	}
	pub fn read_eth_type(&self) -> u16 {
		self.data.readu16be(12)
	}
	pub fn write_eth_type(&mut self, typ: u16) {
		self.data.writeu16be(12, typ);
	}
	pub fn read_ip_version(&self) -> u8 {
		self.data.readu8(0x0e) >> 4
	}
	pub fn write_ip_version(&mut self, ver: u8) {
		let old = self.data.readu8(0xe);
		self.data.writeu8(0xe, (old & 0x0f) | (ver << 4));
	}
	pub fn read_ip_hdrlen(&self) -> u8 {
		self.data.readu8(14) & 0xf
	}
	pub fn write_ip_hdrlen(&mut self, hdrlentuples: u8) {
		let old = self.data.readu8(14);
		self.data.writeu8(14, (old & 0xf0) | hdrlentuples);
	}
	pub fn write_ip_dsf(&mut self, dsf: u8) {
		self.data.writeu8(15, dsf);
	}
	pub fn read_ip_total_length(&self) -> u16 {
		self.data.readu16be(16)
	}
 	pub fn write_ip_total_length(&mut self, totlen: u16) {
		self.data.writeu16be(16, totlen);
	}
	pub fn read_ip_iden(&self) -> u16 {
		self.data.readu16be(0x12)
	}
	pub fn write_ip_iden(&mut self, iden: u16) {
		self.data.writeu16be(0x12, iden);
	}
	pub fn read_ip_flags(&self) -> u8 {
		self.data.readu8(0x14) >> 5
	}
	pub fn write_ip_flags(&mut self, flags: u8) {
		let old = self.data.readu8(0x14);
		self.data.writeu8(0x14, (old & 0x1f) | (flags << 5));
	}
	pub fn read_ip_frag_offset(&self) -> u16 {
		self.data.readu16be(0x14) & 0x1fff
	}
	pub fn write_ip_frag_offset(&mut self, offset: u16) {
		let old = self.data.readu16be(0x14);
		self.data.writeu16be(0x14, (old & 0xe0) | (offset & 0x1fff));
	}
	pub fn write_ip_ttl(&mut self, ttl: u8) {
		self.data.writeu8(0x16, ttl);
	}
	pub fn read_ip_protocol(&self) -> u8 {
		self.data.readu8(0x17)
	}
	pub fn write_ip_protocol(&mut self, protocol: u8) {
		self.data.writeu8(0x17, protocol);
	}
	pub fn write_ip_checksum(&mut self, checksum: u16) {
		self.data.writeu16be(0x18, checksum);
	}
	pub fn read_ip_src(&self) -> u32 {
		self.data.readu32be(0x1a)
	}
	pub fn write_ip_src(&mut self, src: u32) {
		self.data.writeu32be(0x1a, src);
	}
	pub fn read_ip_dst(&self) -> u32 {
		self.data.readu32be(0x1e)
	}
	pub fn write_ip_dst(&mut self, dst: u32) {
		self.data.writeu32be(0x1e, dst);
	}
	pub fn read_tcp_port_src(&self) -> u16 {
		self.data.readu16be(0x22)
	}
	pub fn write_tcp_port_src(&mut self, port: u16) {
		self.data.writeu16be(0x22, port);
	}
	pub fn read_tcp_port_dst(&self) -> u16 {
		self.data.readu16be(0x24)
	}
	pub fn write_tcp_port_dst(&mut self, port: u16) {
		self.data.writeu16be(0x24, port);
	}
	pub fn read_tcp_sequence(&self) -> u32 {
		self.data.readu32be(0x26)
	}
	pub fn write_tcp_sequence(&mut self, sequence: u32) {
		self.data.writeu32be(0x26, sequence);
	}
	pub fn read_tcp_acknowledge(&self) -> u32 {
		self.data.readu32be(0x2a)
	}
	pub fn write_tcp_acknowledge(&mut self, acknowledge: u32) {
		self.data.writeu32be(0x2a, acknowledge);
	}
	pub fn read_tcp_hdrlen(&self) -> u8 {
		self.data.readu8(0x2e) >> 4
	}
	pub fn write_tcp_hdrlen(&mut self, hdrlentuples: u8) {
		let old = self.data.readu8(0x2e);
		self.data.writeu8(0x2e, (old & 0x0f) | (hdrlentuples << 4));
	}
	pub fn read_tcp_flags(&self) -> u16 {
		self.data.readu16be(0x2e) & 0xfff
	}
	pub fn write_tcp_flags(&mut self, flags: u16) {
		let old = self.data.readu16be(0x2e);
		self.data.writeu16be(0x2e, (old & 0xf000) | (flags & 0xfff));
	}
	pub fn write_tcp_window_size(&mut self, size: u16) {
		self.data.writeu16be(0x30, size);
	}
	pub fn write_tcp_checksum(&mut self, checksum: u16) {
		self.data.writeu16be(0x32, checksum);
	}
	pub fn write_tcp_urgent_pointer(&mut self, pointer: u16) {
		self.data.writeu16be(0x34, pointer);
	}
}