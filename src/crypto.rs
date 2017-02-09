pub struct CryptoContext {
    y: u32,
    z: u32,
    key: Vec<u8>, // Initial key value
    workbuf: Vec<u8>,
}

impl CryptoContext {
    pub fn new(key: &str) -> CryptoContext {
        let mut vec: Vec<u8> = Vec::with_capacity(key.len());
        vec.extend_from_slice(key.as_bytes());
        CryptoContext {
            y: 0,
            z: 0,
            workbuf: vec.to_vec(),
            key: vec,
        }
    }

    pub fn reset(&mut self) {
        self.y = 0;
        self.z = 0;
        self.workbuf.copy_from_slice(&self.key);
    }

    fn update_yz(&mut self, index: usize, ks_val: u32) {
        let new_y = ((ks_val & 0xffff) * 0x015a) & 0xffff;
        let mut new_z = index as u32 + (self.z & 0xffff);
        new_z &= 0xffff;

        if new_z != 0 {
            new_z = (new_z & 0xffff) * 0x4e35;
            new_z &= 0xffff;
        };
        new_z += new_y & 0xffff;
        new_z += self.y & 0xffff;

        self.y = new_y;
        self.z = new_z;
    }

    fn assemble(&mut self) -> u16 {
        let hwords = self.workbuf.len() >> 1;
        let mut coded_result = 0u32;
        let mut prev_ks_val = 0u32;

        for round in 0..hwords {
            let keyhword = {
                // Extract low and high bytes and sign-extend them
                let keybyte0 = {
                    (self.workbuf[round << 1] as i8) as i32
                };
                let keybyte1 = {
                    (self.workbuf[(round << 1) + 1] as i8) as i32
                };
                ((keybyte0 << 8) + keybyte1) as u32
            };
            let mut ks_val = prev_ks_val ^ keyhword;
            self.update_yz(round, ks_val);
            ks_val = ((ks_val & 0xffff) * 0x4e35) + 1;
            ks_val &= 0xffff;
            coded_result = coded_result ^ (ks_val ^ self.z);
            prev_ks_val = ks_val;
        }
        coded_result as u16
    }

    pub fn encrypt(&mut self, inbyte: u8) -> u8 {
        let assembled = self.assemble();
        let assembled_byte = ((assembled >> 8) ^ assembled) as u8;

        // Scramble the key with data byte
        for idx in 0..self.workbuf.len() {
            self.workbuf[idx] ^= inbyte;
        }

        inbyte ^ assembled_byte
    }

    pub fn decrypt(&mut self, inbyte: u8) -> u8 {
        let assembled = self.assemble();
        let assembled_byte = ((assembled >> 8) ^ assembled) as u8;
        let outbyte = inbyte ^ assembled_byte;

        // Scramble the key with data byte
        for idx in 0..self.workbuf.len() {
            self.workbuf[idx] ^= outbyte;
        }

        outbyte
    }
}

#[cfg(test)]
mod tests {
    use super::CryptoContext;

    // 32 bytes from /dev/urandom
    const SAMPLE1_PLAINTEXT: [u8; 0x20] = [
        0x5a, 0x90, 0x77, 0x24, 0xc7, 0x14, 0x37, 0xeb, 0x52, 0x5f,
        0x72, 0x60, 0xbc, 0x7d, 0xb1, 0x95, 0x36, 0x99, 0x5e, 0x09,
        0xe5, 0x49, 0x06, 0x5b, 0xdb, 0x3a, 0xa3, 0xd4, 0x17, 0x9a,
        0xd4, 0x4a,
    ];
    const SAMPLE1_CIPHERTEXT: [u8; 0x20] = [
        0x3f, 0xb9, 0xcf, 0xf6, 0xd1, 0x80, 0xc0, 0x4c, 0xf7, 0x40,
        0xc0, 0x74, 0x98, 0xbd, 0x7e, 0x3f, 0x8f, 0xc6, 0x98, 0x92,
        0x55, 0xc0, 0x09, 0xd9, 0xa7, 0x8b, 0x10, 0x90, 0xfe, 0x66,
        0xc5, 0xcf
    ];
    const SAMPLE1_KEY: &'static str = "TestKey";

    #[test]
    fn instantiate() {
        CryptoContext::new("blablabla");
    }

    #[test]
    fn reset() {
        let mut ctx: CryptoContext = CryptoContext::new("TrucMachin");
        ctx.y = 30;
        ctx.z = 0x4809;
        ctx.workbuf[0] = 0xff;
        ctx.reset();
        assert_eq!(ctx.y, 0);
        assert_eq!(ctx.z, 0);
        assert_eq!(ctx.workbuf[0], ctx.key[0]);
    }

    #[test]
    fn key_does_not_include_null_terminator() {
        let ctx: CryptoContext = CryptoContext::new("TrucMachin");
        assert_eq!(ctx.key.len(), 10);
    }

    #[test]
    fn encrypt_sample1() {
        let mut ctx: CryptoContext = CryptoContext::new(SAMPLE1_KEY);
        let mut encbyte;
        for i in 0..(SAMPLE1_PLAINTEXT.len()) {
            encbyte = ctx.encrypt(SAMPLE1_PLAINTEXT[i]);
            assert_eq!(encbyte, SAMPLE1_CIPHERTEXT[i]);
            println!("Encrypted byte {}", i);
        }
    }

    #[test]
    fn decrypt_sample1() {
        let mut ctx: CryptoContext = CryptoContext::new(SAMPLE1_KEY);
        let mut decbyte;
        for i in 0..(SAMPLE1_CIPHERTEXT.len()) {
            decbyte = ctx.decrypt(SAMPLE1_CIPHERTEXT[i]);
            assert_eq!(decbyte, SAMPLE1_PLAINTEXT[i]);
            println!("Decrypted byte {}", i);
        }
    }

    #[test]
    fn encrypt_and_decrypt() {
        use std::str;
        let orig = "Il était un petit navire, il était un petit navire \
            qui n'avait ja-ja-jamais navigué, qui n'avait ja-ja-jamais \
            navigué. Oh hé, oh hé !";
        let enc = {
            let mut ectx: CryptoContext = CryptoContext::new("SomeSecret");
            let mut enc: Vec<u8> = Vec::with_capacity(orig.bytes().len());
            for b in orig.bytes() {
                enc.push(ectx.encrypt(b));
            };
            enc
        };
        let dec = {
            let mut dctx: CryptoContext = CryptoContext::new("SomeSecret");
            let mut dec: Vec<u8> = Vec::with_capacity(enc.len());
            for b in enc {
                dec.push(dctx.decrypt(b));
            }
            dec
        };
        assert_eq!(&dec, &orig.as_bytes());
    }
}

