#[inline] fn maj(x: u8, y: u8, z: u8) -> u8 { (x & y) ^ (x & z) ^ (y & z) }
#[inline] fn ch(x: u8, y: u8, z: u8) -> u8 { (x & y) ^ ((x ^ 1) & z) }

fn ksg128(state: &[u8]) -> u8 {
    state[12] ^ state[154] ^ maj(state[235], state[61], state[193])
}

/// returns (f, ks)
fn fbk128(state: &[u8], ca: u8, cb: u8) -> (u8, u8) {
    let ks = ksg128(state);
    (
        state[0]
		    ^ (state[107] ^ 1)
		    ^ maj(state[244], state[23], state[160])
		    ^ ch(state[230], state[111], state[66])
		    ^ (ca & state[196]) ^ (cb & ks),
        ks
    )
}

/// returns (ciphertextbit, ks)
fn encrypt_state_update_128(state: &mut [u8], plaintextbit: u8, ca: u8, cb: u8) -> (u8, u8) {
    state[289] ^= state[235] ^ state[230];
    state[230] ^= state[196] ^ state[193];
    state[193] ^= state[160] ^ state[154];
    state[154] ^= state[111] ^ state[107];
    state[107] ^= state[66]  ^ state[61];
    state[61]  ^= state[23]  ^ state[0];

    let (f, ks) = fbk128(state, ca, cb);

    for j in 0..292 {
        state[j] = state[j + 1];
    }
    state[292] = f ^ plaintextbit;
    (ks ^ plaintextbit, ks)
}

/// returns (plaintextbit, ks)
fn decrypt_state_update_128(state: &mut [u8], ciphertextbit: u8, ca: u8, cb: u8) -> (u8, u8) {
    state[289] ^= state[235] ^ state[230];
    state[230] ^= state[196] ^ state[193];
    state[193] ^= state[160] ^ state[154];
    state[154] ^= state[111] ^ state[107];
    state[107] ^= state[66]  ^ state[61];
    state[61]  ^= state[23]  ^ state[0];

    let (f, ks) = fbk128(state, ca, cb);

    for j in 0..292 {
        state[j] = state[j + 1];
    }
    let plaintextbit = ks ^ ciphertextbit;
    state[292] = f ^ plaintextbit;
    (plaintextbit, ks)
}

#[derive(Copy)]
pub struct Acorn128 {
    state: [u8; 293]
}

impl Clone for Acorn128 { fn clone(&self) -> Acorn128 { *self } }

impl Acorn128 {
    pub fn init(key: &[u8], iv: &[u8]) -> Acorn128 {
        let mut m = [0; 1536];
        let mut acorn = Acorn128 { state: [0; 293] };

        for i in 0..127 {
            m[i] = key[i / 8] >> (i & 7) & 1;
            m[i + 128] = iv[i / 8] >> (i & 7) & 1;
        }
        m[256] = 1;

        for i in 0..1536 {
            encrypt_state_update_128(&mut acorn.state, m[i], 1, 1);
        }

        acorn
    }

    /// returns (ciphertextbyte, ksbyte)
    pub fn enc_onebyte(&mut self, plaintextbyte: u8, cabyte: u8, cbbyte: u8) -> (u8, u8) {
        let mut ciphertextbyte = 0;
        let mut ksbyte = 0;

        for i in 0..8 {
            let ca = (cabyte >> i) & 1;
            let cb = (cbbyte >> i) & 1;
            let plaintextbit = (plaintextbyte >> i) & 1;
            let (ctb, kst) = encrypt_state_update_128(&mut self.state, plaintextbit, ca, cb);
            ciphertextbyte |= ctb << i;
            ksbyte |= kst << i;
        }

        (ciphertextbyte, ksbyte)
    }

    /// returns plaintextbyte
    pub fn dec_onebyte(&mut self, ciphertextbyte: u8, cabyte: u8, cbbyte: u8) -> u8 {
        let mut plaintextbyte = 0;

        for i in 0..8 {
            let ca = (cabyte >> i) & 1;
            let cb = (cbbyte >> i) & 1;
            let ciphertextbit = (ciphertextbyte >> i) & 1;
            let (ptb, _) = decrypt_state_update_128(&mut self.state, ciphertextbit, ca, cb);
            plaintextbyte |= ptb << i;
        }

        plaintextbyte
    }

    pub fn tag_generation(mut self) -> [u8; 16] {
        let mut output = [0; 16];

        for i in 0..(512 / 8) {
            let (_, ksbyte) = self.enc_onebyte(0, 0xff, 0xff);
            if i >= (512 / 8 -16) {
                output[i - (512 / 8 - 16)] = ksbyte;
            }
        }

        output
    }
}
