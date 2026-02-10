#![feature(slice_split_once)]
#![feature(slice_from_ptr_range)]
#![allow(clippy::missing_transmute_annotations)]
use std::{collections::HashMap, fs::File, hash::BuildHasherDefault, os::fd::AsRawFd};

mod libc {
    use std::ffi::{c_int, c_void};

    pub const PROT_READ: c_int = 1;
    pub const MAP_PRIVATE: c_int = 0x0002;
    pub const MAP_FAILED: *mut c_void = !0 as *mut c_void;
    pub const MADV_SEQUENTIAL: c_int = 2;

    unsafe extern "C" {
        pub fn mmap(
            addr: *mut c_void,
            len: usize,
            prot: c_int,
            flags: c_int,
            fd: c_int,
            offset: i64,
        ) -> *mut c_void;

        pub fn madvise(addr: *mut c_void, len: usize, advice: c_int) -> c_int;

        pub fn memchr(cx: *const c_void, c: c_int, n: usize) -> *mut c_void;
    }
}

mod ahash {
    use std::hash::Hasher;

    #[derive(Debug, Clone)]
    pub struct AHasher {
        enc: u128,
        sum: u128,
        key: u128,
    }

    impl Default for AHasher {
        fn default() -> Self {
            const PI_U64X4: [u64; 4] = [
                0x243f_6a88_85a3_08d3,
                0x1319_8a2e_0370_7344,
                0xa409_3822_299f_31d0,
                0x082e_fa98_ec4e_6c89,
            ];

            const {
                let [k0, k1, k2, k3] = PI_U64X4;

                Self::from_random_state([k0, k1, k2, k3])
            }
            // hasher.write_usize(0xe81127a606887fab);
            // let mix = |l: u64, r: u64| {
            //     let mut h = hasher.clone();
            //     h.write_u64(l);
            //     h.write_u64(r);
            //     h.finish()
            // };
            // Self::from_random_state([
            //     mix(PI2[0], PI2[2]),
            //     mix(PI2[1], PI2[3]),
            //     mix(PI2[2], PI2[1]),
            //     mix(PI2[3], PI2[0]),
            // ])
        }
    }

    impl AHasher {
        #[inline]
        const fn from_random_state(keys: [u64; 4]) -> Self {
            // SAFETY: these types are the same size and they have the same memory layout
            let keys: [u128; 2] = unsafe { std::mem::transmute(keys) };
            Self {
                enc: keys[0],
                sum: keys[1],
                key: keys[0] ^ keys[1],
            }
        }

        #[inline(always)]
        fn hash_in(&mut self, new_value: u128) {
            self.enc = aesdec(self.enc, new_value);
            self.sum = shuffle_and_add(self.sum, new_value);
        }

        #[inline(always)]
        fn hash_in_2(&mut self, v1: u128, v2: u128) {
            self.enc = aesdec(self.enc, v1);
            self.sum = shuffle_and_add(self.sum, v1);
            self.enc = aesdec(self.enc, v2);
            self.sum = shuffle_and_add(self.sum, v2);
        }

        #[inline(always)]
        fn add_in_length(enc: &mut u128, len: u64) {
            use core::arch::x86_64::*;

            unsafe {
                let enc = enc as *mut u128;
                let len = _mm_cvtsi64_si128(len as i64);
                let data = _mm_loadu_si128(enc.cast());
                let sum = _mm_add_epi64(data, len);
                _mm_storeu_si128(enc.cast(), sum);
            }
        }

        #[inline(always)]
        fn read_small(data: &[u8]) -> [u64; 2] {
            debug_assert!(data.len() <= 8);
            if data.len() >= 2 {
                if data.len() >= 4 {
                    //len 4-8
                    let head = unsafe { data.as_chunks_unchecked::<4>() }[0];
                    let head: u32 = u32::from_ne_bytes(head);

                    let (_, tail) = data.as_rchunks::<4>();
                    let tail = tail[tail.len() - 1];
                    let tail: u32 = u32::from_ne_bytes(tail);
                    [head.into(), tail.into()]
                } else {
                    let head = unsafe { data.as_chunks_unchecked::<2>() }[0];
                    let head: u16 = u16::from_ne_bytes(head);

                    let (_, tail) = data.as_rchunks::<2>();
                    let tail = tail[tail.len() - 1];
                    let tail: u16 = u16::from_ne_bytes(tail);
                    [head.into(), tail.into()]
                }
            } else {
                if data.len() > 0 {
                    [data[0] as u64, data[0] as u64]
                } else {
                    [0, 0]
                }
            }
        }
    }

    #[inline(always)]
    fn aesenc(value: u128, xor: u128) -> u128 {
        #[cfg(target_arch = "x86_64")]
        use core::arch::x86_64::*;
        unsafe {
            let value = std::mem::transmute(value);
            std::mem::transmute(_mm_aesenc_si128(value, std::mem::transmute(xor)))
        }
    }

    #[inline(always)]
    pub(crate) fn aesdec(value: u128, xor: u128) -> u128 {
        #[cfg(target_arch = "x86_64")]
        use core::arch::x86_64::*;
        unsafe {
            let value = std::mem::transmute(value);
            std::mem::transmute(_mm_aesdec_si128(value, std::mem::transmute(xor)))
        }
    }

    #[inline(always)]
    fn add_by_64s(a: u128, b: u128) -> u128 {
        unsafe {
            #[cfg(target_arch = "x86_64")]
            use core::arch::x86_64::*;
            std::mem::transmute(_mm_add_epi64(
                std::mem::transmute(a),
                std::mem::transmute(b),
            ))
        }
    }

    #[inline(always)]
    fn shuffle_and_add(base: u128, to_add: u128) -> u128 {
        let shuffled = base.swap_bytes();
        add_by_64s(shuffled, to_add)
    }

    /// Provides [Hasher] methods to hash all of the primitive types.
    ///
    /// [Hasher]: core::hash::Hasher
    impl Hasher for AHasher {
        #[inline]
        fn write_usize(&mut self, i: usize) {
            self.write_u64(i as u64);
        }

        #[inline]
        fn write_u64(&mut self, i: u64) {
            self.write_u128(i as u128);
        }

        #[inline]
        #[allow(clippy::collapsible_if)]
        fn write(&mut self, input: &[u8]) {
            let mut data = input;
            let length = data.len();
            Self::add_in_length(&mut self.enc, length as u64);

            //A 'binary search' on sizes reduces the number of comparisons.
            if data.len() <= 16 {
                let value = Self::read_small(data);
                self.hash_in(unsafe { std::mem::transmute(value) });
            } else {
                if data.len() > 32 {
                    if data.len() > 64 {
                        let (_, tail) = data.as_rchunks::<64>();
                        let tail = tail[tail.len() - 1];
                        let tail: [u128; 4] = unsafe { std::mem::transmute(tail) };
                        let mut current: [u128; 4] = [self.key; 4];
                        current[0] = aesenc(current[0], tail[0]);
                        current[1] = aesdec(current[1], tail[1]);
                        current[2] = aesenc(current[2], tail[2]);
                        current[3] = aesdec(current[3], tail[3]);
                        let mut sum: [u128; 2] = [self.key, !self.key];
                        sum[0] = add_by_64s(sum[0], tail[0]);
                        sum[1] = add_by_64s(sum[1], tail[1]);
                        sum[0] = shuffle_and_add(sum[0], tail[2]);
                        sum[1] = shuffle_and_add(sum[1], tail[3]);
                        while data.len() > 64 {
                            // SAFETY: len > 64 and we read a single chunk
                            let head = unsafe { data.as_chunks_unchecked::<64>() }[0];
                            let blocks: [u128; 4] = unsafe { std::mem::transmute(head) };
                            let rest = &data[64..];
                            current[0] = aesdec(current[0], blocks[0]);
                            current[1] = aesdec(current[1], blocks[1]);
                            current[2] = aesdec(current[2], blocks[2]);
                            current[3] = aesdec(current[3], blocks[3]);
                            sum[0] = shuffle_and_add(sum[0], blocks[0]);
                            sum[1] = shuffle_and_add(sum[1], blocks[1]);
                            sum[0] = shuffle_and_add(sum[0], blocks[2]);
                            sum[1] = shuffle_and_add(sum[1], blocks[3]);
                            data = rest;
                        }
                        self.hash_in_2(current[0], current[1]);
                        self.hash_in_2(current[2], current[3]);
                        self.hash_in_2(sum[0], sum[1]);
                    } else {
                        //len 33-64
                        let head = unsafe { data.as_chunks_unchecked::<32>() }[0];
                        let head: [u128; 2] = unsafe { std::mem::transmute(head) };

                        let (_, tail) = data.as_rchunks::<32>();
                        let tail = tail[tail.len() - 1];
                        let tail: [u128; 2] = unsafe { std::mem::transmute(tail) };

                        self.hash_in_2(head[0], head[1]);
                        self.hash_in_2(tail[0], tail[1]);
                    }
                } else {
                    if data.len() > 16 {
                        //len 17-32
                        let head = unsafe { data.as_chunks_unchecked::<16>() }[0];
                        let head: u128 = u128::from_ne_bytes(head);

                        let (_, tail) = data.as_rchunks::<16>();
                        let tail = tail[tail.len() - 1];
                        let tail: u128 = u128::from_ne_bytes(tail);
                        self.hash_in_2(head, tail);
                    } else {
                        let head = unsafe { data.as_chunks_unchecked::<8>() }[0];
                        let head: u64 = u64::from_ne_bytes(head);

                        let (_, tail) = data.as_rchunks::<8>();
                        let tail = tail[tail.len() - 1];
                        let tail: u64 = u64::from_ne_bytes(tail);
                        //len 9-16
                        let value: [u64; 2] = [head, tail];
                        self.hash_in(unsafe { std::mem::transmute(value) });
                    }
                }
            }
        }
        #[inline]
        fn finish(&self) -> u64 {
            let combined = aesenc(self.sum, self.enc);
            let result: [u64; 2] =
                unsafe { std::mem::transmute(aesdec(aesdec(combined, self.key), combined)) };
            result[0]
        }
    }
}

#[derive(Clone, Copy)]
struct Stats {
    min: i16,
    max: i16,
    sum: i32,
    count: u32,
}

impl Stats {
    fn mean(self) -> f64 {
        (self.sum as f64 / self.count as f64).round() / 10.
    }
}

impl Default for Stats {
    fn default() -> Self {
        const {
            Self {
                min: i16::MAX,
                max: i16::MIN,
                sum: 0,
                count: 0,
            }
        }
    }
}

fn mmap(file: File) -> &'static [u8] {
    let len = file.metadata().unwrap().len() as usize;
    // SAFETY: I said so.
    let ptr = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            len,
            libc::PROT_READ,
            libc::MAP_PRIVATE,
            file.as_raw_fd(),
            0,
        )
    };
    assert_ne!(ptr, libc::MAP_FAILED);

    // SAFETY: the ptr is from mmap
    let ret = unsafe { libc::madvise(ptr, len, libc::MADV_SEQUENTIAL) };
    assert_ne!(ret, -1);

    // SAFETY: mmap returns a valid pointer
    unsafe { std::slice::from_raw_parts(ptr as *const u8, len) }
}

fn parse_temp(bytes: &[u8]) -> (&[u8], i16) {
    //   ;0.0
    //  ;-0.0
    //  ;00.0
    // ;-00.0
    let get = |offset: usize| unsafe { bytes.get_unchecked(bytes.len() - offset) };
    let slice = |offset: usize| unsafe { bytes.get_unchecked(..bytes.len() - offset) };
    // 0.0
    //   ^
    let mut out = i16::from(get(1) - b'0');

    // skip '.'

    // 0.0
    // ^
    out += i16::from(get(3) - b'0') * 10;

    match get(4) {
        b @ b'0'..=b'9' => out += i16::from(b - b'0') * 100,
        b'-' => out = -out,
        b';' => return (slice(4), out),
        _ => {}
    };

    let neg = *get(5) == b'-';
    (
        slice(5 + usize::from(neg)),
        out * ((1 - i16::from(neg)) * 2 - 1),
    )
}

fn main() {
    let file = File::open("./measurements.txt").unwrap();
    let file = mmap(file);
    let mut map = HashMap::<&[u8], Stats, _>::with_capacity_and_hasher(
        10_000,
        BuildHasherDefault::<ahash::AHasher>::new(),
    );
    let mut rest = file;
    loop {
        let line = unsafe {
            if rest.len() < 3 {
                break;
            }
            let nl_ptr = libc::memchr(rest.as_ptr().cast(), i32::from(b'\n'), rest.len());
            let line = std::slice::from_ptr_range(rest.as_ptr()..nl_ptr.cast_const().cast());

            rest = std::slice::from_ptr_range(
                nl_ptr.add(1).cast_const().cast()..rest.as_ptr_range().end,
            );
            line
        };
        if line.is_empty() {
            break;
        }
        let (station, temp) = parse_temp(line);
        let stats = map.entry(station).or_default();
        stats.min = stats.min.min(temp);
        stats.max = stats.max.max(temp);
        stats.sum += temp as i32;
        stats.count += 1;
    }

    let mut stations = map.into_iter().collect::<Vec<_>>();
    stations.sort_unstable_by(|(a, _), (b, _)| a.as_ref().cmp(b.as_ref()));
    print!("{{");
    for (i, (station, stats)) in stations.into_iter().enumerate() {
        if i > 0 {
            print!(", ");
        }
        let station = unsafe { std::str::from_utf8_unchecked(station) };
        print!(
            "{}={}.{}/{:.1}/{}.{}",
            station,
            stats.min / 10,
            (stats.min % 10).unsigned_abs(),
            stats.mean(),
            stats.max / 10,
            (stats.max % 10).unsigned_abs(),
        );
    }
    print!("}}");
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn parse_temperature() {
        assert_eq!(parse_temp(b"abc;42.1"), (&b"abc"[..], 421));
        assert_eq!(parse_temp(b"abc;-42.1"), (&b"abc"[..], -421));
        assert_eq!(parse_temp(b"abc;9.1"), (&b"abc"[..], 91));
        assert_eq!(parse_temp(b"abc;-9.1"), (&b"abc"[..], -91));
        assert_eq!(parse_temp(b"abc;0.1"), (&b"abc"[..], 1));
        assert_eq!(parse_temp(b"abc;-0.1"), (&b"abc"[..], -1));
    }

    #[test]
    fn smol_str() {
        macro_rules! ss_test {
            ($slice: expr) => {
                assert_eq!(SmolStr::from(&$slice[..]).as_ref(), $slice);
            };
        }

        ss_test!([0, 1, 2, 3]);
        ss_test!([
            0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20
        ]);
        ss_test!([0]);
        ss_test!([]);
        ss_test!(b"hello world");
    }
}
