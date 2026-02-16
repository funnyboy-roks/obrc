#![feature(slice_split_once)]
#![feature(slice_from_ptr_range)]
#![feature(portable_simd)]
#![feature(hasher_prefixfree_extras)]
#![allow(clippy::missing_transmute_annotations)]

use std::{
    collections::{BTreeMap, HashMap},
    fs::File,
    hash::{BuildHasherDefault, Hasher},
    ops::AddAssign,
    os::fd::AsRawFd,
    simd::{
        Mask, Select,
        cmp::SimdPartialEq,
        i16x8,
        num::{SimdInt, SimdUint},
        u8x8,
    },
};

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

#[derive(Clone, Copy)]
struct Stats {
    min: i16,
    max: i16,
    sum: i32,
    count: u32,
}

impl AddAssign for Stats {
    fn add_assign(&mut self, rhs: Self) {
        self.min = self.min.min(rhs.min);
        self.max = self.max.max(rhs.max);
        self.sum += rhs.sum;
        self.count += rhs.count;
    }
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

#[inline(never)]
fn parse_temp(bytes: &[u8]) -> (&[u8], i16) {
    const SEMI_U8: u8x8 = u8x8::splat(b';');
    const SEMI_I16: i16x8 = i16x8::splat(b';' as i16);
    const NEG: i16x8 = i16x8::splat(b'-' as i16);
    const ZERO_CHAR: i16x8 = i16x8::splat(b'0' as _);
    const TENS: i16x8 = i16x8::from_array([0, 0, 0, 0, 100, 10, 0, 1]);
    const ZERO: i16x8 = const { i16x8::splat(0) };

    // I wish this could be const...
    let enable = Mask::from_bitmask(0b1111_1000);
    // SAFETY: This is not strictly safe. ptr[0], ptr[1], and ptr[2] are not necessarily valid with
    // the requirements set by the 1brc.
    let ptr = unsafe { bytes.as_ptr().add(bytes.len() - 8) };
    // SAFETY: This does not invalidate the safety of `ptr` as the `enable` mask only uses the
    // last 5 items and does not dereference ptr[0], ptr[1], or ptr[2].
    let line: i16x8 = unsafe { u8x8::load_select_ptr(ptr, enable, SEMI_U8) }.cast();

    let semi = line.simd_eq(SEMI_I16);
    let neg = line.simd_eq(NEG);

    let line = line - ZERO_CHAR;
    let line = (!semi & !neg).select(line, ZERO) * TENS;
    let temp = line.reduce_sum() * (-i16::from(neg.any()) | 1);

    let tz = semi.reverse().to_bitmask().trailing_zeros();
    debug_assert!(tz <= 8);
    let s = tz as usize + 1;

    let station = unsafe { bytes.get_unchecked(..bytes.len() - s) };

    (station, temp)
}

#[derive(Default)]
struct FxHasherIsh(u64);

impl Hasher for FxHasherIsh {
    fn finish(&self) -> u64 {
        self.0.rotate_left(26)
    }

    fn write_length_prefix(&mut self, _len: usize) {}

    fn write(&mut self, bytes: &[u8]) {
        const HASH_K: u64 = 0xf135_7aea_2e62_a9c5;
        const HASH_SEED: u64 = 0x1319_8a2e_0370_7344;

        let len = bytes.len();

        let acc = HASH_SEED
            ^ if len < 4 {
                let lo = bytes[0];
                let mid = bytes[len / 2];
                let hi = bytes[len - 1];
                (lo as u64) | ((mid as u64) << 8) | ((hi as u64) << 16)
            } else {
                u32::from_le_bytes(bytes[0..4].try_into().unwrap()) as u64
            };

        self.0 = self.0.wrapping_add(acc).wrapping_mul(HASH_K);
    }
}

#[inline(never)]
fn process_chunk(chunk: &[u8]) -> impl IntoIterator<Item = (&[u8], Stats)> {
    let mut map = HashMap::<&[u8], Stats, _>::with_capacity_and_hasher(
        10_000,
        BuildHasherDefault::<FxHasherIsh>::new(),
    );
    let mut rest = chunk;
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
    map
}

fn print_map(stations: BTreeMap<&[u8], Stats>) {
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

fn main() {
    let file = File::open("./measurements.txt").unwrap();
    let file = mmap(file);

    let nproc = std::thread::available_parallelism().unwrap().get();
    // NOTE: nproc*2 here is a little weird as obviously we can't be running more than nproc
    // threads at once, yet using nproc*2 gives about a 10% speed up.  Working theory is that it
    // helps when some threads are waiting on IO, but I'm not sure how that works with mmap.
    let nproc = nproc * 2;

    let mut threads = Vec::with_capacity(nproc);
    let mut rest = file;
    while !rest.is_empty() {
        let chunk_len = file.len() / nproc;
        let i = rest[chunk_len.min(rest.len())..]
            .iter()
            .position(|b| *b == b'\n')
            .map(|i| i + chunk_len)
            .unwrap_or(rest.len() - 1);
        let chunk = &rest[..=i];
        rest = &rest[i + 1..];
        threads.push(std::thread::spawn(move || process_chunk(chunk)));
    }

    let mut stations = BTreeMap::<&[u8], Stats>::new();
    for thread in threads {
        let map = thread.join().unwrap();
        for (k, v) in map {
            *stations.entry(k).or_default() += v;
        }
    }

    print_map(stations);
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
}
