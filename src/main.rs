#![feature(slice_split_once)]
#![feature(slice_from_ptr_range)]
use std::{collections::HashMap, fs::File, ops::AddAssign, os::fd::AsRawFd};

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
    count: usize,
}

impl Stats {
    fn mean(self) -> f64 {
        (self.sum as f64 / self.count as f64).round() / 10.
    }
}

impl Default for Stats {
    fn default() -> Self {
        Self {
            min: i16::MAX,
            max: i16::MIN,
            sum: Default::default(),
            count: Default::default(),
        }
    }
}

impl AddAssign<i16> for Stats {
    fn add_assign(&mut self, rhs: i16) {
        self.min = self.min.min(rhs);
        self.max = self.max.max(rhs);
        self.sum += rhs as i32;
        self.count += 1;
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
    let mut out = i16::from(bytes[bytes.len() - 1] - b'0');
    out += i16::from(bytes[bytes.len() - 3] - b'0') * 10;

    match bytes[bytes.len() - 4] {
        b'0'..=b'9' => out += i16::from(bytes[bytes.len() - 4] - b'0') * 100,
        b'-' => out = -out,
        b';' => return (&bytes[..bytes.len() - 4], out),
        _ => {}
    };

    match bytes[bytes.len() - 5] {
        b'-' => (&bytes[..bytes.len() - 6], -out),
        _ => (&bytes[..bytes.len() - 5], out),
    }
}

fn main() {
    let file = File::open("./measurements.txt").unwrap();
    let file = mmap(file);
    let mut map = HashMap::<&[u8], Stats>::with_capacity(10_000);
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
        *map.entry(station).or_default() += temp;
    }

    let mut stations = map.into_iter().collect::<Vec<_>>();
    stations.sort_unstable_by(|(a, _), (b, _)| a.cmp(b));
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
}
