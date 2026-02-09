#![feature(slice_split_once)]
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
    }
}

#[derive(Clone, Copy)]
struct Stats {
    min: f64,
    max: f64,
    sum: f64,
    count: usize,
}

impl Stats {
    fn mean(self) -> f64 {
        self.sum / self.count as f64
    }
}

impl Default for Stats {
    fn default() -> Self {
        Self {
            min: f64::MAX,
            max: f64::MIN,
            sum: Default::default(),
            count: Default::default(),
        }
    }
}

impl AddAssign<f64> for Stats {
    fn add_assign(&mut self, rhs: f64) {
        self.min = self.min.min(rhs);
        self.max = self.max.max(rhs);
        self.sum += rhs;
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

fn main() {
    let file = File::open("./measurements.txt").unwrap();
    let file = mmap(file);
    let mut map = HashMap::<&[u8], Stats>::with_capacity(10_000);
    for line in file.split(|b| *b == b'\n') {
        if line.is_empty() {
            break;
        }
        let (station, temp) = line.split_once(|b| *b == b';').unwrap();
        let temp: f64 = unsafe { std::str::from_utf8_unchecked(temp) }
            .parse()
            .unwrap();
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
        print!("{}={}/{}/{}", station, stats.min, stats.mean(), stats.max);
    }
    print!("}}");
}
