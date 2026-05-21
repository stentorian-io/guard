//! Thread-local fd classification bitmap for write()/writev() interpose.
//!
//! On first write to an unknown fd, we call getsockopt(SO_TYPE) via raw
//! syscall to classify the fd as socket or non-socket. The result is cached
//! in a thread-local bitmap so subsequent writes to the same fd pay zero
//! overhead beyond a bitmap lookup.
//!
//! The bitmap tracks fds 0..MAX_FD. Fds above MAX_FD are classified on
//! every call (no caching) — this is acceptable because high-numbered fds
//! are rare in practice.

const MAX_FD: usize = 1024;
const BITMAP_WORDS: usize = MAX_FD / 64;

struct FdBitmap {
    is_socket: [u64; BITMAP_WORDS],
    classified: [u64; BITMAP_WORDS],
}

impl FdBitmap {
    const fn new() -> Self {
        Self {
            is_socket: [0; BITMAP_WORDS],
            classified: [0; BITMAP_WORDS],
        }
    }

    #[inline(always)]
    fn is_classified(&self, fd: usize) -> bool {
        let word = fd / 64;
        let bit = fd % 64;
        (self.classified[word] >> bit) & 1 == 1
    }

    #[inline(always)]
    fn is_socket(&self, fd: usize) -> bool {
        let word = fd / 64;
        let bit = fd % 64;
        (self.is_socket[word] >> bit) & 1 == 1
    }

    #[inline(always)]
    fn set(&mut self, fd: usize, socket: bool) {
        let word = fd / 64;
        let bit = fd % 64;
        self.classified[word] |= 1u64 << bit;
        if socket {
            self.is_socket[word] |= 1u64 << bit;
        } else {
            self.is_socket[word] &= !(1u64 << bit);
        }
    }

    #[inline(always)]
    fn invalidate(&mut self, fd: usize) {
        let word = fd / 64;
        let bit = fd % 64;
        self.classified[word] &= !(1u64 << bit);
        self.is_socket[word] &= !(1u64 << bit);
    }
}

// UnsafeCell wrapper for thread-local — no Sync needed.
struct FdBitmapCell(core::cell::UnsafeCell<FdBitmap>);
unsafe impl Sync for FdBitmapCell {}

thread_local! {
    static FD_MAP: FdBitmapCell = const { FdBitmapCell(core::cell::UnsafeCell::new(FdBitmap::new())) };
}

/// Classify an fd as socket or non-socket. Returns true if the fd is a
/// connected TCP socket (the only type where write() can send data to a
/// remote host that was already permitted at connect time).
///
/// Classification uses getsockopt(SO_TYPE) via raw syscall to avoid
/// recursion through the interpose chain.
#[inline]
pub fn is_connected_socket(fd: i32) -> bool {
    if fd < 0 {
        return false;
    }
    let ufd = fd as usize;

    if ufd < MAX_FD {
        let result = FD_MAP.with(|cell| {
            let map = unsafe { &*cell.0.get() };
            if map.is_classified(ufd) {
                return Some(map.is_socket(ufd));
            }
            None
        });
        if let Some(is_sock) = result {
            return is_sock;
        }
    }

    // Cache miss or fd >= MAX_FD — classify now.
    let sock = classify_fd(fd);

    if ufd < MAX_FD {
        FD_MAP.with(|cell| {
            let map = unsafe { &mut *cell.0.get() };
            map.set(ufd, sock);
        });
    }

    sock
}

/// Invalidate the classification for an fd (call on close).
#[inline]
pub fn invalidate_fd(fd: i32) {
    if fd < 0 {
        return;
    }
    let ufd = fd as usize;
    if ufd < MAX_FD {
        FD_MAP.with(|cell| {
            let map = unsafe { &mut *cell.0.get() };
            map.invalidate(ufd);
        });
    }
}

/// Probe an fd with getsockopt(SOL_SOCKET, SO_TYPE) via raw syscall.
/// Returns true if the fd is a socket (any type — SOCK_STREAM, SOCK_DGRAM, etc.).
fn classify_fd(fd: i32) -> bool {
    let mut sock_type: libc::c_int = 0;
    let mut optlen: libc::socklen_t = core::mem::size_of::<libc::c_int>() as libc::socklen_t;
    let ret = unsafe {
        crate::raw_syscall::raw_getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_TYPE,
            &mut sock_type as *mut _ as *mut core::ffi::c_void,
            &mut optlen,
        )
    };
    ret == 0
}
