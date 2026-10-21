//! Randomness for token masks.
//!
//! Every issued token is masked with fresh random bytes (the pad), so the same
//! session token looks different on every page and a compression side channel
//! (BREACH) cannot recover it. The pad travels with the token, so it is not
//! secret once sent, but it must be **unpredictable** before the response is
//! built: with a known pad, the masked half of the token is a fixed string
//! again. Pads therefore come from a cryptographically secure generator.

use crate::error::Error;

/// A source of cryptographically secure random bytes for token pads.
///
/// Tier 1 and Tier 2 calls use [`OsPads`]. Implement this trait to supply
/// randomness on targets without `std` (a hardware generator, an OS call), and
/// pass it to [`Csrf::issue_at`](crate::Csrf::issue_at).
///
/// An implementation must fill `out` completely from a CSPRNG, or return
/// [`Error::Random`]; never a partial or predictable fill.
///
/// ```
/// use csrf_sec::{Error, PadSource};
///
/// struct Hardware;
///
/// impl PadSource for Hardware {
///     fn fill(&mut self, out: &mut [u8]) -> Result<(), Error> {
///         // read the platform's CSPRNG into `out`
/// #       out.iter_mut().enumerate().for_each(|(i, b)| *b = i as u8);
///         Ok(())
///     }
/// }
/// ```
pub trait PadSource {
    /// Fill `out` with cryptographically secure random bytes.
    ///
    /// # Errors
    ///
    /// [`Error::Random`] when the generator cannot produce bytes. The caller
    /// then issues no token.
    fn fill(&mut self, out: &mut [u8]) -> Result<(), Error>;
}

impl<P: PadSource + ?Sized> PadSource for &mut P {
    #[inline]
    fn fill(&mut self, out: &mut [u8]) -> Result<(), Error> {
        (**self).fill(out)
    }
}

#[cfg(feature = "std")]
pub use os::OsPads;

#[cfg(feature = "std")]
mod os {
    use core::cell::RefCell;

    use crypt_io::Zeroizing;

    use super::PadSource;
    use crate::error::Error;

    /// Bytes fetched from the OS per refill: about 90 session-token pads for
    /// one system call.
    const POOL_LEN: usize = 2048;

    /// The operating system's CSPRNG, read through a small per-thread buffer.
    ///
    /// Each thread keeps a buffer of random bytes refilled in bulk from the OS
    /// generator (`getrandom` on Linux, `getentropy` on macOS, `ProcessPrng` /
    /// `BCryptGenRandom` on Windows, through `mod-rand`), so masking a token
    /// costs a copy instead of a system call. The buffer takes no lock, is
    /// never shared between threads, and is wiped when the thread exits.
    ///
    /// After a `fork` without `exec`, parent and child hold the same unused
    /// buffer, so up to one buffer of pads could repeat across the two
    /// processes. That does not weaken BREACH protection (pads still differ on
    /// every response within each process, and no attacker sees both
    /// processes' responses for one victim), but long-lived forked workers
    /// that want separate streams can call [`OsPads::refill`] after the fork.
    ///
    /// ```
    /// use csrf_sec::{OsPads, PadSource};
    ///
    /// let mut pad = [0u8; 22];
    /// OsPads.fill(&mut pad)?;
    /// # Ok::<(), csrf_sec::Error>(())
    /// ```
    #[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
    pub struct OsPads;

    struct Pool {
        buf: Zeroizing<[u8; POOL_LEN]>,
        pos: usize,
    }

    impl Pool {
        fn new() -> Self {
            Self {
                buf: Zeroizing::new([0u8; POOL_LEN]),
                pos: POOL_LEN, // empty: the first use refills
            }
        }

        fn refill(&mut self) -> Result<(), Error> {
            os_fill(&mut self.buf[..])?;
            self.pos = 0;
            Ok(())
        }

        fn take(&mut self, out: &mut [u8]) -> Result<(), Error> {
            if out.len() > POOL_LEN / 4 {
                return os_fill(out);
            }
            if POOL_LEN - self.pos < out.len() {
                self.refill()?;
            }
            let end = self.pos + out.len();
            out.copy_from_slice(&self.buf[self.pos..end]);
            // Used bytes are cleared so nothing handed out stays in memory twice.
            self.buf[self.pos..end].fill(0);
            self.pos = end;
            Ok(())
        }
    }

    thread_local! {
        static POOL: RefCell<Pool> = RefCell::new(Pool::new());
    }

    fn os_fill(out: &mut [u8]) -> Result<(), Error> {
        mod_rand::tier3::fill_bytes(out).map_err(|_| Error::Random)
    }

    impl OsPads {
        /// Discard this thread's buffered bytes and refill from the OS.
        ///
        /// # Errors
        ///
        /// [`Error::Random`] if the OS generator fails.
        pub fn refill() -> Result<(), Error> {
            POOL.try_with(|pool| match pool.try_borrow_mut() {
                Ok(mut pool) => pool.refill(),
                Err(_) => Ok(()),
            })
            .unwrap_or(Ok(()))
        }
    }

    impl PadSource for OsPads {
        #[inline]
        fn fill(&mut self, out: &mut [u8]) -> Result<(), Error> {
            // During thread teardown, or if the buffer is somehow in use, read
            // the OS generator directly rather than fail or panic.
            match POOL.try_with(|pool| pool.try_borrow_mut().map(|mut p| p.take(out))) {
                Ok(Ok(result)) => result,
                _ => os_fill(out),
            }
        }
    }

    #[cfg(test)]
    mod tests {
        use super::{OsPads, POOL_LEN, Pool};
        use crate::PadSource;

        #[test]
        fn test_os_pads_fill_produces_distinct_pads() {
            let mut a = [0u8; 22];
            let mut b = [0u8; 22];
            OsPads.fill(&mut a).unwrap();
            OsPads.fill(&mut b).unwrap();
            assert_ne!(a, b);
            assert_ne!(a, [0u8; 22]);
        }

        #[test]
        fn test_pool_refills_across_boundary() {
            let mut pool = Pool::new();
            let mut seen = std::collections::HashSet::new();
            for _ in 0..(POOL_LEN / 22) * 3 {
                let mut pad = [0u8; 22];
                pool.take(&mut pad).unwrap();
                assert!(seen.insert(pad), "a pad repeated");
            }
        }

        #[test]
        fn test_pool_large_request_reads_os_directly() {
            let mut pool = Pool::new();
            let mut big = vec![0u8; POOL_LEN];
            pool.take(&mut big).unwrap();
            assert_eq!(pool.pos, POOL_LEN, "buffer untouched");
            assert!(big.iter().any(|&b| b != 0));
        }

        #[test]
        fn test_pool_clears_used_bytes() {
            let mut pool = Pool::new();
            let mut pad = [0u8; 32];
            pool.take(&mut pad).unwrap();
            assert!(pool.buf[..32].iter().all(|&b| b == 0));
        }

        #[test]
        fn test_os_pads_refill_then_fill() {
            OsPads::refill().unwrap();
            let mut pad = [0u8; 16];
            OsPads.fill(&mut pad).unwrap();
            assert_ne!(pad, [0u8; 16]);
        }

        #[test]
        fn test_os_pads_threads_get_independent_streams() {
            let a = std::thread::spawn(|| {
                let mut p = [0u8; 22];
                OsPads.fill(&mut p).unwrap();
                p
            })
            .join()
            .unwrap();
            let mut b = [0u8; 22];
            OsPads.fill(&mut b).unwrap();
            assert_ne!(a, b);
        }
    }
}
