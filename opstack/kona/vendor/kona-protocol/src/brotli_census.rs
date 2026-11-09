//! Native-only bounded channel diagnostics; no decoder or consensus shortcut.
#[cfg(target_arch = "riscv64")]
compile_error!("Brotli census is native-only");
extern crate std;
#[cfg(feature = "stwo-lazy-brotli-alloc")]
use crate::brotli_alloc::Budget;
#[cfg(feature = "stwo-lazy-brotli-alloc")]
use alloc::rc::Rc;
use alloc::vec::Vec;
use core::cell::RefCell;
use std::time::Instant;
const MAX_BYTES: usize = 64 * 1024 * 1024;
const MAX_CALLS: usize = 32;
/// One allocator's final counters, measured in logical elements.
#[derive(Debug, Clone, Copy)]
pub struct Allocation {
    /// Maximum simultaneously live elements.
    pub limit: usize,
    /// Live elements after decoder destruction.
    pub live: usize,
    /// Maximum live element count.
    pub peak: usize,
    /// Number of nonempty allocations.
    pub allocations: usize,
    /// Total initialized elements over the call.
    pub initialized_cells: usize,
    /// Size of one element in bytes.
    pub cell_bytes: usize,
}
/// Captured input/output and diagnostic timings for one decoder invocation.
#[derive(Debug)]
pub struct Call {
    /// Exact compressed channel bytes.
    pub input: Vec<u8>,
    /// Decoded bytes, or none on rejection.
    pub output: Option<Vec<u8>>,
    /// Original protocol output truncation cap.
    pub max_output: usize,
    /// Time through decoder setup.
    pub setup_ns: u64,
    /// Total decoder time.
    pub elapsed_ns: u64,
    /// Number of nonempty allocations.
    pub allocations: Vec<Allocation>,
    /// Eager pool initialization bytes; zero in lazy mode.
    pub upfront_zeroed_bytes: usize,
}
/// Bounded per-thread capture result.
#[derive(Debug)]
pub struct Report {
    /// Captured calls in execution order.
    pub calls: Vec<Call>,
    /// Capture refused data beyond its own diagnostics caps.
    pub overflow: bool,
}
struct State {
    calls: Vec<Call>,
    reserved: usize,
    overflow: bool,
    #[cfg(feature = "stwo-lazy-brotli-alloc")]
    budgets: Vec<Option<[Rc<Budget>; 3]>>,
}
std::thread_local! {static STATE:RefCell<Option<State>>=const{RefCell::new(None)};}
#[derive(Debug)]
pub(crate) struct Scope {
    index: Option<usize>,
    start: Instant,
}
impl Scope {
    pub(crate) fn begin(input: &[u8], cap: usize) -> Self {
        let index = STATE.with_borrow_mut(|state| {
            let Some(s) = state else { return None };
            let bytes = input.len();
            if s.calls.len() >= MAX_CALLS
                || s.reserved.checked_add(bytes).is_none_or(|n| n > MAX_BYTES)
            {
                s.overflow = true;
                return None;
            }
            s.reserved += bytes;
            let i = s.calls.len();
            s.calls.push(Call {
                input: input.to_vec(),
                output: None,
                max_output: cap,
                setup_ns: 0,
                elapsed_ns: 0,
                allocations: Vec::new(),
                upfront_zeroed_bytes: if cfg!(feature = "stwo-lazy-brotli-alloc") {
                    0
                } else {
                    32 * 1024 * 1024
                        + 1024 * 1024 * core::mem::size_of::<u32>()
                        + 4 * 1024 * 1024 * core::mem::size_of::<brotli_decompressor::HuffmanCode>()
                },
            });
            #[cfg(feature = "stwo-lazy-brotli-alloc")]
            s.budgets.push(None);
            Some(i)
        });
        Self {
            index,
            start: Instant::now(),
        }
    }
    pub(crate) fn setup_complete(&self) {
        if let Some(i) = self.index {
            STATE.with_borrow_mut(|s| {
                s.as_mut().unwrap().calls[i].setup_ns = self.start.elapsed().as_nanos() as u64
            });
        }
    }
    #[cfg(feature = "stwo-lazy-brotli-alloc")]
    pub(crate) fn budgets(&self, values: [Rc<Budget>; 3]) {
        if let Some(i) = self.index {
            STATE.with_borrow_mut(|s| s.as_mut().unwrap().budgets[i] = Some(values));
        }
    }
    pub(crate) fn finish(self, result: &Result<Vec<u8>, crate::BrotliDecompressionError>) {
        if let Some(i) = self.index {
            STATE.with_borrow_mut(|s| {
                let s = s.as_mut().unwrap();
                let call = &mut s.calls[i];
                call.elapsed_ns = self.start.elapsed().as_nanos() as u64;
                if let Ok(output) = result {
                    if output.len() <= call.max_output
                        && s.reserved
                            .checked_add(output.len())
                            .is_some_and(|n| n <= MAX_BYTES)
                    {
                        s.reserved += output.len();
                        call.output = Some(output.clone());
                    } else {
                        s.overflow = true;
                    }
                }
                #[cfg(feature = "stwo-lazy-brotli-alloc")]
                if let Some(budgets) = s.budgets[i].take() {
                    for (budget, cell_bytes) in budgets.into_iter().zip([
                        1,
                        core::mem::size_of::<u32>(),
                        core::mem::size_of::<brotli_decompressor::HuffmanCode>(),
                    ]) {
                        let a = budget.stats();
                        call.allocations.push(Allocation {
                            limit: a.limit,
                            live: a.live,
                            peak: a.peak,
                            allocations: a.allocations,
                            initialized_cells: a.initialized_cells,
                            cell_bytes,
                        });
                    }
                }
            });
        }
    }
}
/// Capture calls made by the closure, clearing thread-local state on panic.
pub fn record<T>(f: impl FnOnce() -> T) -> (T, Report) {
    STATE.with_borrow_mut(|s| {
        assert!(s.is_none(), "nested Brotli capture");
        *s = Some(State {
            calls: Vec::new(),
            reserved: 0,
            overflow: false,
            #[cfg(feature = "stwo-lazy-brotli-alloc")]
            budgets: Vec::new(),
        })
    });
    struct Guard;
    impl Drop for Guard {
        fn drop(&mut self) {
            STATE.with_borrow_mut(|s| {
                s.take();
            });
        }
    }
    let guard = Guard;
    let result = f();
    let state = STATE.with_borrow_mut(|s| s.take().unwrap());
    drop(guard);
    (
        result,
        Report {
            calls: state.calls,
            overflow: state.overflow,
        },
    )
}
