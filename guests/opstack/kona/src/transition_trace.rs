//! Host-only recording of authenticated inputs consumed by a transition.
extern crate std;

use alloy_primitives::B256;
use core::cell::RefCell;
use std::collections::BTreeSet;

#[derive(Default, serde::Serialize)]
pub struct ReadTrace {
    pub execution_fixture: Option<crate::execution::Fixture>,
    pub execution_preimages: BTreeSet<B256>,
    #[serde(skip)]
    executing: bool,
    pub preimages: BTreeSet<B256>,
    pub versioned_blob_hashes: BTreeSet<B256>,
}

std::thread_local! {
    static TRACE: RefCell<Option<ReadTrace>> = const { RefCell::new(None) };
}

pub(crate) fn preimage(hash: B256) {
    TRACE.with_borrow_mut(|trace| {
        if let Some(trace) = trace {
            trace.preimages.insert(hash);
            if trace.executing {
                trace.execution_preimages.insert(hash);
            }
        }
    });
}

pub(crate) fn blob(hash: B256) {
    TRACE.with_borrow_mut(|trace| {
        if let Some(trace) = trace {
            trace.versioned_blob_hashes.insert(hash);
        }
    });
}

pub(crate) fn start_execution() -> bool {
    TRACE.with_borrow_mut(|trace| {
        if let Some(trace) = trace {
            trace.executing = true;
            true
        } else {
            false
        }
    })
}

pub(crate) fn finish_execution(fixture: crate::execution::Fixture) {
    TRACE.with_borrow_mut(|trace| {
        if let Some(trace) = trace {
            trace.executing = false;
            trace.execution_fixture = Some(fixture);
        }
    });
}

/// Record only successful authenticated accesses in this thread. Callers must
/// discard the trace unless the complete transition independently succeeds.
pub fn record<T>(verify: impl FnOnce() -> T) -> (T, ReadTrace) {
    TRACE.with_borrow_mut(|trace| {
        assert!(trace.is_none(), "nested transition tracing");
        *trace = Some(ReadTrace::default());
    });
    struct Guard;
    impl Drop for Guard {
        fn drop(&mut self) {
            TRACE.with_borrow_mut(|trace| {
                trace.take();
            });
        }
    }
    let guard = Guard;
    let result = verify();
    let trace = TRACE.with_borrow_mut(|trace| trace.take().unwrap());
    drop(guard);
    (result, trace)
}
