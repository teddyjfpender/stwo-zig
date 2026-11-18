//! Safe demand-initialized Brotli cells with the original per-type live caps.
use alloc::{boxed::Box, rc::Rc, vec, vec::Vec};
use alloc_no_stdlib::{Allocator, SliceWrapper, SliceWrapperMut};
use core::{cell::Cell, fmt, marker::PhantomData};

#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct Stats {
    pub live: usize,
    pub peak: usize,
    pub allocations: usize,
    pub initialized_cells: usize,
    pub limit: usize,
}
#[derive(Debug)]
pub(crate) struct Budget {
    live: Cell<usize>,
    peak: Cell<usize>,
    allocations: Cell<usize>,
    initialized: Cell<usize>,
    limit: usize,
}
impl Budget {
    pub(crate) fn stats(&self) -> Stats {
        Stats {
            live: self.live.get(),
            peak: self.peak.get(),
            allocations: self.allocations.get(),
            initialized_cells: self.initialized.get(),
            limit: self.limit,
        }
    }
}
/// One allocator's budget survives until its last owned cell buffer is dropped.
pub(crate) struct Heap<T> {
    budget: Rc<Budget>,
    marker: PhantomData<T>,
}
impl<T> fmt::Debug for Heap<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BrotliHeap")
            .field("budget", &self.budget)
            .finish()
    }
}
impl<T> Heap<T> {
    pub(crate) fn new(limit: usize) -> Self {
        Self {
            budget: Rc::new(Budget {
                live: Cell::new(0),
                peak: Cell::new(0),
                allocations: Cell::new(0),
                initialized: Cell::new(0),
                limit,
            }),
            marker: PhantomData,
        }
    }
    pub(crate) fn budget(&self) -> Rc<Budget> {
        self.budget.clone()
    }
}

pub(crate) struct Memory<T> {
    data: Box<[T]>,
    owner: Option<Rc<Budget>>,
}
impl<T> fmt::Debug for Memory<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BrotliMemory")
            .field("len", &self.data.len())
            .finish()
    }
}
impl<T> Default for Memory<T> {
    fn default() -> Self {
        Self {
            data: Vec::new().into_boxed_slice(),
            owner: None,
        }
    }
}
impl<T> SliceWrapper<T> for Memory<T> {
    fn slice(&self) -> &[T] {
        &self.data
    }
}
impl<T> SliceWrapperMut<T> for Memory<T> {
    fn slice_mut(&mut self) -> &mut [T] {
        &mut self.data
    }
}
impl<T> Drop for Memory<T> {
    fn drop(&mut self) {
        if let Some(owner) = &self.owner {
            owner.live.set(
                owner
                    .live
                    .get()
                    .checked_sub(self.data.len())
                    .expect("Brotli live-cell ownership"),
            );
        }
    }
}
struct Reservation {
    owner: Option<Rc<Budget>>,
    len: usize,
}
impl Drop for Reservation {
    fn drop(&mut self) {
        if let Some(owner) = &self.owner {
            owner.live.set(
                owner
                    .live
                    .get()
                    .checked_sub(self.len)
                    .expect("Brotli reservation ownership"),
            );
        }
    }
}
impl<T: Default + Clone> Allocator<T> for Heap<T> {
    type AllocatedMemory = Memory<T>;
    fn alloc_cell(&mut self, len: usize) -> Memory<T> {
        if len == 0 {
            return Memory::default();
        }
        let next = self
            .budget
            .live
            .get()
            .checked_add(len)
            .expect("Brotli cell-count overflow");
        assert!(next <= self.budget.limit, "Brotli per-type live-cell limit");
        let mut reservation = Reservation {
            owner: Some(self.budget.clone()),
            len,
        };
        self.budget.live.set(next);
        self.budget.peak.set(self.budget.peak.get().max(next));
        // Every requested T is initialized. No MaybeUninit, set_len, or assumptions
        // about fresh/recycled allocator contents are used.
        let data = vec![T::default(); len].into_boxed_slice();
        self.budget
            .allocations
            .set(self.budget.allocations.get() + 1);
        self.budget
            .initialized
            .set(self.budget.initialized.get() + len);
        Memory {
            data,
            owner: reservation.owner.take(),
        }
    }
    fn free_cell(&mut self, data: Memory<T>) {
        if let Some(owner) = &data.owner {
            assert!(Rc::ptr_eq(owner, &self.budget), "foreign Brotli cell owner");
        }
        drop(data);
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    #[test]
    fn bounds_reuse_zeroes_and_lifetime() {
        let mut a = Heap::<u32>::new(8);
        let owner = a.budget();
        let mut x = a.alloc_cell(5);
        x.slice_mut().fill(99);
        let y = a.alloc_cell(3);
        assert_eq!(owner.stats().live, 8);
        assert!(
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| a.alloc_cell(1))).is_err()
        );
        a.free_cell(x);
        let z = a.alloc_cell(5);
        assert!(z.slice().iter().all(|x| *x == 0));
        assert_eq!(owner.stats().peak, 8);
        drop(a);
        assert_eq!(owner.stats().live, 8);
        drop(y);
        drop(z);
        assert_eq!(owner.stats().live, 0);
    }
    #[test]
    fn foreign_owner_refuses_and_releases_original() {
        let mut a = Heap::<u8>::new(8);
        let mut b = Heap::<u8>::new(8);
        let owner = a.budget();
        let x = a.alloc_cell(4);
        assert!(std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| b.free_cell(x))).is_err());
        assert_eq!(owner.stats().live, 0);
        assert_eq!(b.budget().stats().live, 0);
    }
    #[test]
    fn initialization_panic_rolls_back() {
        #[derive(Default)]
        struct Bad;
        impl Clone for Bad {
            fn clone(&self) -> Self {
                panic!("test clone failure")
            }
        }
        let mut a = Heap::<Bad>::new(4);
        let owner = a.budget();
        assert!(
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| a.alloc_cell(4))).is_err()
        );
        assert_eq!(owner.stats().live, 0);
        let empty = a.alloc_cell(0);
        assert!(empty.slice().is_empty());
    }
}
