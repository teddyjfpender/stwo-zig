//! Single-threaded, constant-time guest allocator candidate.
//!
//! The Ethereum RV32 guest has a large sparse virtual heap and is strictly
//! single threaded.  Its previous linked-list allocator performs a first-fit
//! scan on every allocation; retained PC evidence shows that scan dominating
//! execution.  This candidate rounds layouts to power-of-two size classes,
//! keeps one intrusive free list per class, and services both allocation and
//! deallocation in O(1).  It deliberately does not coalesce blocks.

use core::{
    alloc::{GlobalAlloc, Layout},
    cell::UnsafeCell,
    cmp, mem, ptr,
};

const MIN_CLASS_SHIFT: u32 = 3;
const MIN_BLOCK_BYTES: usize = 1 << MIN_CLASS_SHIFT;
const CLASS_COUNT: usize = usize::BITS as usize - MIN_CLASS_SHIFT as usize;

struct State {
    bump: usize,
    end: usize,
    free_heads: [*mut u8; CLASS_COUNT],
}

impl State {
    const fn empty() -> Self {
        Self {
            bump: 0,
            end: 0,
            free_heads: [ptr::null_mut(); CLASS_COUNT],
        }
    }
}

/// A single-threaded segregated allocator for the authenticated RV32 heap.
///
/// Every returned block is aligned to its power-of-two class.  Freed blocks
/// store their next pointer in the first machine word, so the allocator needs
/// no side metadata proportional to the number of live allocations.
pub struct SegregatedPowerOfTwoHeapV1(UnsafeCell<State>);

unsafe impl Sync for SegregatedPowerOfTwoHeapV1 {}

impl SegregatedPowerOfTwoHeapV1 {
    pub const fn empty() -> Self {
        Self(UnsafeCell::new(State::empty()))
    }

    /// Initializes the allocator over `[start, start + size)`.
    ///
    /// The caller must invoke this exactly once before any allocation and must
    /// ensure the range remains exclusively owned for the process lifetime.
    pub unsafe fn initialize(&self, start: *mut u8, size: usize) {
        let begin = start as usize;
        let end = begin.checked_add(size).unwrap_or(begin);
        let bump = align_up(begin, MIN_BLOCK_BYTES).unwrap_or(end);
        let state = unsafe { &mut *self.0.get() };
        state.bump = bump;
        state.end = end;
        state.free_heads.fill(ptr::null_mut());
    }

    #[inline(always)]
    fn class_for(layout: Layout) -> Option<(usize, usize)> {
        let needed = layout
            .size()
            .max(layout.align())
            .max(mem::size_of::<*mut u8>());
        let block_bytes = needed.checked_next_power_of_two()?;
        let shift = block_bytes.trailing_zeros();
        if shift < MIN_CLASS_SHIFT {
            return None;
        }
        let class = (shift - MIN_CLASS_SHIFT) as usize;
        (class < CLASS_COUNT).then_some((class, block_bytes))
    }
}

#[inline(always)]
fn align_up(value: usize, alignment: usize) -> Option<usize> {
    let mask = alignment.checked_sub(1)?;
    value.checked_add(mask).map(|candidate| candidate & !mask)
}

unsafe impl GlobalAlloc for SegregatedPowerOfTwoHeapV1 {
    #[inline(always)]
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let Some((class, block_bytes)) = Self::class_for(layout) else {
            return ptr::null_mut();
        };
        let state = unsafe { &mut *self.0.get() };

        let recycled = state.free_heads[class];
        if !recycled.is_null() {
            state.free_heads[class] = unsafe { ptr::read(recycled.cast::<*mut u8>()) };
            return recycled;
        }

        // Recycle a larger class by splitting it downward. The search is
        // bounded by the machine word width and never scans heap addresses.
        let mut donor_class = class + 1;
        while donor_class < CLASS_COUNT && state.free_heads[donor_class].is_null() {
            donor_class += 1;
        }
        if donor_class < CLASS_COUNT {
            let donor = state.free_heads[donor_class];
            state.free_heads[donor_class] = unsafe { ptr::read(donor.cast::<*mut u8>()) };
            while donor_class > class {
                donor_class -= 1;
                let half_bytes = MIN_BLOCK_BYTES << donor_class;
                let buddy = unsafe { donor.add(half_bytes) };
                unsafe { ptr::write(buddy.cast::<*mut u8>(), state.free_heads[donor_class]) };
                state.free_heads[donor_class] = buddy;
            }
            return donor;
        }

        let Some(start) = align_up(state.bump, block_bytes) else {
            return ptr::null_mut();
        };
        let Some(next) = start.checked_add(block_bytes) else {
            return ptr::null_mut();
        };
        if next > state.end {
            return ptr::null_mut();
        }
        state.bump = next;
        start as *mut u8
    }

    #[inline(always)]
    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        let Some((class, _)) = Self::class_for(layout) else {
            return;
        };
        let state = unsafe { &mut *self.0.get() };
        unsafe { ptr::write(pointer.cast::<*mut u8>(), state.free_heads[class]) };
        state.free_heads[class] = pointer;
    }

    #[inline(always)]
    unsafe fn realloc(&self, pointer: *mut u8, old_layout: Layout, new_size: usize) -> *mut u8 {
        let Ok(new_layout) = Layout::from_size_align(new_size, old_layout.align()) else {
            return ptr::null_mut();
        };
        let Some((_, old_block_bytes)) = Self::class_for(old_layout) else {
            return ptr::null_mut();
        };
        let Some((_, new_block_bytes)) = Self::class_for(new_layout) else {
            return ptr::null_mut();
        };
        if old_block_bytes == new_block_bytes {
            return pointer;
        }

        let replacement = unsafe { self.alloc(new_layout) };
        if replacement.is_null() {
            return replacement;
        }
        unsafe {
            ptr::copy_nonoverlapping(pointer, replacement, cmp::min(old_layout.size(), new_size));
            self.dealloc(pointer, old_layout);
        }
        replacement
    }
}
