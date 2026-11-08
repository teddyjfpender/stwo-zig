//! Exact-layout O(1)-average guest allocator candidate.
//!
//! Power-of-two classes remove first-fit scans but over-reserve too much for
//! this Ethereum workload. This variant hashes the exact physical size and
//! alignment into fixed intrusive free-list buckets. A recycled node retains
//! its exact key in the freed bytes; live allocations carry no header. Bucket
//! collisions require a short local scan, never a scan over heap addresses.

use core::{
    alloc::{GlobalAlloc, Layout},
    cell::UnsafeCell,
    cmp, mem, ptr,
};

const FREE_WORDS: usize = 3;
const MIN_BLOCK_BYTES: usize = FREE_WORDS * mem::size_of::<usize>();
const MIN_ALIGNMENT: usize = mem::align_of::<usize>();
const BUCKET_COUNT: usize = 4096;

struct State {
    bump: usize,
    end: usize,
    free_heads: [*mut u8; BUCKET_COUNT],
}

impl State {
    const fn empty() -> Self {
        Self {
            bump: 0,
            end: 0,
            free_heads: [ptr::null_mut(); BUCKET_COUNT],
        }
    }
}

pub struct ExactLayoutFreeListHeapV2(UnsafeCell<State>);

unsafe impl Sync for ExactLayoutFreeListHeapV2 {}

impl ExactLayoutFreeListHeapV2 {
    pub const fn empty() -> Self {
        Self(UnsafeCell::new(State::empty()))
    }

    pub unsafe fn initialize(&self, start: *mut u8, size: usize) {
        let begin = start as usize;
        let end = begin.checked_add(size).unwrap_or(begin);
        let bump = align_up(begin, MIN_ALIGNMENT).unwrap_or(end);
        let state = unsafe { &mut *self.0.get() };
        state.bump = bump;
        state.end = end;
        state.free_heads.fill(ptr::null_mut());
    }

    #[inline(always)]
    fn normalized(layout: Layout) -> (usize, usize) {
        (
            layout.size().max(MIN_BLOCK_BYTES),
            layout.align().max(MIN_ALIGNMENT),
        )
    }

    #[inline(always)]
    fn bucket(block_bytes: usize, alignment: usize) -> usize {
        block_bytes
            .wrapping_mul(0x9e37_79b1usize)
            .wrapping_add(alignment.rotate_left(13))
            & (BUCKET_COUNT - 1)
    }
}

#[inline(always)]
fn align_up(value: usize, alignment: usize) -> Option<usize> {
    let mask = alignment.checked_sub(1)?;
    value.checked_add(mask).map(|candidate| candidate & !mask)
}

unsafe impl GlobalAlloc for ExactLayoutFreeListHeapV2 {
    #[inline(always)]
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let (block_bytes, alignment) = Self::normalized(layout);
        let bucket = Self::bucket(block_bytes, alignment);
        let state = unsafe { &mut *self.0.get() };

        let mut link = ptr::addr_of_mut!(state.free_heads[bucket]);
        loop {
            let candidate = unsafe { ptr::read(link) };
            if candidate.is_null() {
                break;
            }
            let words = candidate.cast::<usize>();
            let next = unsafe { ptr::read(words.cast::<*mut u8>()) };
            let candidate_bytes = unsafe { ptr::read(words.add(1)) };
            let candidate_alignment = unsafe { ptr::read(words.add(2)) };
            if candidate_bytes == block_bytes && candidate_alignment == alignment {
                unsafe { ptr::write(link, next) };
                return candidate;
            }
            link = words.cast::<*mut u8>();
        }

        let Some(start) = align_up(state.bump, alignment) else {
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
        let (block_bytes, alignment) = Self::normalized(layout);
        let bucket = Self::bucket(block_bytes, alignment);
        let state = unsafe { &mut *self.0.get() };
        let words = pointer.cast::<usize>();
        unsafe {
            ptr::write(words.cast::<*mut u8>(), state.free_heads[bucket]);
            ptr::write(words.add(1), block_bytes);
            ptr::write(words.add(2), alignment);
        }
        state.free_heads[bucket] = pointer;
    }

    #[inline(always)]
    unsafe fn realloc(&self, pointer: *mut u8, old_layout: Layout, new_size: usize) -> *mut u8 {
        let Ok(new_layout) = Layout::from_size_align(new_size, old_layout.align()) else {
            return ptr::null_mut();
        };
        if Self::normalized(old_layout) == Self::normalized(new_layout) {
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
