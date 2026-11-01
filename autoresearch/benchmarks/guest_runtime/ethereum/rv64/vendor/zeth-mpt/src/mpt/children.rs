// Copyright 2025 RISC Zero, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! stwo: branch children as tagged words.
//!
//! A slot is `0` (absent), a `Box<Node<M>>` pointer (low bit clear), or
//! `(p << 1) | 1` where `p` points at the 32 digest bytes of a child that is
//! still unresolved, inside an RLP buffer that outlives the trie (see
//! `Children::insert_digest_ref`). Nearly every child of a decoded witness
//! branch is such a digest, and most are never resolved: storing a pointer
//! instead of allocating, initializing and copying a boxed `Node::Digest`
//! is the point. Any access that needs a `&mut Node` (insert, remove,
//! collapsing a branch) first turns the reference into an owned
//! `Node::Digest`, so the rest of the trie code sees the same nodes as
//! before.

use super::{memoize::Memoization, node::{Child, Node}};
use alloc::boxed::Box;
use alloy_primitives::B256;
use core::marker::PhantomData;

const EMPTY: usize = 0;

/// Implements a helper wrapper for the children of a Branch node.
///
/// This wrapper offers various convenience features and assures that there is never a Null child.
pub(super) struct Children<M> {
    slots: [usize; 16],
    _owns: PhantomData<Box<Node<M>>>,
}

/// A read-only view of one child.
pub(super) enum ChildView<'a, M> {
    Node(&'a Node<M>),
    Digest(&'a B256),
}

impl<'a, M> ChildView<'a, M> {
    /// The node, if the child is an owned node.
    #[inline]
    pub(super) fn node(&self) -> Option<&'a Node<M>> {
        match self {
            ChildView::Node(n) => Some(n),
            ChildView::Digest(_) => None,
        }
    }

    /// The digest of an unresolved child, owned or referenced.
    #[inline]
    pub(super) fn digest(&self) -> Option<&'a B256> {
        match self {
            ChildView::Node(Node::Digest(d)) => Some(d),
            ChildView::Node(_) => None,
            ChildView::Digest(d) => Some(d),
        }
    }
}

#[inline(always)]
fn is_ref(slot: usize) -> bool {
    slot & 1 == 1
}

/// # Safety
/// `slot` must be a reference slot.
#[inline(always)]
unsafe fn ref_digest<'a>(slot: usize) -> &'a B256 {
    // SAFETY: B256 has alignment 1; the pointer was taken from a live
    // 32-byte digest (see `insert_digest_ref`).
    unsafe { &*((slot >> 1) as *const B256) }
}

impl<M> Default for Children<M> {
    fn default() -> Self {
        Self { slots: [EMPTY; 16], _owns: PhantomData }
    }
}

impl<M> Drop for Children<M> {
    fn drop(&mut self) {
        for slot in self.slots {
            if slot != EMPTY && !is_ref(slot) {
                // SAFETY: owned slots hold `Box::into_raw` pointers
                drop(unsafe { Box::from_raw(slot as *mut Node<M>) });
            }
        }
    }
}

impl<M: Clone> Clone for Children<M> {
    fn clone(&self) -> Self {
        let mut out = Self::default();
        for (i, &slot) in self.slots.iter().enumerate() {
            out.slots[i] = if slot == EMPTY || is_ref(slot) {
                slot
            } else {
                // SAFETY: owned slot
                let node = unsafe { &*(slot as *const Node<M>) };
                Box::into_raw(Box::new(node.clone())) as usize
            };
        }
        out
    }
}

impl<M> core::fmt::Debug for Children<M>
where
    Node<M>: core::fmt::Debug,
{
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let mut list = f.debug_list();
        for child in self.iter() {
            match child {
                None => list.entry(&None::<()>),
                Some(ChildView::Node(n)) => list.entry(n),
                Some(ChildView::Digest(d)) => list.entry(&Node::<M>::Digest(*d)),
            };
        }
        list.finish()
    }
}

impl<M> PartialEq for Children<M> {
    fn eq(&self, other: &Self) -> bool {
        self.iter().zip(other.iter()).all(|(a, b)| match (a, b) {
            (None, None) => true,
            (Some(a), Some(b)) => match (a.digest(), b.digest()) {
                (Some(x), Some(y)) => x == y,
                (None, None) => a.node() == b.node(),
                _ => false,
            },
            _ => false,
        })
    }
}

impl<M> Eq for Children<M> {}

/// A view into a single entry in a children map, which may either be vacant or occupied.
///
/// This `enum` is constructed from the [`Children::entry`] method.
pub(super) enum Entry<'a, M> {
    Vacant(VacantEntry<'a, M>),
    Occupied(OccupiedEntry<'a, M>),
}

/// A view into a vacant entry in a children map.
/// It is part of the [`Entry`] enum.
pub(super) struct VacantEntry<'a, M> {
    slot: &'a mut usize,
    _owns: PhantomData<Box<Node<M>>>,
}

/// A view into an occupied entry in a children map.
/// It is part of the [`Entry`] enum. Its slot always holds an owned node.
pub(super) struct OccupiedEntry<'a, M> {
    slot: &'a mut usize,
    _owns: PhantomData<Box<Node<M>>>,
}

impl<M> Drop for OccupiedEntry<'_, M> {
    fn drop(&mut self) {
        if matches!(self.get(), Node::Null) {
            // SAFETY: owned slot
            drop(unsafe { Box::from_raw(*self.slot as *mut Node<M>) });
            *self.slot = EMPTY;
        }
    }
}

impl<M> VacantEntry<'_, M> {
    /// Sets the child of the entry with the `VacantEntry`'s index, and returns a mutable reference
    /// to it.
    #[inline]
    pub(super) fn insert(self, child: Child<M>) {
        assert!(!matches!(child.as_ref(), Node::Null));
        *self.slot = Box::into_raw(child) as usize;
    }
}

impl<M> OccupiedEntry<'_, M> {
    /// Gets a reference to the child node in the entry.
    #[inline]
    pub(super) fn get(&self) -> &Node<M> {
        // SAFETY: an OccupiedEntry only wraps an owned slot
        unsafe { &*(*self.slot as *const Node<M>) }
    }

    /// Gets a mutable reference to the child node in the entry.
    #[inline]
    pub(super) fn get_mut(&mut self) -> &mut Node<M> {
        // SAFETY: an OccupiedEntry only wraps an owned slot
        unsafe { &mut *(*self.slot as *mut Node<M>) }
    }
}

#[allow(dead_code)]
impl<M> Children<M> {
    /// Turns a reference slot into an owned `Node::Digest`.
    #[inline]
    fn own(slot: &mut usize) {
        if is_ref(*slot) {
            // SAFETY: reference slot
            let digest = unsafe { *ref_digest(*slot) };
            *slot = Box::into_raw(Box::new(Node::<M>::Digest(digest))) as usize;
        }
    }

    #[inline]
    pub(super) fn get(&self, idx: u8) -> Option<ChildView<'_, M>> {
        Self::view(self.slots[idx as usize])
    }

    #[inline]
    pub(super) unsafe fn get_unchecked(&self, idx: u8) -> Option<ChildView<'_, M>> {
        Self::view(unsafe { *self.slots.get_unchecked(idx as usize) })
    }

    #[inline(always)]
    fn view<'a>(slot: usize) -> Option<ChildView<'a, M>> {
        if slot == EMPTY {
            None
        } else if is_ref(slot) {
            // SAFETY: reference slot
            Some(ChildView::Digest(unsafe { ref_digest(slot) }))
        } else {
            // SAFETY: owned slot
            Some(ChildView::Node(unsafe { &*(slot as *const Node<M>) }))
        }
    }

    #[inline]
    pub(super) fn entry(&mut self, idx: u8) -> Entry<'_, M> {
        let slot = &mut self.slots[idx as usize];
        if *slot == EMPTY {
            Entry::Vacant(VacantEntry { slot, _owns: PhantomData })
        } else {
            Self::own(slot);
            Entry::Occupied(OccupiedEntry { slot, _owns: PhantomData })
        }
    }

    #[inline]
    pub(super) fn insert(&mut self, idx: u8, child: Child<M>) {
        assert!(!matches!(child.as_ref(), Node::Null));
        let slot = &mut self.slots[idx as usize];
        let old = core::mem::replace(slot, Box::into_raw(child) as usize);
        if old != EMPTY && !is_ref(old) {
            // SAFETY: owned slot
            drop(unsafe { Box::from_raw(old as *mut Node<M>) });
        }
    }

    /// stwo: stores an unresolved child as a reference to its 32 digest
    /// bytes.
    ///
    /// # Safety
    /// `digest` must stay valid and unchanged for as long as this trie (and
    /// any clone of it) exists; the slot must be empty.
    #[inline]
    pub(super) unsafe fn insert_digest_ref(&mut self, idx: u8, digest: *const u8) {
        debug_assert!(self.slots[idx as usize] == EMPTY);
        self.slots[idx as usize] = ((digest as usize) << 1) | 1;
    }

    /// stwo: the digest of a referenced (unresolved) child, if slot `idx` is one.
    #[inline(always)]
    pub(super) fn digest_ref(&self, idx: usize) -> Option<&B256> {
        let slot = self.slots[idx];
        // SAFETY: reference slot
        is_ref(slot).then(|| unsafe { ref_digest(slot) })
    }

    /// stwo: replaces slot `idx` with an owned node (used when resolving a
    /// referenced digest).
    #[inline]
    pub(super) fn set_owned(&mut self, idx: usize, child: Child<M>) {
        let old = core::mem::replace(&mut self.slots[idx], Box::into_raw(child) as usize);
        if old != EMPTY && !is_ref(old) {
            // SAFETY: owned slot
            drop(unsafe { Box::from_raw(old as *mut Node<M>) });
        }
    }

    /// stwo: the owned node in slot `idx`, if any.
    #[inline(always)]
    pub(super) fn owned_mut(&mut self, idx: usize) -> Option<&mut Node<M>> {
        let slot = self.slots[idx];
        // SAFETY: owned slot
        (slot != EMPTY && !is_ref(slot)).then(|| unsafe { &mut *(slot as *mut Node<M>) })
    }

    /// stwo: empties slot `idx`.
    #[inline]
    pub(super) fn clear_slot(&mut self, idx: usize) {
        let old = core::mem::replace(&mut self.slots[idx], EMPTY);
        if old != EMPTY && !is_ref(old) {
            // SAFETY: owned slot
            drop(unsafe { Box::from_raw(old as *mut Node<M>) });
        }
    }

    #[inline]
    pub(super) fn len(&self) -> usize {
        self.slots.iter().filter(|&&s| s != EMPTY).count()
    }

    pub(super) fn take_single_child(&mut self) -> Option<(u8, Child<M>)> {
        let mut child_idx = None;
        for (i, &slot) in self.slots.iter().enumerate() {
            if slot != EMPTY {
                if child_idx.is_some() {
                    return None; // more than one child found
                }
                child_idx = Some(i);
            }
        }
        child_idx.map(|i| {
            Self::own(&mut self.slots[i]);
            let slot = core::mem::replace(&mut self.slots[i], EMPTY);
            // SAFETY: owned slot
            (i as u8, unsafe { Box::from_raw(slot as *mut Node<M>) })
        })
    }

    #[inline]
    pub(super) fn iter(&self) -> impl Iterator<Item = Option<ChildView<'_, M>>> + '_ {
        self.slots.iter().map(|&s| Self::view(s))
    }

    #[inline]
    pub(super) fn into_iter(mut self) -> impl Iterator<Item = Option<Child<M>>> {
        let mut out: [Option<Child<M>>; 16] = Default::default();
        for (i, slot) in self.slots.iter_mut().enumerate() {
            if *slot != EMPTY {
                Self::own(slot);
                let s = core::mem::replace(slot, EMPTY);
                // SAFETY: owned slot
                out[i] = Some(unsafe { Box::from_raw(s as *mut Node<M>) });
            }
        }
        out.into_iter()
    }
}

impl<M: Memoization> Children<M> {
    #[inline]
    pub(super) fn memoize(&mut self) {
        // stwo: skip the call (and its large frame) for children that need
        // no work: digests and already memoized nodes, nearly all of them.
        for i in 0..16 {
            if let Some(child) = self.owned_mut(i) {
                match &*child {
                    Node::Null | Node::Digest(_) => {}
                    Node::Leaf(.., cache) | Node::Extension(.., cache) | Node::Branch(.., cache)
                        if cache.get().is_some() => {}
                    _ => child.memoize(),
                }
            }
        }
    }
}

impl<M, C: Into<Child<M>>, const N: usize> From<[(u8, C); N]> for Children<M> {
    fn from(arr: [(u8, C); N]) -> Self {
        let mut children = Children::default();
        for (idx, child) in arr {
            children.insert(idx, child.into());
        }
        children
    }
}
