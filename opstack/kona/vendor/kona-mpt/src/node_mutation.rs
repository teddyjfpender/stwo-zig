//! Ownership-preserving trie collapse; no subtree cloning or temporary path Vecs.
use super::*;

impl TrieNode {
    pub(super) fn collapse_if_possible<F: TrieProvider, H: TrieHinter>(
        &mut self,
        fetcher: &F,
        hinter: &H,
    ) -> TrieNodeResult<()> {
        match self {
            Self::Extension { prefix, node } => {
                let new_prefix = match node.as_ref() {
                    Self::Extension { prefix: child, .. } | Self::Leaf { prefix: child, .. } => {
                        prefix.join(child)
                    }
                    Self::Empty => {
                        *self = Self::Empty;
                        return Ok(());
                    }
                    _ => return Ok(()),
                };
                let Self::Extension { node, .. } = core::mem::replace(self, Self::Empty) else {
                    unreachable!()
                };
                *self = match *node {
                    Self::Extension { node, .. } => Self::Extension {
                        prefix: new_prefix,
                        node,
                    },
                    Self::Leaf { value, .. } => Self::Leaf {
                        prefix: new_prefix,
                        value,
                    },
                    _ => unreachable!("collapse kind selected before ownership transfer"),
                };
            }
            Self::Branch { stack } => {
                // A second live child already rules out collapse. Do not build a
                // temporary Vec of mutable references just to count to two.
                let mut only = None;
                for (index, child) in stack.iter().enumerate() {
                    if matches!(child, Self::Empty) {
                        continue;
                    }
                    if only.is_some() {
                        return Ok(());
                    }
                    only = Some(index);
                }
                let Some(index) = only else {
                    return Ok(());
                };
                if let Self::Blinded { commitment } = &stack[index] {
                    // Keep provider/hint errors before ownership transfer, exactly
                    // as in the original algorithm.
                    hinter
                        .hint_trie_node(*commitment)
                        .map_err(|e| TrieNodeError::Provider(e.to_string()))?;
                    stack[index].unblind(fetcher)?;
                    return self.collapse_if_possible(fetcher, hinter);
                }
                let prefix = Nibbles::from_nibbles_unchecked([index as u8]);
                let child = core::mem::replace(&mut stack[index], Self::Empty);
                *self = match child {
                    Self::Leaf {
                        prefix: rest,
                        value,
                    } => Self::Leaf {
                        prefix: prefix.join(&rest),
                        value,
                    },
                    Self::Extension { prefix: rest, node } => Self::Extension {
                        prefix: prefix.join(&rest),
                        node,
                    },
                    child @ Self::Branch { .. } => Self::Extension {
                        prefix,
                        node: Box::new(child),
                    },
                    _ => unreachable!("nonempty revealed child selected above"),
                };
            }
            _ => {}
        }
        Ok(())
    }
}
