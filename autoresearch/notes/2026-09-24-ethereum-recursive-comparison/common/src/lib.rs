#![no_std]
#[cfg(test)]
extern crate std;
pub trait Crypto {
    fn keccak(data: &[u8]) -> [u8; 32];
    fn recover(digest: &[u8; 32], r: &[u8; 32], s: &[u8; 32], parity: u8) -> Option<[u8; 64]>;
}
pub const MAX_INPUT: usize = 4096;
pub const MAX_BATCH: usize = 16;
const N: [u8; 32] = [
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe,
    0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b, 0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36, 0x41, 0x41,
];
const HALF: [u8; 32] = [
    0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0x5d, 0x57, 0x6e, 0x73, 0x57, 0xa4, 0x50, 0x1d, 0xdf, 0xe9, 0x2f, 0x46, 0x68, 0x1b, 0x20, 0xa0,
];
#[derive(Clone, Copy)]
struct Item<'a> {
    raw: &'a [u8],
    data: &'a [u8],
    list: bool,
}
fn item(input: &[u8]) -> Result<Item<'_>, ()> {
    let b = *input.first().ok_or(())?;
    let (offset, len, list) = match b {
        0..=0x7f => (0, 1, false),
        0x80..=0xb7 => (1, (b - 0x80) as usize, false),
        0xc0..=0xf7 => (1, (b - 0xc0) as usize, true),
        _ => {
            let list = b >= 0xf8;
            let k = (b - if list { 0xf7 } else { 0xb7 }) as usize;
            if k > 4 || input.len() <= k || input[1] == 0 {
                return Err(());
            }
            let mut len = 0usize;
            for &x in &input[1..=k] {
                len = len
                    .checked_mul(256)
                    .ok_or(())?
                    .checked_add(x as usize)
                    .ok_or(())?;
            }
            if len < 56 {
                return Err(());
            }
            (k + 1, len, list)
        }
    };
    let end = offset.checked_add(len).ok_or(())?;
    let raw = input.get(..end).ok_or(())?;
    let data = &raw[offset..];
    if !list && offset == 1 && len == 1 && data[0] < 0x80 {
        return Err(());
    }
    Ok(Item { raw, data, list })
}
fn integer(i: Item<'_>, max: usize) -> Result<(), ()> {
    if i.list || i.data.len() > max || i.data.first() == Some(&0) {
        Err(())
    } else {
        Ok(())
    }
}
fn scalar(i: Item<'_>) -> Result<[u8; 32], ()> {
    integer(i, 32)?;
    if i.data.is_empty() {
        return Err(());
    }
    let mut x = [0u8; 32];
    x[32 - i.data.len()..].copy_from_slice(i.data);
    if x >= N {
        return Err(());
    }
    Ok(x)
}
fn access_list(i: Item<'_>) -> Result<(), ()> {
    if !i.list {
        return Err(());
    }
    let mut rest = i.data;
    while !rest.is_empty() {
        let entry = item(rest)?;
        if !entry.list {
            return Err(());
        }
        let address = item(entry.data)?;
        if address.list || address.data.len() != 20 {
            return Err(());
        }
        let keys = item(&entry.data[address.raw.len()..])?;
        if !keys.list || address.raw.len() + keys.raw.len() != entry.data.len() {
            return Err(());
        }
        let mut k = keys.data;
        while !k.is_empty() {
            let key = item(k)?;
            if key.list || key.data.len() != 32 {
                return Err(());
            }
            k = &k[key.raw.len()..];
        }
        rest = &rest[entry.raw.len()..];
    }
    Ok(())
}
fn auth<C: Crypto>(tx: &[u8]) -> Result<([u8; 32], [u8; 20]), ()> {
    if tx.first() != Some(&2) || tx.len() > 1024 {
        return Err(());
    }
    let root = item(&tx[1..])?;
    if !root.list || root.raw.len() + 1 != tx.len() {
        return Err(());
    }
    let mut fields = [Item {
        raw: &[],
        data: &[],
        list: false,
    }; 12];
    let mut rest = root.data;
    for f in &mut fields {
        *f = item(rest)?;
        rest = &rest[f.raw.len()..];
    }
    if !rest.is_empty() {
        return Err(());
    }
    for (i, max) in [(0, 32), (1, 8), (2, 32), (3, 32), (4, 8), (6, 32), (9, 1)] {
        integer(fields[i], max)?;
    }
    if fields[5].list || ![0, 20].contains(&fields[5].data.len()) || fields[7].list {
        return Err(());
    }
    access_list(fields[8])?;
    let parity = fields[9].data.first().copied().unwrap_or(0);
    if parity > 1 {
        return Err(());
    }
    let r = scalar(fields[10])?;
    let s = scalar(fields[11])?;
    if s > HALF {
        return Err(());
    }
    let len: usize = fields[..9].iter().map(|f| f.raw.len()).sum();
    let mut signing = [0u8; 1028];
    signing[0] = 2;
    let start = if len < 56 {
        signing[1] = 0xc0 + len as u8;
        2
    } else if len < 256 {
        signing[1] = 0xf8;
        signing[2] = len as u8;
        3
    } else {
        signing[1] = 0xf9;
        signing[2] = (len >> 8) as u8;
        signing[3] = len as u8;
        4
    };
    signing[start..start + len].copy_from_slice(&root.data[..len]);
    let digest = C::keccak(&signing[..start + len]);
    let key = C::recover(&digest, &r, &s, parity).ok_or(())?;
    let kh = C::keccak(&key);
    let mut sender = [0u8; 20];
    sender.copy_from_slice(&kh[12..]);
    Ok((C::keccak(tx), sender))
}
/// Output: version:u32, count:u32, Keccak(input), ordered result commitment.
/// Error callers publish an all-zero output, outside the accepted version domain.
pub fn run<C: Crypto>(input: &[u8]) -> Result<[u8; 72], ()> {
    if input.len() > MAX_INPUT || input.len() < 4 {
        return Err(());
    }
    let n = u32::from_le_bytes(input[..4].try_into().map_err(|_| ())?) as usize;
    if n == 0 || n > MAX_BATCH {
        return Err(());
    }
    let mut rest = &input[4..];
    let mut result = C::keccak(b"stwo-zisk-eth-auth-v1");
    for _ in 0..n {
        if rest.len() < 4 {
            return Err(());
        }
        let len = u32::from_le_bytes(rest[..4].try_into().map_err(|_| ())?) as usize;
        let tx = rest.get(4..4usize.checked_add(len).ok_or(())?).ok_or(())?;
        let (hash, sender) = auth::<C>(tx)?;
        let mut preimage = [0u8; 84];
        preimage[..32].copy_from_slice(&result);
        preimage[32..64].copy_from_slice(&hash);
        preimage[64..].copy_from_slice(&sender);
        result = C::keccak(&preimage);
        rest = &rest[4 + len..];
    }
    if !rest.is_empty() {
        return Err(());
    }
    let mut out = [0u8; 72];
    out[..4].copy_from_slice(&1u32.to_le_bytes());
    out[4..8].copy_from_slice(&(n as u32).to_le_bytes());
    out[8..40].copy_from_slice(&C::keccak(input));
    out[40..].copy_from_slice(&result);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn reject_noncanonical_rlp_and_integer_encodings() {
        for b in [
            &[0x81, 0x01][..],
            &[0xb8, 1, 0x80],
            &[0xb9, 0, 56],
            &[0xf8, 1, 0x80],
        ] {
            assert!(item(b).is_err());
        }
        assert!(integer(item(&[0]).unwrap(), 32).is_err());
        assert!(integer(item(&[0x80]).unwrap(), 32).is_ok());
        assert!(integer(item(&[0xc0]).unwrap(), 32).is_err());
    }
    #[test]
    fn enforce_scalar_range_and_access_list_structure() {
        assert!(scalar(item(&[0x80]).unwrap()).is_err());
        let mut n = [0u8; 33];
        n[0] = 0xa0;
        n[1..].copy_from_slice(&N);
        assert!(scalar(item(&n).unwrap()).is_err());
        assert!(access_list(item(&[0xc0]).unwrap()).is_ok());
        assert!(access_list(item(&[0x80]).unwrap()).is_err());
        assert!(access_list(item(&[0xc1, 0x80]).unwrap()).is_err());
        let mut valid = std::vec![0xd7, 0xd6, 0x94];
        valid.extend([0u8; 20]);
        valid.push(0xc0);
        assert!(access_list(item(&valid).unwrap()).is_ok());
        valid.push(0x80);
        valid[0] += 1;
        assert!(access_list(item(&valid).unwrap()).is_err());
    }
}
