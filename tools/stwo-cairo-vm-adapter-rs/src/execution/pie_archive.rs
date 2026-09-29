//! Bounded PIE decode with streamed memory, using the official cell decoder.

use anyhow::{Context, Result, ensure};
use cairo_vm::vm::runners::cairo_pie::{CairoPie, CairoPieMemory};
use serde::de::DeserializeOwned;
use std::collections::HashSet;
use std::io::{BufReader, Cursor, Read};

const MEMBERS: [&str; 5] = [
    "version.json",
    "metadata.json",
    "memory.bin",
    "additional_data.json",
    "execution_resources.json",
];
const MAX_MEMORY_BYTES: u64 = 1 << 30;
const MAX_METADATA_BYTES: u64 = 32 << 20;
const CELL_BYTES: usize = 40;

pub fn decode(bytes: &[u8]) -> Result<CairoPie> {
    let mut archive =
        zip::ZipArchive::new(Cursor::new(bytes)).context("invalid Cairo PIE zip archive")?;
    ensure!(
        archive.len() == MEMBERS.len(),
        "PIE archive must contain exactly the five canonical members"
    );
    let mut seen = HashSet::new();
    for index in 0..archive.len() {
        let file = archive.by_index(index)?;
        ensure!(
            MEMBERS.contains(&file.name()) && seen.insert(file.name().to_owned()),
            "invalid or repeated PIE member"
        );
        let limit = if file.name() == "memory.bin" {
            MAX_MEMORY_BYTES
        } else {
            MAX_METADATA_BYTES
        };
        ensure!(
            file.size() <= limit,
            "PIE member {} exceeds its size limit",
            file.name()
        );
    }
    let pie = CairoPie {
        version: json(&mut archive, "version.json")?,
        metadata: json(&mut archive, "metadata.json")?,
        memory: memory(&mut archive)?,
        additional_data: json(&mut archive, "additional_data.json")?,
        execution_resources: json(&mut archive, "execution_resources.json")?,
    };
    pie.run_validity_checks()
        .context("invalid Cairo PIE execution")?;
    Ok(pie)
}

fn json<T: DeserializeOwned>(
    archive: &mut zip::ZipArchive<Cursor<&[u8]>>,
    name: &str,
) -> Result<T> {
    let file = archive.by_name(name)?;
    let expected = file.size();
    let mut bytes = Vec::new();
    file.take(MAX_METADATA_BYTES + 1).read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() as u64 <= MAX_METADATA_BYTES && bytes.len() as u64 == expected,
        "PIE member {name} has invalid decoded length"
    );
    serde_json::from_slice(&bytes).with_context(|| format!("invalid PIE member {name}"))
}

fn memory(archive: &mut zip::ZipArchive<Cursor<&[u8]>>) -> Result<CairoPieMemory> {
    let file = archive.by_name("memory.bin")?;
    let expected = file.size();
    ensure!(
        expected % CELL_BYTES as u64 == 0,
        "invalid PIE memory cell length"
    );
    let mut reader = BufReader::with_capacity(256 << 10, file.take(MAX_MEMORY_BYTES + 1));
    let mut cells = Vec::new();
    cells.try_reserve_exact((expected / CELL_BYTES as u64).try_into()?)?;
    let mut buffer = [0_u8; CELL_BYTES * 4096];
    let mut total = 0_u64;
    loop {
        let mut used = 0;
        while used < buffer.len() {
            let count = reader.read(&mut buffer[used..])?;
            if count == 0 {
                break;
            }
            used += count;
        }
        total += used as u64;
        ensure!(
            total <= MAX_MEMORY_BYTES && total <= expected,
            "PIE memory exceeds its decoded length limit"
        );
        if used == 0 {
            break;
        }
        let decoded =
            CairoPieMemory::from_bytes(&buffer[..used]).context("invalid PIE memory cells")?;
        cells.extend(decoded.0);
    }
    ensure!(total == expected, "truncated PIE memory");
    Ok(CairoPieMemory(cells))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn archive(names: &[&str], broken_memory: bool) -> Vec<u8> {
        let fixture = include_bytes!("../../resources/fibonacci_pie.zip");
        let mut source = zip::ZipArchive::new(Cursor::new(fixture)).unwrap();
        let mut output = zip::ZipWriter::new(Cursor::new(Vec::new()));
        for name in names {
            let mut bytes = Vec::new();
            if let Ok(mut member) = source.by_name(name) {
                member.read_to_end(&mut bytes).unwrap();
            }
            if *name == "memory.bin" && broken_memory {
                bytes.pop();
            }
            output
                .start_file(*name, zip::write::FileOptions::default())
                .unwrap();
            output.write_all(&bytes).unwrap();
        }
        output.finish().unwrap().into_inner()
    }

    #[test]
    fn canonical_members_are_required_once_each() {
        assert!(decode(&archive(&MEMBERS, false)).is_ok());
        assert!(decode(&archive(&MEMBERS[..4], false)).is_err());
        let mut duplicate = MEMBERS;
        duplicate[4] = "version.json";
        assert!(decode(&archive(&duplicate, false)).is_err());
        let mut unknown = MEMBERS;
        unknown[4] = "../execution_resources.json";
        assert!(decode(&archive(&unknown, false)).is_err());
    }

    #[test]
    fn incomplete_memory_cells_are_rejected() {
        let error = decode(&archive(&MEMBERS, true)).unwrap_err();
        assert!(error.to_string().contains("memory cell length"));
    }
}
