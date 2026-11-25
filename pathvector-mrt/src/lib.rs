//! pathvector-mrt library — MRT `TABLE_DUMP_V2` parsing and BGP UPDATE
//! construction, shared by the `pathvector-mrt` replay binary and the
//! `pathvector-loadtest` harness.

use std::path::Path;

pub mod mrt;
pub mod speaker;

use mrt::RibEntry;

/// Read and parse an MRT file, handling optional gzip compression (chosen by
/// the `.gz` extension).
///
/// # Errors
///
/// Returns an error if the file cannot be opened or is not valid MRT.
pub fn read_mrt(path: &Path) -> Result<Vec<RibEntry>, Box<dyn std::error::Error>> {
    let file = std::fs::File::open(path)?;
    let ext = path.extension().and_then(|s| s.to_str()).unwrap_or("");
    if ext == "gz" {
        Ok(mrt::parse(flate2::read::GzDecoder::new(file))?)
    } else {
        Ok(mrt::parse(std::io::BufReader::new(file))?)
    }
}
