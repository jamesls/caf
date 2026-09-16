//! Shared fixed recipes and store assertions for library and production CLI tests.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use caf_format::{Digest, HEADER_SIZE, Header, hash_to_path};
use caf_store::{GenerationSeed, Verifier};
use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct Vectors {
    pub seed: String,
    pub recipes: Vec<Recipe>,
}

#[derive(Debug, Deserialize)]
pub struct Recipe {
    pub name: String,
    pub format: String,
    pub spec: String,
    pub sizes: Vec<u64>,
    pub chain_tip: String,
    pub all: String,
}

pub fn vectors() -> Vectors {
    serde_json::from_str(include_str!("generation-v3.json")).expect("valid generation vectors")
}

/// Includes every relative file path and byte, including metadata and stray temporaries.
pub fn snapshot(root: &Path) -> BTreeMap<PathBuf, Vec<u8>> {
    fn walk(root: &Path, dir: &Path, files: &mut BTreeMap<PathBuf, Vec<u8>>) {
        for entry in fs::read_dir(dir).expect("read store") {
            let path = entry.expect("entry").path();
            if path.is_dir() {
                walk(root, &path, files);
            } else {
                files.insert(
                    path.strip_prefix(root).expect("relative path").to_owned(),
                    fs::read(path).expect("read file"),
                );
            }
        }
    }
    let mut files = BTreeMap::new();
    walk(root, root, &mut files);
    files
}

/// Checks the chain in creation order, its content seeds, and both metadata outputs.
pub fn assert_store(root: &Path, recipe: &Recipe, seed: &GenerationSeed) {
    let files = snapshot(root);
    assert_eq!(
        files.len(),
        recipe.sizes.len() + 2,
        "{} {}",
        recipe.name,
        recipe.format
    );
    assert_eq!(
        fs::read_to_string(root.join(".metadata/all")).expect("aggregate"),
        recipe.all
    );
    let marker = root.join(".metadata/roots").join(&recipe.chain_tip);
    assert_eq!(fs::read(marker).expect("chain tip marker"), b"");
    let mut identity: Digest = recipe.chain_tip.parse().expect("chain tip");
    for (index, size) in recipe.sizes.iter().enumerate().rev() {
        let bytes = fs::read(hash_to_path(root, identity)).expect("chain file");
        assert_eq!(bytes.len() as u64, *size);
        let header = Header::parse(&bytes[..HEADER_SIZE]).expect("valid header");
        assert_eq!(header.content_seed(), seed.content_seed(index as u64));
        identity = header.parent();
    }
    assert_eq!(identity, Digest::ZERO);
    let report = Verifier::new(root)
        .verify()
        .expect("verify generated content and paths");
    assert!(report.success(), "{:?}", report.diagnostics());
}
