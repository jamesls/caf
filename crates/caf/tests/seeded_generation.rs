//! Golden CLI recipes; `CAF_RELEASE_BIN` selects the separately built production executable.

use std::path::PathBuf;
use std::process::Command;

use caf_store::GenerationSeed;

#[path = "../../../tests/golden/generation.rs"]
mod golden;

#[test]
fn complete_recipes_match_seeded_v3() {
    let binary = std::env::var_os("CAF_RELEASE_BIN")
        .map_or_else(|| PathBuf::from(env!("CARGO_BIN_EXE_caf")), PathBuf::from);
    let vectors = golden::vectors();
    let seed = GenerationSeed::new(&vectors.seed).expect("seed");
    for recipe in vectors.recipes {
        let mut serial = None;
        for jobs in ["1", "2"] {
            let root = tempfile::tempdir().expect("fresh store");
            let output = Command::new(&binary)
                .args([
                    "gen",
                    "--seed",
                    &vectors.seed,
                    "--format",
                    &recipe.format,
                    "--file-size",
                    &recipe.spec,
                    "--max-files",
                    &recipe.sizes.len().to_string(),
                    "--jobs",
                    jobs,
                    "--directory",
                ])
                .arg(root.path())
                .output()
                .expect("run selected CLI");
            assert!(
                output.status.success(),
                "{} {}: {}",
                recipe.name,
                recipe.format,
                String::from_utf8_lossy(&output.stderr)
            );
            assert!(output.stdout.is_empty());
            assert!(output.stderr.is_empty());
            golden::assert_store(root.path(), &recipe, &seed);
            let actual = golden::snapshot(root.path());
            if let Some(expected) = &serial {
                assert!(
                    expected == &actual,
                    "{} {} serial/parallel mismatch",
                    recipe.name,
                    recipe.format
                );
            } else {
                serial = Some(actual);
            }
        }
    }
}
