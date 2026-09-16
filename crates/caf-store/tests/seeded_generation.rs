//! Exact CAF v3 generation stores, independent of scheduling and destination directory.

use std::num::NonZeroUsize;

use caf_format::Format;
use caf_store::{GenerationSeed, Generator, SizeSpec};

#[path = "../../../tests/golden/generation.rs"]
mod golden;

#[test]
fn complete_recipes_match_seeded_v3() {
    let vectors = golden::vectors();
    let seed = GenerationSeed::new(&vectors.seed).expect("seed");
    for recipe in vectors.recipes {
        let spec: SizeSpec = recipe.spec.parse().expect("size spec");
        let mut serial = None;
        for jobs in [1, 2] {
            let root = tempfile::tempdir().expect("fresh store");
            assert_eq!(recipe.format, "v3");
            let report = Generator::builder(root.path())
                .seed(seed.clone())
                .file_sizes(spec.chooser_seeded(&seed))
                .format(Format::V3)
                .jobs(NonZeroUsize::new(jobs).expect("positive jobs"))
                .progress(|_| {})
                .max_files(recipe.sizes.len() as u64)
                .build()
                .generate()
                .expect("generation");
            assert_eq!(report.chain_tip().to_hex(), recipe.chain_tip);
            assert_eq!(report.all_digest().to_hex(), recipe.all);
            golden::assert_store(root.path(), &recipe, &seed);
            let actual = golden::snapshot(root.path());
            if let Some(expected) = &serial {
                // Avoid dumping megabytes of bytes on failure.
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
