//! Operating-system randomness shared by generation and size selection.

use std::io;

/// Fills `bytes` from the operating-system random source.
///
/// Used for content seeds, temporary-file name suffixes, and seeding the
/// size-selection RNG. CAF randomness is not secret (seeds are stored in
/// headers), but the OS source guarantees distinct chains and seeds
/// across concurrent processes without shared state. Generation and
/// verification reach it through [`Env`](crate::env::Env), which a
/// mocked run replaces; [`SizeSpec::chooser`](crate::SizeSpec::chooser)
/// calls it directly, since deterministic size sequences already have
/// [`SizeChooser::from_fn`](crate::SizeChooser::from_fn).
pub(crate) fn fill(bytes: &mut [u8]) -> io::Result<()> {
    getrandom::fill(bytes).map_err(io::Error::other)
}

#[cfg(test)]
mod tests {
    use super::fill;

    #[test]
    fn arrays_are_filled_and_distinct() -> std::io::Result<()> {
        // 16 zero bytes from the OS source would signal a broken backend;
        // the odds of a false failure are 2^-128.
        let mut first = [0_u8; 16];
        let mut second = [0_u8; 16];
        fill(&mut first)?;
        fill(&mut second)?;
        assert_ne!(first, [0; 16]);
        assert_ne!(first, second);
        Ok(())
    }
}
