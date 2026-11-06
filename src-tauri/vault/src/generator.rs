//! Random passwords for new accounts.

use aes_gcm::aead::rand_core::RngCore;
use aes_gcm::aead::OsRng;

pub const DEFAULT_LENGTH: usize = 20;

// Characters that are easy to confuse (l, I, 1, O, 0) are left out, in case a
// password ever has to be read and typed by hand.
const GROUPS: [&[u8]; 4] = [
    b"abcdefghijkmnopqrstuvwxyz",
    b"ABCDEFGHJKLMNPQRSTUVWXYZ",
    b"23456789",
    b"!@#$%^&*-_=+?",
];

/// A password with at least one character from each group, because many sites
/// require that. `length` is raised to the number of groups if it's lower.
pub fn generate(length: usize) -> String {
    let all: Vec<u8> = GROUPS.concat();
    let length = length.max(GROUPS.len());

    let mut chars: Vec<u8> = GROUPS
        .iter()
        .map(|group| group[below(group.len())])
        .collect();
    while chars.len() < length {
        chars.push(all[below(all.len())]);
    }
    // Otherwise the required characters would always come first.
    for last in (1..chars.len()).rev() {
        chars.swap(last, below(last + 1));
    }
    chars.into_iter().map(char::from).collect()
}

/// A uniform random number below `limit`. Values past the largest multiple of
/// `limit` are redrawn, because keeping them would favour the low numbers.
fn below(limit: usize) -> usize {
    let limit = limit as u32;
    let zone = u32::MAX - (u32::MAX % limit);
    loop {
        let value = OsRng.next_u32();
        if value < zone {
            return (value % limit) as usize;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn has_the_requested_length_and_every_group() {
        for _ in 0..200 {
            let password = generate(DEFAULT_LENGTH);
            assert_eq!(password.len(), DEFAULT_LENGTH);
            for group in GROUPS {
                assert!(password.bytes().any(|c| group.contains(&c)), "{password}");
            }
        }
    }

    #[test]
    fn a_short_length_still_covers_every_group() {
        let password = generate(1);
        assert_eq!(password.len(), GROUPS.len());
        for group in GROUPS {
            assert!(password.bytes().any(|c| group.contains(&c)));
        }
    }

    #[test]
    fn passwords_do_not_repeat() {
        let seen: HashSet<String> = (0..1000).map(|_| generate(DEFAULT_LENGTH)).collect();
        assert_eq!(seen.len(), 1000);
    }

    #[test]
    fn required_characters_are_not_stuck_in_fixed_positions() {
        // Without the shuffle, the first character would always be lowercase.
        let first_is_lowercase = (0..300)
            .filter(|_| generate(DEFAULT_LENGTH).as_bytes()[0].is_ascii_lowercase())
            .count();
        assert!(first_is_lowercase < 250, "{first_is_lowercase} of 300");
    }

    #[test]
    fn every_character_is_used_about_equally() {
        let mut counts = [0u32; 256];
        for _ in 0..4000 {
            for byte in generate(DEFAULT_LENGTH).bytes() {
                counts[byte as usize] += 1;
            }
        }
        for group in GROUPS {
            for &c in group {
                assert!(counts[c as usize] > 0, "{} never appeared", c as char);
            }
        }
    }
}
