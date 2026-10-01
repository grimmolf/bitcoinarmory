//! Output-descriptor checksums (BIP380).

const INPUT_CHARSET: &str =
    "0123456789()[],'/*abcdefgh@:$%{}IJKLMNOPQRSTUVWXYZ&+-.;<=>?!^_|~ijklmnopqrstuvwxyzABCDEFGH`#\"\\ ";
const CHECKSUM_CHARSET: &[u8] = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";

fn polymod(symbols: &[u64]) -> u64 {
    const GEN: [u64; 5] = [0xf5dee51989, 0xa9fdca3312, 0x1bab10e32d, 0x3706b1677a, 0x644d626ffd];
    let mut chk = 1u64;
    for v in symbols {
        let top = chk >> 35;
        chk = ((chk & 0x7ffffffff) << 5) ^ v;
        for (i, g) in GEN.iter().enumerate() {
            if (top >> i) & 1 == 1 {
                chk ^= g;
            }
        }
    }
    chk
}

/// The 8-character checksum, or `None` if the descriptor contains a character outside the set.
pub fn checksum(desc: &str) -> Option<String> {
    let mut symbols = Vec::new();
    let mut groups = Vec::new();
    for c in desc.chars() {
        let v = INPUT_CHARSET.find(c)? as u64;
        symbols.push(v & 31);
        groups.push(v >> 5);
        if groups.len() == 3 {
            symbols.push(groups[0] * 9 + groups[1] * 3 + groups[2]);
            groups.clear();
        }
    }
    match groups.len() {
        1 => symbols.push(groups[0]),
        2 => symbols.push(groups[0] * 3 + groups[1]),
        _ => {}
    }
    symbols.extend([0; 8]);
    let c = polymod(&symbols) ^ 1;
    Some((0..8).map(|i| CHECKSUM_CHARSET[((c >> (5 * (7 - i))) & 31) as usize] as char).collect())
}

/// `desc#checksum`.
pub fn with_checksum(desc: &str) -> String {
    format!("{desc}#{}", checksum(desc).expect("descriptor uses valid characters"))
}

#[cfg(test)]
mod tests {
    use super::*;

    // BIP380 test vectors
    #[test]
    fn vectors() {
        assert_eq!(with_checksum("raw(deadbeef)"), "raw(deadbeef)#89f8spxm");
        assert_eq!(
            with_checksum(
                "pk(xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8)"
            ),
            "pk(xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8)#axav5m0j"
        );
    }
}
