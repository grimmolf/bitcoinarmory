//! Shamir secret sharing as used by Armory fragmented backups
//! (`FiniteField`, `SplitSecret`, `ReconstructSecret`; `ArmoryUtils.py:2449-2636`, spec 02 §4).
//!
//! Armory puts the secret in the **leading** coefficient of the polynomial and derives the other
//! coefficients deterministically from the secret with an HMAC chain. Two fragment sets of the
//! same wallet made with different M share coefficients, which lets fragments from different
//! sets be combined (fixed upstream in goatpig 0.96.3). This module therefore:
//!
//! * reproduces [`split_legacy`] exactly, **for tests and verification only**;
//! * creates new sets with [`split_random`] (CSPRNG coefficients);
//! * reconstructs with [`reconstruct`], which works for both.

use num_bigint::{BigInt, Sign};
use num_integer::Integer;
use num_traits::{One, Zero};
use zeroize::Zeroizing;

use crate::hash::hash256;
use crate::hmac::hmac512;
use crate::{Error, Result, base58};

/// Prime field with a hard-coded prime just below `2^(8*nbytes)`.
#[derive(Debug, Clone)]
pub struct FiniteField {
    prime: BigInt,
}

pub type Matrix = Vec<Vec<BigInt>>;

impl FiniteField {
    pub fn new(nbytes: usize) -> Result<Self> {
        let offset: u32 = match nbytes {
            1 => 5,
            2 => 39,
            4 => 5,
            8 => 59,
            16 => 797,
            20 => 543,
            24 => 333,
            32 => 357,
            48 => 317,
            64 => 569,
            96 => 825,
            128 => 105,
            192 => 3453,
            256 => 1157,
            _ => return Err(Error::FiniteField("no prime for this width")),
        };
        let prime = (BigInt::one() << (8 * nbytes)) - BigInt::from(offset);
        Ok(Self { prime })
    }

    pub fn prime(&self) -> &BigInt {
        &self.prime
    }

    fn reduce(&self, v: BigInt) -> BigInt {
        v.mod_floor(&self.prime)
    }

    pub fn add(&self, a: &BigInt, b: &BigInt) -> BigInt {
        self.reduce(a + b)
    }

    pub fn subtract(&self, a: &BigInt, b: &BigInt) -> BigInt {
        self.reduce(a - b)
    }

    pub fn mult(&self, a: &BigInt, b: &BigInt) -> BigInt {
        self.reduce(a * b)
    }

    /// Right-to-left square-and-multiply, as in Armory.
    pub fn power(&self, a: &BigInt, b: &BigInt) -> BigInt {
        let mut result = BigInt::one();
        let mut a = a.clone();
        let mut b = b.clone();
        let two = BigInt::from(2);
        while b > BigInt::zero() {
            let (q, x) = b.div_mod_floor(&two);
            b = q;
            if !x.is_zero() {
                result = self.reduce(&result * &a);
            } else {
                result = self.reduce(result);
            }
            a = self.reduce(&a * &a);
        }
        result
    }

    /// `power(a, p-2)`; `powinv(0) == 0` without error, as in Armory.
    pub fn powinv(&self, a: &BigInt) -> BigInt {
        self.power(a, &(&self.prime - 2))
    }

    pub fn divide(&self, a: &BigInt, b: &BigInt) -> BigInt {
        self.mult(a, &self.powinv(b))
    }

    /// Drops row `r` and column `c`; an empty result for a non-square matrix.
    pub fn mtrx_rm_row_col(&self, m: &Matrix, r: usize, c: usize) -> Matrix {
        if m.len() != m[0].len() {
            return Vec::new();
        }
        m.iter()
            .enumerate()
            .filter(|(i, _)| *i != r)
            .map(|(_, row)| row.iter().enumerate().filter(|(j, _)| *j != c).map(|(_, v)| v.clone()).collect())
            .collect()
    }

    /// Laplace expansion along row 0. A 1x1 matrix returns its entry unreduced and a non-square
    /// matrix returns -1, both as in Armory.
    pub fn mtrx_det(&self, m: &Matrix) -> BigInt {
        if m.len() == 1 {
            return m[0][0].clone();
        }
        if m.len() != m[0].len() {
            return BigInt::from(-1);
        }
        let mut result = BigInt::zero();
        for i in 0..m.len() {
            let sign = if i % 2 == 1 { BigInt::from(-1) } else { BigInt::one() };
            let mult = &m[0][i] * sign;
            let sub = self.mtrx_det(&self.mtrx_rm_row_col(m, 0, i));
            result = self.add(&result, &self.mult(&mult, &sub));
        }
        result
    }

    pub fn mtrx_mult_vect(&self, m: &Matrix, v: &[BigInt]) -> Vec<BigInt> {
        let n = m[0].len();
        m.iter()
            .map(|row| {
                let sum: BigInt = (0..n).map(|j| self.mult(&row[j], &v[j])).sum();
                self.reduce(sum)
            })
            .collect()
    }

    pub fn mtrx_adjoint(&self, m: &Matrix) -> Matrix {
        let sz = m.len();
        (0..sz)
            .map(|i| {
                (0..sz)
                    .map(|j| {
                        let sign = if (i + j) % 2 == 1 { BigInt::from(-1) } else { BigInt::one() };
                        self.reduce(sign * self.mtrx_det(&self.mtrx_rm_row_col(m, j, i)))
                    })
                    .collect()
            })
            .collect()
    }

    /// Adjoint / determinant. A singular matrix yields the zero matrix (not an error), as in
    /// Armory.
    pub fn mtrx_inv(&self, m: &Matrix) -> Matrix {
        let det = self.mtrx_det(m);
        self.mtrx_adjoint(m).iter().map(|row| row.iter().map(|v| self.divide(v, &det)).collect()).collect()
    }
}

/// One share: `(x, y)`, both big-endian and `nbytes` wide.
#[derive(Clone, PartialEq, Eq)]
pub struct Fragment {
    pub x: Vec<u8>,
    pub y: Zeroizing<Vec<u8>>,
}

impl std::fmt::Debug for Fragment {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Fragment").field("x", &self.x).field("y", &"<redacted>").finish()
    }
}

fn to_fixed_be(v: &BigInt, nbytes: usize) -> Vec<u8> {
    let (_, bytes) = v.to_bytes_be();
    // Python's int_to_binary never truncates; values here are always < p < 2^(8*nbytes).
    let mut out = vec![0u8; nbytes.saturating_sub(bytes.len())];
    out.extend_from_slice(&bytes);
    out
}

fn check_split_args(ff: &FiniteField, a: &BigInt, needed: usize, pieces: usize) -> Result<()> {
    if a >= ff.prime() {
        return Err(Error::FiniteField("secret must be less than the field prime"));
    }
    if pieces < needed {
        return Err(Error::FiniteField("more pieces than needed are required"));
    }
    if needed <= 1 || needed > 8 {
        return Err(Error::FiniteField("between 2 and 8 fragments may be required"));
    }
    Ok(())
}

fn evaluate(ff: &FiniteField, a: &BigInt, coeffs: &[BigInt], needed: usize, x: &BigInt) -> BigInt {
    let mut out = ff.mult(a, &ff.power(x, &BigInt::from(needed - 1)));
    for (i, e) in (0..needed - 1).rev().enumerate() {
        let term = ff.mult(&coeffs[i], &ff.power(x, &BigInt::from(e)));
        out = ff.add(&out, &term);
    }
    out
}

fn split_with(
    secret: &[u8],
    needed: usize,
    pieces: usize,
    coeffs: &[BigInt],
    nbytes: usize,
) -> Result<Vec<Fragment>> {
    let ff = FiniteField::new(nbytes)?;
    let a = BigInt::from_bytes_be(Sign::Plus, secret);
    check_split_args(&ff, &a, needed, pieces)?;
    Ok((0..pieces)
        .map(|i| {
            let x = BigInt::from(i + 1);
            let y = evaluate(&ff, &a, coeffs, needed, &x);
            Fragment { x: to_fixed_be(&x, nbytes), y: Zeroizing::new(to_fixed_be(&y, nbytes)) }
        })
        .collect())
}

/// Armory's deterministic `SplitSecret` (x = 1..pieces). Use only to reproduce or verify legacy
/// fragments; new backups must use [`split_random`].
pub fn split_legacy(secret: &[u8], needed: usize, pieces: usize) -> Result<Vec<Fragment>> {
    let nbytes = secret.len();
    let mut last = Zeroizing::new(secret.to_vec());
    let mut coeffs = Vec::with_capacity(pieces + needed - 1);
    for _ in 0..pieces + needed - 1 {
        let h = hmac512(&last, b"splitsecrets");
        last = Zeroizing::new(h[..nbytes.min(64)].to_vec());
        // binary_to_int default: little-endian.
        coeffs.push(BigInt::from_bytes_le(Sign::Plus, &last));
    }
    split_with(secret, needed, pieces, &coeffs, nbytes)
}

/// Split with coefficients drawn from the OS CSPRNG (x = 1..pieces).
pub fn split_random(secret: &[u8], needed: usize, pieces: usize) -> Result<Vec<Fragment>> {
    use rand::RngCore;
    let nbytes = secret.len();
    let ff = FiniteField::new(nbytes)?;
    let mut rng = rand::rngs::OsRng;
    let coeffs: Vec<BigInt> = (0..needed.saturating_sub(1))
        .map(|_| {
            let mut buf = Zeroizing::new(vec![0u8; nbytes + 16]);
            rng.fill_bytes(&mut buf);
            BigInt::from_bytes_be(Sign::Plus, &buf).mod_floor(ff.prime())
        })
        .collect();
    split_with(secret, needed, pieces, &coeffs, nbytes)
}

/// `ReconstructSecret`: uses the first `needed` fragments. Duplicate x values produce an all-zero
/// result (as in Armory), so callers must check the result, e.g. against the wallet ID.
pub fn reconstruct(fragments: &[Fragment], needed: usize, nbytes: usize) -> Result<Zeroizing<Vec<u8>>> {
    if fragments.len() < needed || needed == 0 {
        return Err(Error::FiniteField("not enough fragments"));
    }
    let ff = FiniteField::new(nbytes)?;
    let mut m: Matrix = Vec::with_capacity(needed);
    let mut v = Vec::with_capacity(needed);
    for f in &fragments[..needed] {
        let x = BigInt::from_bytes_be(Sign::Plus, &f.x);
        m.push((0..needed).rev().map(|e| ff.power(&x, &BigInt::from(e))).collect());
        v.push(BigInt::from_bytes_be(Sign::Plus, &f.y));
    }
    let out = ff.mtrx_mult_vect(&ff.mtrx_inv(&m), &v);
    Ok(Zeroizing::new(to_fixed_be(&out[0], nbytes)))
}

/// `ComputeFragIDBase58(M, wltIDBin)`: e.g. `"2jCLhy"`.
pub fn fragment_set_id(m: u8, wallet_id_bin: &[u8; 6]) -> String {
    let mut data = wallet_id_bin.to_vec();
    data.extend_from_slice(&u32::from(m).to_be_bytes());
    format!("{}{}", m, base58::encode(&hash256(&data)[..4]))
}

/// The 8-byte fragment ID line: `M (| 0x80 if SecurePrint) || index+1 || wallet ID`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FragmentIdLine {
    pub m: u8,
    pub number: u8,
    pub wallet_id_bin: [u8; 6],
    pub secure_print: bool,
}

impl FragmentIdLine {
    pub fn to_bytes(&self) -> [u8; 8] {
        let mut b = [0u8; 8];
        b[0] = if self.secure_print { 0x80 + self.m } else { self.m };
        b[1] = self.number;
        b[2..].copy_from_slice(&self.wallet_id_bin);
        b
    }

    /// `ComputeFragIDLineHex(..., addSpaces=True)`: `"0201 bad4 ab48 0100"`.
    pub fn to_hex_spaced(&self) -> String {
        let h: String = self.to_bytes().iter().map(|b| format!("{b:02x}")).collect();
        (0..4).map(|i| &h[i * 4..(i + 1) * 4]).collect::<Vec<_>>().join(" ")
    }

    /// `ReadFragIDLineHex`.
    pub fn parse_hex(s: &str) -> Result<Self> {
        let compact: String = s.trim().chars().filter(|c| *c != ' ').collect();
        if compact.len() != 16 || !compact.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(Error::InvalidLength { expected: 16, got: compact.len() });
        }
        let b: Vec<u8> =
            (0..8).map(|i| u8::from_str_radix(&compact[2 * i..2 * i + 2], 16).unwrap()).collect();
        Ok(Self {
            m: b[0] & 0x7f,
            number: b[1],
            wallet_id_bin: b[2..8].try_into().unwrap(),
            secure_print: b[0] > 127,
        })
    }

    /// `"<set id>-#<n>"` as printed on the fragment.
    pub fn display_id(&self) -> String {
        format!("{}-#{}", fragment_set_id(self.m, &self.wallet_id_bin), self.number)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bi(v: i64) -> BigInt {
        BigInt::from(v)
    }

    fn mtrx(rows: &[&[i64]]) -> Matrix {
        rows.iter().map(|r| r.iter().map(|v| bi(*v)).collect()).collect()
    }

    // pytest/testSplitSecret.py:20-60
    #[test]
    fn finite_field_vectors() {
        let ff = FiniteField::new(1).unwrap();
        assert!(FiniteField::new(257).is_err());
        assert_eq!(ff.add(&bi(200), &bi(100)), bi(49));
        assert_eq!(ff.subtract(&bi(200), &bi(100)), bi(100));
        assert_eq!(ff.mult(&bi(200), &bi(100)), bi(171));
        assert_eq!(ff.divide(&bi(200), &bi(100)), bi(2));
        let m = mtrx(&[&[1, 2, 3], &[3, 4, 5], &[6, 7, 8]]);
        let m32 = mtrx(&[&[1, 2, 3], &[3, 4, 5]]);
        let m23 = mtrx(&[&[1, 2], &[3, 4], &[5, 6]]);
        assert_eq!(ff.mtrx_rm_row_col(&m, 1, 1), mtrx(&[&[1, 3], &[6, 8]]));
        assert!(ff.mtrx_rm_row_col(&m32, 1, 1).is_empty());
        assert_eq!(ff.mtrx_det(&mtrx(&[&[1]])), bi(1));
        assert_eq!(ff.mtrx_det(&m32), bi(-1));
        assert_eq!(ff.mtrx_det(&m), bi(0));
        let v = [bi(1), bi(2), bi(3)];
        assert_eq!(ff.mtrx_mult_vect(&m, &v), vec![bi(14), bi(26), bi(44)]);
        assert_eq!(ff.mtrx_mult_vect(&m32, &v), vec![bi(14), bi(26)]);
        assert_eq!(ff.mtrx_mult_vect(&m23, &v), vec![bi(5), bi(11), bi(17)]);
        assert_eq!(ff.mtrx_adjoint(&m), mtrx(&[&[248, 5, 249], &[6, 241, 4], &[248, 5, 249]]));
        assert_eq!(ff.mtrx_inv(&m), mtrx(&[&[0, 0, 0], &[0, 0, 0], &[0, 0, 0]]));
    }

    fn all_subsets(n: usize, k: usize) -> Vec<Vec<usize>> {
        (0u32..(1 << n))
            .filter(|b| b.count_ones() as usize == k)
            .map(|b| (0..n).filter(|i| b & (1 << i) != 0).collect())
            .collect()
    }

    // pytest/testSplitSecret.py:61-96 and pytest/testFragmentedBackup.py:50-82
    #[test]
    fn split_and_reconstruct_all_subsets() {
        let secret8 = [0u8, 1, 2, 3, 4, 5, 6, 7];
        let cases: Vec<(Vec<u8>, usize, usize)> = vec![
            (vec![0x9f], 2, 3),
            (vec![0x9f], 3, 5),
            (vec![0x9f], 4, 7),
            (vec![0x9f], 5, 9),
            (vec![0x9f], 6, 7),
            (vec![0x9f; 16], 3, 5),
            (vec![0x9f; 16], 7, 10),
            (secret8.to_vec(), 2, 3),
            (secret8.to_vec(), 3, 4),
            (secret8.to_vec(), 5, 7),
            (secret8.to_vec(), 8, 8),
            (secret8.to_vec(), 2, 12),
        ];
        for (secret, m, n) in cases {
            for split in [split_legacy, split_random] {
                let frags = split(&secret, m, n).unwrap();
                for subset in all_subsets(n, m).into_iter().take(40) {
                    let pick: Vec<Fragment> = subset.iter().map(|i| frags[*i].clone()).collect();
                    assert_eq!(*reconstruct(&pick, m, secret.len()).unwrap(), secret, "m={m} n={n}");
                }
            }
        }
    }

    #[test]
    fn split_errors() {
        let secret8 = [0u8, 1, 2, 3, 4, 5, 6, 7];
        assert!(split_legacy(&[0xff; 8], 2, 3).is_err()); // secret >= prime
        assert!(split_legacy(&secret8, 4, 3).is_err());
        assert!(split_legacy(&secret8, 9, 12).is_err());
        assert!(split_legacy(&secret8, 1, 12).is_err());
        let frags = split_legacy(&secret8, 3, 5).unwrap();
        assert_ne!(*reconstruct(&frags[..2], 2, 8).unwrap(), secret8);
    }

    // spec 02 §9.5 [port-generated, deterministic coefficients]
    #[test]
    fn legacy_split_vectors() {
        let f = split_legacy(&[0, 1, 2, 3, 4, 5, 6, 7], 2, 3).unwrap();
        let ys: Vec<String> = f.iter().map(|f| hex::encode(&*f.y)).collect();
        assert_eq!(ys, ["26b87337afdc8a0b", "26b9753ab3e19012", "26ba773db7e69619"]);
        assert_eq!(hex::encode(&f[2].x), "0000000000000003");
        let f = split_legacy(&[0x9f], 3, 5).unwrap();
        let pts: Vec<(u8, u8)> = f.iter().map(|f| (f.x[0], f.y[0])).collect();
        assert_eq!(pts, [(1, 0x19), (2, 0xa2), (3, 0x73), (4, 0x87), (5, 0xde)]);
    }

    /// The flaw that motivates restore-only legacy splitting: one fragment of a 2-of-N set plus
    /// two fragments of a 3-of-N set of the same secret reveal the secret.
    #[test]
    fn legacy_cross_set_leak() {
        let secret = [0x42u8; 32];
        let two = split_legacy(&secret, 2, 3).unwrap();
        let three = split_legacy(&secret, 3, 5).unwrap();
        let ff = FiniteField::new(32).unwrap();
        let p = ff.prime().clone();
        let int = |b: &[u8]| BigInt::from_bytes_be(Sign::Plus, b);
        // 2-of-N: y = a*x + c0. 3-of-N: y = a*x^2 + c0*x + c1. Unknowns a, c0, c1.
        let rows: Matrix = vec![
            vec![int(&two[0].x), BigInt::one(), BigInt::zero()],
            vec![ff.power(&int(&three[0].x), &bi(2)), int(&three[0].x), BigInt::one()],
            vec![ff.power(&int(&three[1].x), &bi(2)), int(&three[1].x), BigInt::one()],
        ];
        let v = vec![int(&two[0].y), int(&three[0].y), int(&three[1].y)];
        let sol = ff.mtrx_mult_vect(&ff.mtrx_inv(&rows), &v);
        assert_eq!(to_fixed_be(&sol[0].mod_floor(&p), 32), secret);
    }

    #[test]
    fn fragment_ids() {
        assert_eq!(fragment_set_id(3, &[0; 6]), "34ZFkPT");
        let wid: [u8; 6] = hex::decode("bad4ab480100").unwrap().try_into().unwrap();
        assert_eq!(fragment_set_id(2, &wid), "2jCLhy");
        let line = FragmentIdLine { m: 2, number: 1, wallet_id_bin: wid, secure_print: true };
        assert_eq!(line.to_hex_spaced(), "8201 bad4 ab48 0100");
        assert_eq!(FragmentIdLine::parse_hex("8201 bad4 ab48 0100").unwrap(), line);
        assert_eq!(line.display_id(), "2jCLhy-#1");
    }
}
