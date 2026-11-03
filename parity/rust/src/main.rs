//! Звірка uacrypto з Rust-реалізаціями: ua-cryptography-*, RustCrypto kupyna, structured-dstu4145.
use std::collections::BTreeMap;
use std::io::{BufRead, BufReader, Write};

use kupyna::Digest;
use num_bigint::BigUint;
use structured_dstu4145::domain::Domain;
use structured_dstu4145::{Basis, ByteOrder};
use ua_cryptography_dstu4145::{decode_signature, encode_signature, get_polynomial_curve_by_index, Signer};
use ua_cryptography_dstu7564::{HashSize, Kupyna};
use ua_cryptography_gost::{Gost28147, Gost34311, DEFAULT_DKE};

const DEGREES: [usize; 10] = [163, 167, 173, 179, 191, 233, 257, 307, 367, 431];

fn h(s: &str) -> Vec<u8> {
    if s == "-" { vec![] } else { hex::decode(s).unwrap() }
}
fn x(b: &[u8]) -> String {
    if b.is_empty() { "-".into() } else { hex::encode(b) }
}
fn rev(b: &[u8]) -> Vec<u8> {
    b.iter().rev().copied().collect()
}
/// v little-endian in exactly `width` bytes, or None when it does not fit.
fn le(v: &BigUint, width: usize) -> Option<Vec<u8>> {
    let mut b = v.to_bytes_le();
    if b.len() > width {
        return None;
    }
    b.resize(width, 0);
    Some(b)
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let input = BufReader::new(std::fs::File::open(&args[1]).unwrap());
    let mut out = std::fs::File::create(&args[2]).unwrap();
    let mut stats: BTreeMap<String, (u32, u32)> = BTreeMap::new();
    let mut check = |what: &str, ok: bool, detail: &str| {
        let e = stats.entry(what.to_string()).or_default();
        if ok { e.0 += 1 } else { e.1 += 1; eprintln!("MISMATCH {what} {detail}") }
    };
    let sbox = Gost28147::expand_dke(&DEFAULT_DKE).unwrap();
    let sdke = structured_dstu4145::gost::Dke::new(&DEFAULT_DKE).unwrap();

    for line in input.lines() {
        let line = line.unwrap();
        let f: Vec<&str> = line.split(' ').collect();
        match f[0] {
            "H" => {
                let m = h(f[1]);
                let n = m.len().to_string();
                check("ua-cryptography-gost      gost34311", x(&Gost34311::calculate_hash(&m)) == f[2], &n);
                let mut sg = structured_dstu4145::gost::Gost34311::new(&sdke);
                sg.update(&m).unwrap();
                check("structured-dstu4145       gost34311", x(&sg.finalize()) == f[2], &n);
                for (bits, want) in [(256usize, f[3]), (384, f[4]), (512, f[5])] {
                    let ua = Kupyna::calculate_hash(&m, HashSize::from_bits(bits).unwrap());
                    check(&format!("ua-cryptography-dstu7564  kupyna{bits}"), x(&ua) == want, &n);
                    let rc = match bits {
                        256 => kupyna::Kupyna256::digest(&m).to_vec(),
                        384 => kupyna::Kupyna384::digest(&m).to_vec(),
                        _ => kupyna::Kupyna512::digest(&m).to_vec(),
                    };
                    check(&format!("RustCrypto kupyna         kupyna{bits}"), x(&rc) == want, &n);
                    let mut st = structured_dstu4145::hash::State::new(structured_dstu4145::hash::Hash::Kupyna((bits / 8) as u8)).unwrap();
                    st.update(&m).unwrap();
                    check(&format!("structured-dstu4145       kupyna{bits}"), x(st.finalize().as_ref()) == want, &n);
                }
            }
            "C" => {
                let mut c = Gost28147::new(&sbox).unwrap();
                c.set_key(&h(f[1]).try_into().unwrap());
                let ct = c.encrypt_block(&h(f[2]).try_into().unwrap());
                check("ua-cryptography-gost      gost28147", x(&ct) == f[3], &line);
                let back = c.decrypt_block(&ct);
                check("ua-cryptography-gost      gost28147 decrypt", x(&back) == f[2], &line);
            }
            "S" => {
                let id: usize = f[1].parse().unwrap();
                let tag = format!("curve {} #{}", f[1], f[2]);
                let params = get_polynomial_curve_by_index(id).unwrap();
                let mut signer = Signer::new(&params);
                let d = BigUint::from_bytes_be(&h(f[3]));
                let q = signer.calculate_public_key(&d).unwrap();
                check("ua-cryptography-dstu4145  public key from d", x(&params.curve().compress_to_bytes(&q).unwrap()) == f[4], &tag);
                let pk = params.curve().decompress_from_bytes(&h(f[4])).unwrap();
                check("ua-cryptography-dstu4145  decode Go key", params.curve().compress_to_bytes(&pk).unwrap() == h(f[4]), &tag);
                let hash = h(f[5]);
                let (r, s) = (BigUint::parse_bytes(f[6].as_bytes(), 16).unwrap(), BigUint::parse_bytes(f[7].as_bytes(), 16).unwrap());
                let accepted = match encode_signature(&r, &s, params.minimum_signature_bits()) {
                    // стандарт подає геш старшим байтом уперед, BC і uacrypto — як видав ГОСТ 34.311, тому розвертаємо
                    Ok(sig) => signer.verify_hash(&pk, &rev(&hash), &sig),
                    Err(_) => false, // r або s не вміщуються в половину D — підпис відхилено
                };
                check("ua-cryptography-dstu4145  verify Go signature", accepted, &tag);
                let own = signer.sign_hash(&d, &rev(&hash)).unwrap();
                let (r2, s2) = decode_signature(&own).unwrap();
                writeln!(out, "X ua-cryptography {} {} {} {} {}", f[1], f[4], f[5], r2.to_str_radix(16), s2.to_str_radix(16)).unwrap();

                // structured-dstu4145: ключ у кодуванні сертифіката BE, підпис r||s little-endian, як у ІІТ
                let domain = Domain::named(Basis::Polynomial, DEGREES[id]).unwrap();
                let width = domain.order_bits().div_ceil(8);
                match domain.public_key(&h(f[4]), ByteOrder::BigEndian) {
                    Ok(spk) => {
                        let accepted = match (le(&r, width), le(&s, width)) {
                            (Some(r), Some(s)) => spk.verify_prehash(&hash, &[r, s].concat(), ByteOrder::LittleEndian).unwrap_or(false),
                            _ => false, // r або s ширші за поле підпису — підпис відхилено
                        };
                        check("structured-dstu4145       verify Go signature (r||s LE)", accepted, &tag);
                    }
                    Err(e) => check("structured-dstu4145       decode Go key", false, &format!("{tag} {e:?}")),
                }
            }
            _ => {}
        }
    }
    let failed = stats.values().any(|(_, bad)| *bad > 0);
    for (k, (ok, bad)) in stats {
        println!("{k:<55} {ok:4} ok {bad} mismatch");
    }
    if failed {
        std::process::exit(1);
    }
}
