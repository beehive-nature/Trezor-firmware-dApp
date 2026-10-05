//! Rust oracle for crypto/bpq/emu_xcheck.py.
//!
//! Reads the same input JSON as js-xcheck.mjs on stdin, plus the wallet's
//! binding as the JS oracle made it. bsigner never derives the SLH-DSA
//! succession key (bpq.rs says so), so here the device's succession
//! commitment is an input and the check is that the id recomputes from it.

// bpq.rs is compiled whole; the parts this oracle does not call (sealed
// objects) show up as dead-code warnings, and are left showing.
mod bpq {
    include!(concat!(env!("OUT_DIR"), "/bpq.rs"));
}
mod b64 {
    include!(concat!(env!("OUT_DIR"), "/b64.rs"));
}

use serde_json::Value;
use std::io::Read;

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
}

fn b64u(b: &[u8]) -> String {
    const A: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::new();
    for c in b.chunks(3) {
        let n = c.iter().enumerate().fold(0u32, |acc, (i, &x)| acc | (x as u32) << (16 - 8 * i));
        for i in 0..=c.len() {
            out.push(A[(n >> (18 - 6 * i) & 63) as usize] as char);
        }
    }
    out
}

fn unb64u(s: &str) -> Vec<u8> {
    let v = |c: u8| match c {
        b'A'..=b'Z' => c - b'A',
        b'a'..=b'z' => c - b'a' + 26,
        b'0'..=b'9' => c - b'0' + 52,
        b'-' => 62,
        b'_' => 63,
        _ => panic!("not base64url"),
    };
    let mut out = Vec::new();
    for c in s.as_bytes().chunks(4) {
        let n = c.iter().enumerate().fold(0u32, |acc, (i, &x)| acc | (v(x) as u32) << (18 - 6 * i));
        for i in 0..c.len() - 1 {
            out.push((n >> (16 - 8 * i)) as u8);
        }
    }
    out
}

fn main() {
    let mut s = String::new();
    std::io::stdin().read_to_string(&mut s).unwrap();
    let input: Value = serde_json::from_str(&s).unwrap();
    let card = &input["card"];
    let prk: [u8; 32] = unhex(input["prk"].as_str().unwrap()).try_into().unwrap();
    let ctx = input["context"].as_str().unwrap();
    let file = unhex(input["file_hex"].as_str().unwrap());

    let k = bpq::keys(&prk, ctx).expect("bsigner keys");
    let card_dsa = card["dsa"].as_str().unwrap();
    let card_succ = unb64u(card["succ"].as_str().unwrap());
    let mut checks: Vec<(&str, bool)> = vec![
        ("dsa_equal", b64u(&k.dsa_public) == card_dsa),
        ("kem_equal", b64u(&k.kem_public) == card["kem"].as_str().unwrap()),
        ("id_from_device_succ_equal", bpq::id_from(&k.dsa_public, &card_succ).as_deref() == card["id"].as_str()),
        ("verify_card_device", bpq::verify_card(card)),
        ("verify_bind_device", bpq::verify_bind(&input["binding"])),
        ("verify_detached_device", bpq::verify_detached(&input["detached"], &file).is_some()),
        ("verify_bind_wallet", bpq::verify_bind(&input["wallet_binding"])),
    ];
    let mut flipped = card.clone();
    let mut sig = unb64u(card["sig"].as_str().unwrap());
    sig[100] ^= 1;
    flipped["sig"] = Value::from(b64u(&sig));
    checks.push(("control_card_bitflip_refused", !bpq::verify_card(&flipped)));
    let mut longer = file.clone();
    longer.push(b'x');
    checks.push(("control_file_changed_refused", bpq::verify_detached(&input["detached"], &longer).is_none()));

    let ok = checks.iter().all(|(_, v)| *v);
    let obj: serde_json::Map<String, Value> =
        checks.iter().map(|(n, v)| (n.to_string(), Value::from(*v))).collect();
    println!(
        "{}",
        serde_json::json!({"oracle": "crates/bsigner/src/bpq.rs", "path": env!("BPQ_RS_PATH"), "checks": obj, "ok": ok})
    );
    std::process::exit(if ok { 0 } else { 1 });
}
