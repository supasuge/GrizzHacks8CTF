use aes::Aes256;
use cbc::Decryptor;
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Nonce,
};
use cipher::{block_padding::Pkcs7, BlockDecryptMut, KeyIvInit};
use sha2::{Digest, Sha256};
use std::fs;
use std::hint::black_box;
use std::io::{self, BufRead, BufReader, Write};
use std::net::{TcpListener, TcpStream};
use std::time::{Duration, Instant};
const LCG_A: u64 = 6364136223846793005;
const LCG_C: u64 = 1442695040888963407;
const LEAK_COUNT: usize = 8;
const KEY_ROUNDS: usize = 4;
const DECOY_SHA256: &str = "fd6ce68767dbdf5f55b0f711b4f5379f693a2f0dddc4f62dce7cf0f2f582d82f";
const DECOY_CT_HEX: &str = "7fbf9d5e0d9dc4b2d26ebf14220c96d269307d7d96fd41ee16a070e6a6ba1e50";
const ECHOES: [&str; LEAK_COUNT] = [
    "attitude controller ping",
    "star tracker fix",
    "fuel pressure poll",
    "thermal regulator tick",
    "comms heartbeat",
    "reaction wheel sync",
    "solar array query",
    "final telemetry mark",
];
type Aes256CbcDec = Decryptor<Aes256>;
fn lcg_next(state: u64) -> u64 {
    state.wrapping_mul(LCG_A).wrapping_add(LCG_C)
}
fn mix64(mut z: u64) -> u64 {
    z ^= z >> 30;
    z = z.wrapping_mul(0xbf58_476d_1ce4_e5b9);
    z ^= z >> 27;
    z = z.wrapping_mul(0x94d0_49bb_1331_11eb);
    z ^= z >> 31;
    z
}
fn derive_key(mut state: u64) -> [u8; 32] {
    let mut material = [0u8; KEY_ROUNDS * 8];
    for chunk in material.chunks_exact_mut(8) {
        state = lcg_next(state);
        chunk.copy_from_slice(&mix64(state).to_le_bytes());
    }
    Sha256::digest(material).into()
}
fn fill_random(buf: &mut [u8]) {
    let mut f = fs::File::open("/dev/urandom").expect("failed to open /dev/urandom");
    io::Read::read_exact(&mut f, buf).expect("failed to read /dev/urandom");
}
fn generate_seed() -> u64 {
    let mut buf = [0u8; 8];
    fill_random(&mut buf);
    u64::from_le_bytes(buf)
}
struct Session {
    leaks: [u64; LEAK_COUNT],
    nonce: [u8; 12],
    ciphertext: Vec<u8>,
}
fn new_session(flag: &[u8]) -> Session {
    let mut state = generate_seed();
    let mut leaks = [0u64; LEAK_COUNT];
    for leak in &mut leaks {
        state = lcg_next(state);
        *leak = state >> 16;
    }
    let key = derive_key(state);
    let mut nonce = [0u8; 12];
    fill_random(&mut nonce);
    let cipher = ChaCha20Poly1305::new((&key).into());
    let ct = cipher
        .encrypt(Nonce::from_slice(&nonce), flag)
        .expect("encryption failed");
    Session {
        leaks,
        nonce,
        ciphertext: ct,
    }
}
fn emit_puzzle<W: Write>(out: &mut W, session: &Session) -> io::Result<()> {
    writeln!(out, "== Orbital Salvage // Recovery Node 7 ==")?;
    writeln!(out)?;
    writeln!(
        out,
        "The guidance computer's PRNG was a 64-bit linear congruential engine."
    )?;
    writeln!(
        out,
        "It died mid-sequence. We pulled {} heartbeats from the telemetry",
        LEAK_COUNT
    )?;
    writeln!(
        out,
        "buffer, but radiation stripped the lower 16 bits from each word."
    )?;
    writeln!(out)?;
    for (i, leak) in session.leaks.iter().enumerate() {
        writeln!(out, "  echo[{i}]: 0x{leak:012x}  \u{2014} {}", ECHOES[i])?;
    }
    writeln!(out)?;
    writeln!(
        out,
        "After the final echo the engine turned {KEY_ROUNDS} more revolutions."
    )?;
    writeln!(
        out,
        "Each output was mixed through a bijective finalizer, concatenated"
    )?;
    writeln!(
        out,
        "(little-endian), and SHA-256 hashed to produce the 256-bit seal key."
    )?;
    writeln!(out)?;
    writeln!(out, "  nonce = {}", hex::encode(session.nonce))?;
    writeln!(out, "  sealed_token = {}", hex::encode(&session.ciphertext))?;
    writeln!(out, "  cipher = ChaCha20-Poly1305")?;
    writeln!(out)?;
    writeln!(out, "Unseal the token. Return it exactly.")?;
    writeln!(out, "operator_token>")?;
    out.flush()
}

fn tracer_pid_present() -> bool {
    let Ok(status) = fs::read_to_string("/proc/self/status") else {
        return false;
    };
    status
        .lines()
        .find(|line| line.starts_with("TracerPid:"))
        .and_then(|line| line.split(':').nth(1))
        .and_then(|n| n.trim().parse::<u32>().ok())
        .is_some_and(|pid| pid != 0)
}
fn timing_anomaly() -> bool {
    let start = Instant::now();
    let mut acc: u64 = 0;
    for i in 0..2_000_000u64 {
        acc = acc.wrapping_add(i.rotate_left((i & 31) as u32));
        black_box(acc);
    }
    black_box(acc);
    start.elapsed().as_millis() > 250
}
fn anti_debug_score() -> u32 {
    let mut score = 0;
    if tracer_pid_present() {
        score += 2;
    }
    if timing_anomaly() {
        score += 1;
    }
    score
}
fn fake_validate(input: &str) -> bool {
    hex::encode(Sha256::digest(input.as_bytes())) == DECOY_SHA256
}

#[allow(dead_code)]
fn decoy_crypto_path(input: &str) -> bool {
    let mut bogus_key = [0x41u8; 32];
    bogus_key[7] = 0x13;
    bogus_key[19] = 0x37;
    let iv = [0x24u8; 16];
    let ct = hex::decode(DECOY_CT_HEX).expect("decoy hex");
    let Ok(pt) =
        Aes256CbcDec::new((&bogus_key).into(), (&iv).into()).decrypt_padded_vec_mut::<Pkcs7>(&ct)
    else {
        return false;
    };
    match String::from_utf8(pt) {
        Ok(s) => s == input,
        Err(_) => false,
    }
}
fn run_session<R: BufRead, W: Write>(reader: &mut R, out: &mut W, flag: &str) -> io::Result<()> {
    let session = new_session(flag.as_bytes());
    let score = anti_debug_score();
    emit_puzzle(out, &session)?;
    if score > 0 {
        writeln!(
            out,
            "[warning] telemetry jitter detected; auxiliary recovery path loaded."
        )?;
        out.flush()?;
    }
    let mut input = String::new();
    reader.read_line(&mut input)?;
    let input = input.trim();
    if input == flag {
        writeln!(out, "ACCESS GRANTED")?;
        writeln!(out, "{flag}")?;
    } else if fake_validate(input) {
        writeln!(out, "partial recovery accepted")?;
        writeln!(
            out,
            "note: that token belongs to a dead relay, not this node"
        )?;
        writeln!(out, "decoy{{follow_the_real_prng_not_the_hash}}")?;
    } else {
        writeln!(out, "recovery failed")?;
    }
    out.flush()
}

fn handle_stdio(flag: &str) -> io::Result<()> {
    let stdin = io::stdin();
    let mut reader = stdin.lock();
    let stdout = io::stdout();
    let mut out = stdout.lock();
    run_session(&mut reader, &mut out, flag)
}

fn handle_client(stream: TcpStream, flag: &str) -> io::Result<()> {
    stream.set_read_timeout(Some(Duration::from_secs(30)))?;
    let reader_stream = stream.try_clone()?;
    let mut reader = BufReader::new(reader_stream);
    let mut out = stream;
    run_session(&mut reader, &mut out, flag)
}

fn serve(addr: &str, flag: &str) -> io::Result<()> {
    let listener = TcpListener::bind(addr)?;
    eprintln!("[*] listening on {addr}");
    for conn in listener.incoming() {
        match conn {
            Ok(stream) => {
                let flag = flag.to_string();
                std::thread::spawn(move || {
                    if let Err(err) = handle_client(stream, &flag) {
                        eprintln!("client error: {err}");
                    }
                });
            }
            Err(err) => eprintln!("accept error: {err}"),
        }
    }
    Ok(())
}

fn main() -> io::Result<()> {
    let flag = fs::read_to_string("flag.txt")
        .expect("flag.txt missing")
        .trim()
        .to_string();
    assert!(!flag.is_empty(), "flag.txt is empty");

    if let Ok(addr) = std::env::var("LISTEN_ADDR") {
        serve(&addr, &flag)
    } else {
        handle_stdio(&flag)
    }
}
