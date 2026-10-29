// Fixtures for the attacker-controlled preallocation rules.
//
// These stand in for a binary protocol reader: a length prefix arrives first and
// the receiver sizes a buffer from it. The whole bug is the missing cap between
// those two steps.

use byteorder::{BigEndian, ReadBytesExt};
use bytes::Buf;
use std::cmp;
use std::collections::HashMap;
use std::io::{self, Read};

const MAX_FRAME: usize = 1 << 20;

// The four header bytes fully control a reservation of up to 4 GiB.
fn read_frame<R: Read>(mut r: R) -> io::Result<Vec<u8>> {
    let mut hdr = [0u8; 4];
    r.read_exact(&mut hdr)?;
    let n = u32::from_be_bytes(hdr) as usize;
    // ruleid: attacker-controlled-preallocation
    let mut buf = Vec::with_capacity(n);
    // ruleid: attacker-controlled-preallocation
    buf.resize(n, 0);
    r.read_exact(&mut buf)?;
    Ok(buf)
}

// Same defect reached through `reserve` on an existing buffer.
fn read_into<R: Read>(mut r: R, out: &mut Vec<u8>) -> io::Result<()> {
    let n = r.read_u32::<BigEndian>()? as usize;
    // ruleid: attacker-controlled-preallocation
    out.reserve(n);
    Ok(())
}

// A declared entry count sizes a map before any entry is parsed.
fn read_table<B: Buf>(mut b: B) -> HashMap<u32, u32> {
    let entries = b.get_u32() as usize;
    // ruleid: attacker-controlled-preallocation
    let map = HashMap::with_capacity(entries);
    map
}

// The zero-fill form: eager, and the pages are actually touched.
fn read_frame_macro<R: Read>(mut r: R) -> io::Result<Vec<u8>> {
    let mut hdr = [0u8; 4];
    r.read_exact(&mut hdr)?;
    let n = u32::from_be_bytes(hdr) as usize;
    // ruleid: attacker-controlled-preallocation-vec-macro
    let mut buf = vec![0u8; n];
    r.read_exact(&mut buf)?;
    Ok(buf)
}

fn read_frame_macro_cast<R: Read>(mut r: R) -> io::Result<Vec<u8>> {
    let len = r.read_u32::<BigEndian>()?;
    // ruleid: attacker-controlled-preallocation-vec-macro
    let mut buf = vec![0u8; len as usize];
    r.read_exact(&mut buf)?;
    Ok(buf)
}

// Capped with `min` before the allocation.
fn read_frame_capped<R: Read>(mut r: R) -> io::Result<Vec<u8>> {
    let mut hdr = [0u8; 4];
    r.read_exact(&mut hdr)?;
    let n = (u32::from_be_bytes(hdr) as usize).min(MAX_FRAME);
    // ok: attacker-controlled-preallocation
    // ok: attacker-controlled-preallocation-vec-macro
    let mut buf = vec![0u8; n];
    r.read_exact(&mut buf)?;
    Ok(buf)
}

// Rejected outright when the declared length exceeds the protocol maximum.
fn read_frame_rejected<R: Read>(mut r: R) -> io::Result<Vec<u8>> {
    let n = r.read_u32::<BigEndian>()? as usize;
    if n > MAX_FRAME {
        return Err(io::ErrorKind::InvalidData.into());
    }
    // ok: attacker-controlled-preallocation
    // ok: attacker-controlled-preallocation-vec-macro
    let mut buf = vec![0u8; n];
    r.read_exact(&mut buf)?;
    Ok(buf)
}

// Clamped through cmp::min.
fn read_frame_clamped<R: Read>(mut r: R) -> io::Result<Vec<u8>> {
    let declared = r.read_u32::<BigEndian>()? as usize;
    let n = cmp::min(declared, MAX_FRAME);
    // ok: attacker-controlled-preallocation
    // ok: attacker-controlled-preallocation-vec-macro
    let mut buf = Vec::with_capacity(n);
    buf.resize(n, 0);
    Ok(buf)
}

// No wire-controlled length anywhere: the capacity is a compile-time constant and
// the buffer grows only as bytes genuinely arrive.
fn read_frame_bounded<R: Read>(r: R) -> io::Result<Vec<u8>> {
    // ok: attacker-controlled-preallocation
    // ok: attacker-controlled-preallocation-vec-macro
    let mut buf = Vec::with_capacity(8192);
    r.take(MAX_FRAME as u64).read_to_end(&mut buf)?;
    Ok(buf)
}

// Sizing from a buffer already in memory is not attacker-amplified: the bytes
// were paid for before the allocation.
fn copy_payload(payload: &[u8]) -> Vec<u8> {
    // ok: attacker-controlled-preallocation
    // ok: attacker-controlled-preallocation-vec-macro
    let mut out = vec![0u8; payload.len()];
    out.copy_from_slice(payload);
    out
}

// A protocol maximum is idiomatically an associated or module constant, and the
// `$MAX` regex accepted a bare `MAX_FRAME` but not a path-qualified one -- so
// the bound was invisible and a correctly-capped allocation was reported.
pub struct PathQualified;

impl PathQualified {
    const MAX_FRAME: usize = 4096;

    pub fn read_assoc(&self, hdr: [u8; 4]) -> Vec<u8> {
        let n = u32::from_be_bytes(hdr) as usize;
        if n > Self::MAX_FRAME {
            return Vec::new();
        }
        // ok: attacker-controlled-preallocation
        Vec::with_capacity(n)
    }
}
