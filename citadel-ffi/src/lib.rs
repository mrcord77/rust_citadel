// SPDX-License-Identifier: AGPL-3.0-or-later
//! citadel-ffi: C-compatible FFI for citadel-envelope
//!
//! Exposes citadel's post-quantum hybrid encryption to any language
//! that can call a C shared library: Java (JNA), C# (P/Invoke),
//! Go (cgo), Python (ctypes), Node.js (ffi-napi).
//!
//! Memory contract:
//! - Output buffers are allocated by citadel and returned via out-pointers.
//! - The CALLER must free every such buffer with citadel_free().
//! - Passing NULL to any function returns CITADEL_ERR_NULL.
//!
//! Error codes:
//!   0 = CITADEL_OK
//!   1 = CITADEL_ERR_NULL   (null pointer argument)
//!   2 = CITADEL_ERR_SEAL   (encryption failed)
//!   3 = CITADEL_ERR_OPEN   (decryption/authentication failed)
//!   4 = CITADEL_ERR_KEY    (invalid key bytes)
//!   5 = CITADEL_ERR_ALLOC  (memory allocation failed)

use std::alloc::{alloc, dealloc, Layout};
use std::slice;

use citadel_envelope::{Aad, Citadel, Context, PublicKey, SecretKey};

// ── Error codes ──────────────────────────────────────────────────────────────

pub const CITADEL_OK: i32 = 0;
pub const CITADEL_ERR_NULL: i32 = 1;
pub const CITADEL_ERR_SEAL: i32 = 2;
pub const CITADEL_ERR_OPEN: i32 = 3;
pub const CITADEL_ERR_KEY: i32 = 4;
pub const CITADEL_ERR_ALLOC: i32 = 5;

// ── Internal helpers ─────────────────────────────────────────────────────────

fn alloc_buf(size: usize) -> *mut u8 {
    if size == 0 {
        return std::ptr::NonNull::dangling().as_ptr();
    }
    let layout = match Layout::array::<u8>(size) {
        Ok(l) => l,
        Err(_) => return std::ptr::null_mut(),
    };
    unsafe { alloc(layout) }
}

fn write_output(data: &[u8], out_ptr: *mut *mut u8, out_len: *mut usize) -> i32 {
    let len = data.len();
    let buf = alloc_buf(len);
    if buf.is_null() {
        return CITADEL_ERR_ALLOC;
    }
    unsafe {
        std::ptr::copy_nonoverlapping(data.as_ptr(), buf, len);
        *out_ptr = buf;
        *out_len = len;
    }
    CITADEL_OK
}

// ── Public API ────────────────────────────────────────────────────────────────

/// Size of a serialized public key in bytes (1216).
#[no_mangle]
pub extern "C" fn citadel_public_key_bytes() -> usize {
    citadel_envelope::wire::KEM_PUBLIC_KEY_BYTES
}

/// Size of a serialized secret key in bytes (2432).
#[no_mangle]
pub extern "C" fn citadel_secret_key_bytes() -> usize {
    citadel_envelope::wire::KEM_SECRET_KEY_BYTES
}

/// Generate a new hybrid keypair.
/// Writes public key into *pk_out/*pk_len and secret key into *sk_out/*sk_len.
/// Caller must free both buffers with citadel_free().
#[no_mangle]
pub unsafe extern "C" fn citadel_keygen(
    pk_out: *mut *mut u8,
    pk_len: *mut usize,
    sk_out: *mut *mut u8,
    sk_len: *mut usize,
) -> i32 {
    if pk_out.is_null() || pk_len.is_null() || sk_out.is_null() || sk_len.is_null() {
        return CITADEL_ERR_NULL;
    }
    let engine = Citadel::new();
    let (pk, sk) = engine.generate_keypair();
    let rc = write_output(&pk.to_bytes(), pk_out, pk_len);
    if rc != CITADEL_OK {
        return rc;
    }
    write_output(&sk.to_bytes(), sk_out, sk_len)
}

/// Encrypt plaintext to a recipient public key.
/// Caller must free *ct_out with citadel_free(*ct_out, *ct_len_out).
#[no_mangle]
pub unsafe extern "C" fn citadel_seal(
    pk_ptr: *const u8,
    pk_len: usize,
    pt_ptr: *const u8,
    pt_len: usize,
    aad_ptr: *const u8,
    aad_len: usize,
    ctx_ptr: *const u8,
    ctx_len: usize,
    ct_out: *mut *mut u8,
    ct_len_out: *mut usize,
) -> i32 {
    if pk_ptr.is_null() || pt_ptr.is_null() || ct_out.is_null() || ct_len_out.is_null() {
        return CITADEL_ERR_NULL;
    }
    let pk_bytes = slice::from_raw_parts(pk_ptr, pk_len);
    let pk = match PublicKey::from_bytes(pk_bytes) {
        Ok(k) => k,
        Err(_) => return CITADEL_ERR_KEY,
    };
    let plaintext = slice::from_raw_parts(pt_ptr, pt_len);
    let aad_bytes = if aad_ptr.is_null() || aad_len == 0 {
        &[][..]
    } else {
        slice::from_raw_parts(aad_ptr, aad_len)
    };
    let ctx_bytes = if ctx_ptr.is_null() || ctx_len == 0 {
        &[][..]
    } else {
        slice::from_raw_parts(ctx_ptr, ctx_len)
    };
    let engine = Citadel::new();
    let ciphertext = match engine.seal(
        &pk,
        plaintext,
        &Aad::raw(aad_bytes),
        &Context::raw(ctx_bytes),
    ) {
        Ok(ct) => ct,
        Err(_) => return CITADEL_ERR_SEAL,
    };
    write_output(&ciphertext, ct_out, ct_len_out)
}

/// Decrypt a ciphertext using the recipient secret key.
/// Caller must free *pt_out with citadel_free(*pt_out, *pt_len_out).
#[no_mangle]
pub unsafe extern "C" fn citadel_open(
    sk_ptr: *const u8,
    sk_len: usize,
    ct_ptr: *const u8,
    ct_len: usize,
    aad_ptr: *const u8,
    aad_len: usize,
    ctx_ptr: *const u8,
    ctx_len: usize,
    pt_out: *mut *mut u8,
    pt_len_out: *mut usize,
) -> i32 {
    if sk_ptr.is_null() || ct_ptr.is_null() || pt_out.is_null() || pt_len_out.is_null() {
        return CITADEL_ERR_NULL;
    }
    let sk_bytes = slice::from_raw_parts(sk_ptr, sk_len);
    let sk = match SecretKey::from_bytes(sk_bytes) {
        Ok(k) => k,
        Err(_) => return CITADEL_ERR_KEY,
    };
    let ciphertext = slice::from_raw_parts(ct_ptr, ct_len);
    let aad_bytes = if aad_ptr.is_null() || aad_len == 0 {
        &[][..]
    } else {
        slice::from_raw_parts(aad_ptr, aad_len)
    };
    let ctx_bytes = if ctx_ptr.is_null() || ctx_len == 0 {
        &[][..]
    } else {
        slice::from_raw_parts(ctx_ptr, ctx_len)
    };
    let engine = Citadel::new();
    let plaintext = match engine.open(
        &sk,
        ciphertext,
        &Aad::raw(aad_bytes),
        &Context::raw(ctx_bytes),
    ) {
        Ok(pt) => pt,
        Err(_) => return CITADEL_ERR_OPEN,
    };
    write_output(&plaintext, pt_out, pt_len_out)
}

/// Free a buffer allocated by citadel_keygen, citadel_seal, or citadel_open.
/// Passing NULL is safe. Length must exactly match what was returned.
#[no_mangle]
pub unsafe extern "C" fn citadel_free(ptr: *mut u8, len: usize) {
    if ptr.is_null() || len == 0 {
        return;
    }
    if let Ok(layout) = Layout::array::<u8>(len) {
        dealloc(ptr, layout);
    }
}

/// Return a static C string describing an error code. Do NOT free the result.
#[no_mangle]
pub extern "C" fn citadel_error_string(code: i32) -> *const u8 {
    match code {
        CITADEL_OK => b"ok\0".as_ptr(),
        CITADEL_ERR_NULL => b"null pointer argument\0".as_ptr(),
        CITADEL_ERR_SEAL => b"encryption failed\0".as_ptr(),
        CITADEL_ERR_OPEN => b"decryption failed\0".as_ptr(),
        CITADEL_ERR_KEY => b"invalid key\0".as_ptr(),
        CITADEL_ERR_ALLOC => b"memory allocation failed\0".as_ptr(),
        _ => b"unknown error\0".as_ptr(),
    }
}
