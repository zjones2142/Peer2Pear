# core/tests

GoogleTest-based unit + integration tests for `libpeer2pear-core`.

## Running

```bash
# One-time: reconfigure to pull in gtest via vcpkg
cmake -S . -B build

# Build + run everything:
cmake --build build --target test
# or: cd build && ctest --output-on-failure
```

Set `-DBUILD_TESTS=ON` (default on desktop) / `-DBUILD_TESTS=OFF` (iOS
and Android cross-compiles) at configure time.  The vcpkg manifest
feature `tests` is auto-activated when `BUILD_TESTS=ON`, so there's no
`brew install gtest` prereq.

## Layout

One binary per module.  Each source file is `test_<module>.cpp`, producing
an executable `test_<module>` that CMake auto-registers with `ctest` via
`gtest_discover_tests()` — individual test cases show up as separate
ctest items.

| File | Module | Tier | Cases |
|---|---|---|---|
| `test_crypto_engine.cpp` | Ed25519 / X25519 / XChaCha20-Poly1305 / HKDF / ML-KEM-768 / ML-DSA-65 / base64url / identity persistence | 1 (primitives) | 22 |
| `test_sqlcipher_db.cpp` | Vendored SQLCipher amalgamation — codec, multi-page, blobs with embedded NULs, NULL/error paths | 2 (storage) | 9 |
| `test_sealed_envelope.cpp` | Sealed-sender envelope (classical + hybrid PQ), AAD recipient binding, replay-id uniqueness, relay wrap/unwrap | 3 (envelope) | 10 |
| `test_ratchet_session.cpp` | Double Ratchet (classical + hybrid) — round-trip, DH-ratchet step, out-of-order delivery, replay, serialize, mismatched root | 4 (session) | 10 |
| `test_session_manager.cpp` | End-to-end Noise IK + ratchet (classical & hybrid PQ), pre-key offline queue, persistence across manager rebuild | 5 (manager) | 8 |
| `test_file_transfer.cpp` | Chunked file transfer — streaming hash, in-order + out-of-order reassembly, hash-mismatch discard, resumption via DB | 6 (files) | 8 |
| `test_e2e_two_clients.cpp` | Two ChatController instances routed through an in-process mock relay — full send → seal → relay → unseal → ratchet round-trip | 7 (E2E) | 4 |
| `test_c_api.cpp` | Public C FFI surface — H4 v5 passphrase path, identity persistence, wrong-passphrase rejection, arg validation | C API | 4 |

The Tier 1 suite includes an RFC 8032 §7.1 KAT for Ed25519 and asserts
the FIPS-203 public/ciphertext sizes for ML-KEM-768, so a regression that
swaps the hash or the parameter set fails loudly.  Tier 2 writes >1 page
of data before reopening so a codec that only decrypts the first page is
caught.

## Next up

All seven tiers are in.  Future additions beyond Tier 7 that would raise
the floor further:

- Additional KAT vectors (FIPS 203 / 204) for ML-KEM / ML-DSA.
- Group-chat end-to-end parity with the two-client harness.
- Fuzzing harness for `SealedEnvelope::unwrapFromRelay` and
  `handleFileEnvelope` (malformed inputs) — ASan + libFuzzer.
- Presence / cover-traffic observability tests against the mock relay.

## Conventions

- **No disk state between tests.**  Any file artifact goes under
  `std::filesystem::temp_directory_path()` with a randomized suffix and is
  removed at the end of the test.
- **No network.**  Tests that exercise the relay or P2P layer use
  in-memory mocks of `IWebSocket` / `IHttpClient`.
- **No globals except libsodium init.**  `sodium_init()` is called by
  `CryptoEngine`'s constructor (and defensively by SqlCipherDb tests);
  everything else is per-test.
- **Bytes == std::vector<uint8_t>.**  Never `QByteArray` — the test
  binaries are built with `WITH_QT_CORE=ON` (via the desktop configure)
  but shouldn't depend on Qt types themselves.

## Adding a new test binary

1. Drop `core/tests/test_<module>.cpp` in this directory.
2. Add one line to `core/tests/CMakeLists.txt`:
   ```
   peer2pear_add_test(test_<module>)
   ```
3. Reconfigure + build: `cmake --build build --target test`.
