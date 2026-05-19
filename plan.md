# Findings (STEP 1: Code Discovery)

## Where `GroupMasterKey` is defined and generated

- **[Primary module]** `external/libsignal/rust/zkgroup/src/api/groups/group_params.rs`
  - **`pub struct GroupMasterKey`**
    - Definition: `#[derive(Copy, Clone, Serialize, Deserialize, Default)] pub struct GroupMasterKey { pub(crate) bytes: [u8; GROUP_MASTER_KEY_LEN], }`
    - Length constant: `GROUP_MASTER_KEY_LEN = 32` from `external/libsignal/rust/zkgroup/src/common/constants.rs`.
  - **`impl GroupMasterKey { pub fn new(bytes: [u8; GROUP_MASTER_KEY_LEN]) -> Self }`**
    - Simple wrapper that stores the bytes.

- **[Generation / derivation entrypoints]** `external/libsignal/rust/zkgroup/src/api/groups/group_params.rs`
  - **`impl GroupSecretParams`**
    - **`pub fn generate(randomness: RandomnessBytes) -> Self`**
      - Constructs a `Sho` with label:
        - `b"Signal_ZKGroup_20200424_Random_GroupSecretParams_Generate"`
      - Derives a master key by squeezing 32 bytes:
        - `let master_key = GroupMasterKey::new(sho.squeeze_as_array());`
      - Immediately derives all secret params from the master key:
        - `GroupSecretParams::derive_from_master_key(master_key)`

    - **`pub fn derive_from_master_key(master_key: GroupMasterKey) -> Self`**
      - Constructs a `Sho` with label:
        - `b"Signal_ZKGroup_20200424_GroupMasterKey_GroupSecretParams_DeriveFromMasterKey"`
      - Uses `master_key.bytes` as the absorbed seed material.
      - Derives the immediate sub-keys / parameters in this exact order:
        - **`group_id: GroupIdentifierBytes`** via `sho.squeeze_as_array()`
        - **`blob_key: AesKeyBytes`** via `sho.squeeze_as_array()`
        - **`uid_enc_key_pair: crypto::uid_encryption::KeyPair`** via `KeyPair::derive_from(sho.as_mut())`
        - **`profile_key_enc_key_pair: crypto::profile_key_encryption::KeyPair`** via `KeyPair::derive_from(sho.as_mut())`
      - Returns `GroupSecretParams { master_key, group_id, blob_key, uid_enc_key_pair, profile_key_enc_key_pair, reserved: Default::default() }`.

- **[Related public parameters]** `external/libsignal/rust/zkgroup/src/api/groups/group_params.rs`
  - **`pub struct GroupPublicParams`** contains:
    - `group_id` and public keys derived from the secret params’ keypairs.
  - **`pub fn get_public_params(&self) -> GroupPublicParams`** simply exposes:
    - `uid_enc_public_key: self.uid_enc_key_pair.public_key`
    - `profile_key_enc_public_key: self.profile_key_enc_key_pair.public_key`
    - `group_id: self.group_id`

## Supporting modules involved in derivation

- **SHO / PRF construction**
  - `external/libsignal/rust/zkgroup/src/common/sho.rs`
    - `pub struct Sho { internal_sho: poksho::ShoHmacSha256 }`
    - Provides `new(label, data)`, `squeeze_as_array`, and implements `AsMut<poksho::ShoHmacSha256>` used for chained derivations.

- **Byte type aliases**
  - `external/libsignal/rust/zkgroup/src/common/simple_types.rs`
    - `pub type RandomnessBytes = [u8; RANDOMNESS_LEN];` (where `RANDOMNESS_LEN = 32`)
    - `pub type GroupIdentifierBytes = [u8; GROUP_IDENTIFIER_LEN];` (where `GROUP_IDENTIFIER_LEN = 32`)
    - `pub type AesKeyBytes = [u8; AES_KEY_LEN];` (where `AES_KEY_LEN = 32`)

## Memory ownership & side-channel relevant observations (Rust-side)

- **[Ownership model]** For the core types involved in Group V2 master-key derivation:
  - `GroupMasterKey` is `Copy` and stores a fixed-size `[u8; 32]` inline.
  - `GroupSecretParams` / `GroupPublicParams` are also `Copy` and store their state inline (including nested keypair/public-key types).
  - The derivation functions return values by move (but values are `Copy`), meaning the code is fundamentally stack/value-oriented, with no explicit heap allocation in these constructors.

- **[No `unsafe`]** `external/libsignal/rust/zkgroup/src/lib.rs` declares `#![deny(unsafe_code)]`, so this crate is intended to be fully safe Rust.

- **[Error handling in the derivation path]**
  - The master key derivation functions **do not return `Result`**:
    - `GroupSecretParams::generate(...) -> Self`
    - `GroupSecretParams::derive_from_master_key(...) -> Self`
    - `GroupMasterKey::new(...) -> Self`
  - Some *downstream* operations from `GroupSecretParams` do return `Result<_, ZkGroupVerificationFailure>`, e.g.:
    - `decrypt_service_id(...) -> Result<libsignal_core::ServiceId, ZkGroupVerificationFailure>`
    - `decrypt_profile_key(...) -> Result<api::profiles::ProfileKey, ZkGroupVerificationFailure>`
    - `decrypt_blob(...) -> Result<Vec<u8>, ZkGroupVerificationFailure>`
  - `ZkGroupVerificationFailure` is defined in:
    - `external/libsignal/rust/zkgroup/src/common/errors.rs`
    - It is a `thiserror::Error` wrapper and is convertible from `zkcredential::VerificationFailure`.

## Security note: zeroization is not implied by these types

- The core key-bearing types involved in this plan are `Copy` and store bytes inline.
- Nothing in the code inspected here indicates automatic secure wiping on drop.
- Therefore, **zeroization must be explicitly enforced at the FFI boundary** for any heap-allocated wrappers (see Architecture section).

# Architecture (STEP 3: Proposed C-ABI boundary + .NET 9 wrapper)

## Goals and constraints

- **Only Groups V2 / `zkgroup`** initial focus.
- **Memory-safe boundary**: Rust owns Rust allocations; .NET uses safe handles and guarantees cleanup.
- **No field-by-field mapping**: use opaque pointers.
- **No Rust `Result` crossing ABI**: return status codes + out params.

## Rust/C-ABI design (no implementation yet)

### Opaque handle strategy

Even though `GroupMasterKey` / `GroupSecretParams` are `Copy` value types in Rust, the C-ABI surface should treat them as **opaque heap-allocated objects** to:

- avoid committing to layout/size in the ABI,
- keep future changes non-breaking,
- ensure managed code never receives secrets in a blittable/field-mapped form that it might accidentally pin/log/copy.

This also centralizes memory ownership in Rust, so we can enforce consistent destruction and wiping.

Proposed Rust-side object model across ABI:

- **`signal_zkgroup_group_master_key_t`** (opaque)
  - Internally: `Box<zkgroup::groups::GroupMasterKey>` (or equivalent path)

- **`signal_zkgroup_group_secret_params_t`** (opaque)
  - Internally: `Box<zkgroup::groups::GroupSecretParams>`

### Status codes

All exported functions return an `int32` status code:

- `0`: success
- non-zero: failure

Because the key generation/derivation path is infallible in Rust today, we still keep status codes for ABI uniformity and future-proofing.

Suggested minimal error code set:

- `1`: null pointer / invalid argument
- `2`: panic caught / unexpected failure (if using `catch_unwind` in the ABI layer)
- `3`: verification failure (for APIs that map `ZkGroupVerificationFailure`)
- `4`: deserialization failure (for APIs that map `ZkGroupDeserializationFailure`)

(We can refine once we inventory more zkgroup APIs.)

### ABI output contract (mandatory)

- On **success** (`status == 0`):
  - all required out-pointers must be set to non-null.
- On **failure** (`status != 0`):
  - all out-pointers must be set to null (never leave them uninitialized), and the caller must treat them as invalid.

### Proposed extern functions (signatures only, conceptual)

- **Construct from randomness**
  - `int32 signal_zkgroup_group_secret_params_generate(const uint8_t* randomness32, size_t randomness_len, void** out_secret_params)`

- **Extract master key**
  - `int32 signal_zkgroup_group_secret_params_get_master_key(const void* secret_params, void** out_master_key)`
  - Note: this would clone/copy the 32-byte master key into a new boxed object on the Rust side.

- **Derive secret params from master key**
  - `int32 signal_zkgroup_group_secret_params_derive_from_master_key(const void* master_key, void** out_secret_params)`

- **Get group ID**
  - `int32 signal_zkgroup_group_secret_params_get_group_id(const void* secret_params, uint8_t* out_buffer, size_t buffer_len)`
    - Requires `buffer_len == 32`.

- **Get blob key**
  - `int32 signal_zkgroup_group_secret_params_get_blob_key(const void* secret_params, uint8_t* out_buffer, size_t buffer_len)`
    - Requires `buffer_len == 32`.

- **Destructors (mandatory)**
  - `void signal_zkgroup_group_master_key_free(void* master_key)`
  - `void signal_zkgroup_group_secret_params_free(void* secret_params)`

### Secret handling and secure destruction (mandatory)

- Each `*_free` must:
  - validate the pointer (null is a no-op),
  - **securely wipe** the allocation contents before freeing.

Rationale: upstream Rust types in this area are `Copy` with inline byte storage, so we cannot assume `Drop` will wipe secrets.

### Panic/abort and side-channel considerations

- The ABI layer must avoid unwinding across the FFI boundary.
  - Plan: wrap exported entrypoints with `std::panic::catch_unwind` and convert to non-zero status.
  - On panic/error, ensure out-pointers are set to null.
  - Follow-up decision: in release builds, consider an **abort-on-panic** policy instead of catching, depending on your desired fail-closed posture.
- Avoid leaking secrets via error strings.
  - Plan: do not expose detailed error text by default; map to numeric codes.
- Keep inputs length-checked without data-dependent branching beyond basic validation.

### Recommended initial API surface

- **Do not expose `GroupMasterKey` to managed code initially**.
  - Prefer exposing only `GroupSecretParams` and any specific operations required by your wrapper.
  - Add a `GroupMasterKey` handle later only if you have a concrete need (e.g., persistence/serialization of a master key), and even then prefer a serialized, versioned format rather than raw bytes.

## C# .NET 9 wrapper design

### P/Invoke surface

- Use `[LibraryImport]` for the native exports.
- Use `nint`/`IntPtr` for opaque pointers.
- Return status codes as `int`.

For input buffers (e.g., `randomness32`), prefer passing `(byte* ptr, nuint len)` to native to avoid implicit allocations.

### SafeHandle-based ownership

- Define `SafeHandle` types:
  - `GroupMasterKeyHandle : SafeHandle`
  - `GroupSecretParamsHandle : SafeHandle`
- Each `SafeHandle` calls the corresponding native `*_free` in `ReleaseHandle()`.

### Managed API shape (conceptual)

- `static GroupSecretParams Generate(ReadOnlySpan<byte> randomness32)`
  - Validates `randomness32.Length == 32`.
  - Calls native `..._generate`.

Avoid exposing master keys as raw bytes or as a first-class managed object unless strictly required.

### Cleanup guarantees

- `SafeHandle` ensures cleanup even on exceptions and during finalization.
- Public managed wrappers should be `IDisposable` and delegate ownership to the underlying `SafeHandle`.

---

# Next step (STEP 4)

Please review this plan and confirm:

- Whether you agree with the recommendation to **not** expose `GroupMasterKey` in the initial C-ABI/managed wrapper.
- Whether you want an abort-on-panic policy (fail-closed) or a catch-and-return-error policy at the FFI boundary.

# Testing Strategy

This testing plan follows `source/unit-testing.md`:

- Tests are written **before** implementation (Red-Green-Refactor).
- Tests use **AAA** (Arrange, Act, Assert).
- Tests validate **public behavior/contracts**, not private fields or internal call order.
- Avoid over-mocking; prefer real value objects and deterministic test inputs.

## Rust (FFI boundary) unit tests

Tests will validate the C-ABI contract of the exported functions (status codes, out-pointer behavior, and safety when called with invalid inputs). These tests should run entirely within Rust, calling `extern "C"` functions directly.

### GroupSecretParams and GroupMasterKey creation

- `GenerateSecretParams_GivenValidRandomness_ReturnsNonNullHandle`
  - **Arrange**: a 32-byte randomness buffer.
  - **Act**: call `signal_zkgroup_group_secret_params_generate(..., &mut out)`.
  - **Assert**:
    - status `== 0`
    - `out != null`

- `GetMasterKey_GivenValidSecretParams_ReturnsNonNullMasterKeyHandle`
  - **Arrange**: a valid secret params handle.
  - **Act**: call `signal_zkgroup_group_secret_params_get_master_key(secret_params, &mut out_master_key)`.
  - **Assert**:
    - status `== 0`
    - `out_master_key != null`

- `DeriveSecretParamsFromMasterKey_RoundTripsGroupIdentifier`
  - **Arrange**:
    - generate secret params A
    - extract master key
    - derive secret params B from master key
  - **Act**: obtain public group identifier for A and B via public API exposure planned for the boundary (either a dedicated FFI accessor or a serialization round-trip depending on final ABI surface).
  - **Assert**: A’s group identifier == B’s group identifier.
  - Note: this asserts a stable *behavioral invariant* without inspecting private fields.

### GroupMasterKey serialization/deserialization

These tests validate the persistence requirement while staying black-box:

- `SerializeMasterKey_GivenValidHandle_WritesExpectedLength`
  - **Arrange**: a valid master key handle.
  - **Act**: call `signal_zkgroup_group_master_key_serialize(master_key, out_buf, out_len)` using the agreed ABI (two-call pattern recommended: query length, then fill buffer).
  - **Assert**:
    - status `== 0`
    - returned/required length is exactly 32 bytes (per `GROUP_MASTER_KEY_LEN`)

- `DeserializeMasterKey_GivenSerializedBytes_ReturnsHandle`
  - **Arrange**: 32-byte serialized master key bytes produced by `serialize`.
  - **Act**: call `signal_zkgroup_group_master_key_deserialize(bytes_ptr, bytes_len, &mut out_handle)`.
  - **Assert**:
    - status `== 0`
    - `out_handle != null`

- `SerializeDeserializeMasterKey_RoundTripStable`
  - **Arrange**: master key handle A.
  - **Act**:
    - serialize A to bytes
    - deserialize to handle B
    - (optionally) re-serialize B
  - **Assert**:
    - serialized bytes A == serialized bytes B (exact byte-for-byte equality)

### FFI boundary safety (nulls, invalid lengths)

These tests ensure the functions are defensive and follow the ABI output contract: **on failure, out-pointers must be null**.

- `GenerateSecretParams_GivenNullOutPointer_ReturnsInvalidArgument`
  - **Act**: call generate with `out_secret_params == null`.
  - **Assert**:
    - status `== 1`
    - no writes occur (cannot assert directly; we assert “no crash” + return code).

- `GenerateSecretParams_GivenWrongRandomnessLength_ReturnsInvalidArgumentAndNullOut`
  - **Arrange**: randomness buffer length != 32.
  - **Act**: call generate.
  - **Assert**:
    - status `== 1`
    - `out_secret_params == null`

- `DeserializeMasterKey_GivenWrongLength_ReturnsInvalidArgumentAndNullOut`
  - **Arrange**: bytes length != 32.
  - **Act**: call deserialize.
  - **Assert**:
    - status `== 1`
    - `out_handle == null`

- `FreeFunctions_AcceptNull_NoCrash`
  - **Act**: call `signal_zkgroup_group_master_key_free(null)` and `signal_zkgroup_group_secret_params_free(null)`.
  - **Assert**: no crash.

### Panic handling contract

- `PanicIsCaught_ReturnsStatus2AndNullOutPointers`
  - **Arrange**: an input configuration that intentionally triggers a panic in the shim layer (e.g., a test-only entrypoint or a guarded branch compiled only for tests).
  - **Act**: call the exported function.
  - **Assert**:
    - status `== 2`
    - out pointers are null

## C# (.NET 9 wrapper) unit tests

These tests validate the *managed public surface* and SafeHandle lifecycle without relying on internal fields.

### Happy paths

- `GroupSecretParams_Generate_With32BytesRandomness_ReturnsInstance`
  - **Arrange**: 32-byte randomness.
  - **Act**: call managed `Generate`.
  - **Assert**: returned object is not null and is usable for subsequent public operations.

- `GroupMasterKey_SerializeDeserialize_RoundTripsBytes`
  - **Arrange**:
    - generate secret params
    - get master key handle
  - **Act**:
    - serialize to `byte[]`
    - deserialize to a new master key
    - re-serialize
  - **Assert**: byte arrays are equal.

### Argument validation / boundary safety

- `Generate_WithWrongLengthRandomness_ThrowsArgumentException`
  - Asserts managed API rejects invalid input length before crossing into native.

- `DeserializeMasterKey_WithWrongLength_ThrowsArgumentException`
  - Asserts managed API rejects invalid byte length.

### Error mapping (status codes to managed exceptions)

- `NativeReturnsInvalidArgument_MapsToArgumentException`
  - **Arrange**: force an invalid-argument status (e.g., call into wrapper with invalid inputs that bypass managed validation in a dedicated test hook).
  - **Assert**: the managed exception type is stable and does not leak sensitive data.

- `NativePanicStatus2_MapsToCryptographicException`
  - **Arrange**: trigger panic path (paired with Rust test-only behavior).
  - **Assert**: wrapper throws a consistent exception type/message; no out handles are produced.

### Cleanup / secure destruction expectations

Directly proving memory wiping from managed code is not reliable (GC, allocator behavior, and OS paging). Instead we test the **observable contract**:

- `SafeHandle_Dispose_IsIdempotent`
  - Disposing twice does not throw and does not double-free.

- `SafeHandle_Finalizer_DoesNotCrash`
  - **Arrange**: allocate object without disposing.
  - **Act**: let it become eligible for GC, force collection.
  - **Assert**: process remains stable (no crash). This validates correct `SafeHandle` finalization wiring.

- `ConcurrentDispose_DoesNotCrash`
  - **Arrange**: a handle shared across tasks.
  - **Act**: race disposing from multiple threads.
  - **Assert**: no crash; wrapper enforces a single native free.

---

After these tests are planned, implementation will proceed strictly via Red-Green-Refactor (tests first), and no tests will assert internal Rust struct layout or private managed fields.
