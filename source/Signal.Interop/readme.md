# Signal.Interop API Surface

This section documents the intended *public* API surface of this repository as implemented.

## C# (.NET 9) API (`Signal.Interop`)

Primary entrypoint:

- **`public static class SignalCrypto`**
    - **`public static int TestConnection()`**
        - Diagnostic call to verify native library loading and basic interop.

    - **`public static GroupSecretParamsSafeHandle GenerateGroupSecretParams(ReadOnlySpan<byte> randomness32)`**
        - Creates a new Groups V2 `GroupSecretParams` from exactly 32 bytes of randomness.
        - Throws `ArgumentException` if `randomness32.Length != 32`.

    - **`public static GroupMasterKeySafeHandle GetGroupMasterKey(GroupSecretParamsSafeHandle secretParams)`**
        - Extracts the `GroupMasterKey` from an existing `GroupSecretParams`.
        - Intended use: persisting group state across sessions.

    - **`public static GroupSecretParamsSafeHandle DeriveGroupSecretParams(GroupMasterKeySafeHandle masterKey)`**
        - Derives `GroupSecretParams` deterministically from a persisted `GroupMasterKey`.

    - **`public static byte[] SerializeGroupMasterKey(GroupMasterKeySafeHandle masterKey)`**
    - **`public static void SerializeGroupMasterKey(GroupMasterKeySafeHandle masterKey, Span<byte> buffer32)`**
        - Serializes a master key into exactly 32 bytes.
        - The `Span<byte>` overload is the allocation-free option.
        - Throws `ArgumentException` if the destination buffer length is not exactly 32.

    - **`public static GroupMasterKeySafeHandle DeserializeGroupMasterKey(ReadOnlySpan<byte> bytes32)`**
        - Reconstructs a master key handle from exactly 32 serialized bytes.
        - Throws `ArgumentException` if `bytes32.Length != 32`.
        - Throws `CryptographicException` if native deserialization fails.

SafeHandle types (opaque native ownership):

- **`public sealed class GroupSecretParamsSafeHandle : SafeHandle`**
- **`public sealed class GroupMasterKeySafeHandle : SafeHandle`**

### Usage notes (C#)

- **Ownership / lifetime**
    - Handles own native allocations.
    - Always dispose with `using` / `Dispose()` as soon as possible.
    - Finalizers exist as a backstop, but explicit disposal is the intended usage.

- **Persistence model**
    - Persist group state by storing **only** the 32-byte serialized `GroupMasterKey` in your encrypted local database.
    - On next launch:
        - `DeserializeGroupMasterKey(bytes32)`
        - `DeriveGroupSecretParams(masterKey)`

- **Threading**
    - The wrapper uses `DangerousAddRef`/`DangerousRelease` when passing handles to native code to prevent races with finalization.
    - Treat handle instances as normal reference types; avoid disposing while concurrently using them.

## Rust C-ABI exports (`signal_shim`)

These functions are exported from the native library and are consumed by the C# wrapper. They are not intended to be called directly from application code.

- **Diagnostics**
    - `int32 signal_shim_test_connection()`

- **Allocation / freeing (must be paired)**
    - `void signal_zkgroup_group_secret_params_free(void* secret_params)`
    - `void signal_zkgroup_group_master_key_free(void* master_key)`
        - Both perform secure wiping before freeing.

- **Groups V2 primitives**
    - `int32 signal_zkgroup_group_secret_params_generate(const uint8_t* randomness32, size_t randomness_len, void** out_secret_params)`
    - `int32 signal_zkgroup_group_secret_params_get_master_key(const void* secret_params, void** out_master_key)`
    - `int32 signal_zkgroup_group_secret_params_derive_from_master_key(const void* master_key, void** out_secret_params)`

- **GroupMasterKey persistence**
    - `int32 signal_zkgroup_group_master_key_serialize(const void* master_key, uint8_t* out_buffer, size_t buffer_len)`
        - Requires `buffer_len == 32`.
    - `int32 signal_zkgroup_group_master_key_deserialize(const uint8_t* bytes, size_t bytes_len, void** out_master_key)`
        - Requires `bytes_len == 32`.

### Usage notes (C-ABI)

- **Output contract**
    - On non-zero status, out pointers are set to null.
- **Panic handling**
    - All exported functions use `catch_unwind` and return status `2` if a panic is caught.
- **Status codes**
    - `0`: success
    - `1`: invalid argument
    - `2`: panic caught
    - `4`: deserialization failure