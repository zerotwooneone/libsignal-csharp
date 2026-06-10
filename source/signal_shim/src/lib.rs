// We include this to ensure the compiler actually downloads and links the Signal library,
// even if we aren't calling its specific cryptographic functions in this dummy test.
use core::ffi::c_void;
use std::panic::{AssertUnwindSafe, catch_unwind};
use zeroize::Zeroize;
use zkgroup::common::sho::Sho;
use zkgroup::common::simple_types::Timestamp;
use libsignal_core::{Aci, Pni};

/// `#[no_mangle]` is critical. It turns off Rust's name mangling so the compiled 
/// function retains the exact name "signal_shim_test_connection" in the exported DLL.
/// `extern "C"` forces the function to use the standard C calling convention.
#[no_mangle]
pub extern "C" fn signal_shim_test_connection() -> i32 {
    // A simple identifiable number to prove the .NET Interop successfully called this library
    42 
}

const STATUS_OK: i32 = 0;
const STATUS_INVALID_ARGUMENT: i32 = 1;
const STATUS_PANIC: i32 = 2;
const STATUS_VERIFICATION_FAILURE: i32 = 3;
const STATUS_DESERIALIZATION_FAILURE: i32 = 4;

const GROUP_MASTER_KEY_LEN: usize = 32;
const UUID_LEN: usize = 16;
const GROUP_SECRET_PARAMS_DERIVE_LABEL: &[u8] =
    b"Signal_ZKGroup_20200424_GroupMasterKey_GroupSecretParams_DeriveFromMasterKey";
const SERVER_GROUP_ID_DERIVE_LABEL: &[u8] =
    b"Signal_ZKGroup_20200424_GroupMasterKey_ServerGroupId_Derive";

type GroupMasterKey = zkgroup::groups::GroupMasterKey;
type GroupSecretParams = zkgroup::groups::GroupSecretParams;
type GroupPublicParams = zkgroup::groups::GroupPublicParams;

type ServerSecretParams = zkgroup::ServerSecretParams;
type ServerPublicParams = zkgroup::ServerPublicParams;

type AuthCredentialWithPniZkcResponse = zkgroup::api::auth::AuthCredentialWithPniZkcResponse;
type AuthCredentialWithPniZkc = zkgroup::api::auth::AuthCredentialWithPniZkc;
type AuthCredentialWithPniZkcPresentation = zkgroup::api::auth::AuthCredentialWithPniZkcPresentation;

// Protocol types for sender key distribution
type SenderKeyRecord = libsignal_protocol::SenderKeyRecord;
type SenderKeyDistributionMessage = libsignal_protocol::SenderKeyDistributionMessage;
type SenderKeyMessage = libsignal_protocol::SenderKeyMessage;
type ProtocolAddress = libsignal_protocol::ProtocolAddress;

// WARNING: This is only safe for flat, Copy types that do not own nested heap allocations.
// If upstream changes introduce fields like Vec/String (or any Drop-requiring ownership),
// wiping the raw bytes before drop would corrupt internal pointers and can cause leaks.
fn wipe_boxed_value<T: Copy>(ptr: *mut T) {
    if ptr.is_null() {
        return;
    }

    debug_assert!(
        !std::mem::needs_drop::<T>(),
        "wipe_boxed_value is only safe for Copy types that do not require Drop"
    );

    unsafe {
        let bytes = std::slice::from_raw_parts_mut(ptr.cast::<u8>(), std::mem::size_of::<T>());
        bytes.zeroize();
        drop(Box::from_raw(ptr));
    }
}

fn free_boxed_value<T>(ptr: *mut T) {
    if ptr.is_null() {
        return;
    }

    unsafe {
        drop(Box::from_raw(ptr));
    }
}

fn write_serialized_to_buffer<T: serde::Serialize>(value: &T, out_buffer: *mut u8, buffer_len: usize) -> i32 {
    if out_buffer.is_null() {
        return STATUS_INVALID_ARGUMENT;
    }

    let mut serialized = zkgroup::serialize(value);
    if buffer_len != serialized.len() {
        serialized.zeroize();
        return STATUS_INVALID_ARGUMENT;
    }

    unsafe {
        std::ptr::copy_nonoverlapping(serialized.as_ptr(), out_buffer, serialized.len());
    }

    serialized.zeroize();
    STATUS_OK
}

fn get_serialized_len<T: serde::Serialize>(value: &T, out_len: *mut usize) -> i32 {
    if out_len.is_null() {
        return STATUS_INVALID_ARGUMENT;
    }

    let mut serialized = zkgroup::serialize(value);
    let len = serialized.len();
    serialized.zeroize();

    unsafe {
        *out_len = len;
    }

    STATUS_OK
}

#[no_mangle]
pub extern "C" fn signal_zkgroup_group_secret_params_get_group_id(
    secret_params: *const c_void,
    out_buffer: *mut u8,
    buffer_len: usize,
) -> i32 {
    if secret_params.is_null() || out_buffer.is_null() || buffer_len != GROUP_MASTER_KEY_LEN {
        return STATUS_INVALID_ARGUMENT;
    }

    let result = catch_unwind(AssertUnwindSafe(|| {
        let params = unsafe { &*secret_params.cast::<GroupSecretParams>() };
        let group_id = params.get_group_identifier();
        unsafe {
            std::ptr::copy_nonoverlapping(group_id.as_ptr(), out_buffer, GROUP_MASTER_KEY_LEN);
        }
        STATUS_OK
    }));

    match result {
        Ok(code) => code,
        Err(_) => STATUS_PANIC,
    }
}

#[no_mangle]
pub extern "C" fn signal_zkgroup_group_secret_params_get_server_group_id(
    secret_params: *const c_void,
    out_buffer: *mut u8,
    buffer_len: usize,
) -> i32 {
    if secret_params.is_null() || out_buffer.is_null() || buffer_len != GROUP_MASTER_KEY_LEN {
        return STATUS_INVALID_ARGUMENT;
    }

    let result = catch_unwind(AssertUnwindSafe(|| {
        let params = unsafe { &*secret_params.cast::<GroupSecretParams>() };
        let master_key = params.get_master_key();
        let mut master_key_bytes = zkgroup::serialize(&master_key);
        if master_key_bytes.len() != GROUP_MASTER_KEY_LEN {
            master_key_bytes.zeroize();
            return STATUS_PANIC;
        }

        let mut sho = Sho::new(SERVER_GROUP_ID_DERIVE_LABEL, &master_key_bytes);
        let server_group_id: [u8; GROUP_MASTER_KEY_LEN] = sho.squeeze_as_array();

        unsafe {
            std::ptr::copy_nonoverlapping(server_group_id.as_ptr(), out_buffer, GROUP_MASTER_KEY_LEN);
        }

        master_key_bytes.zeroize();
        STATUS_OK
    }));

    match result {
        Ok(code) => code,
        Err(_) => STATUS_PANIC,
    }
}

#[no_mangle]
pub extern "C" fn signal_zkgroup_group_secret_params_get_public_params(
    secret_params: *const c_void,
    out_public_params: *mut *mut c_void,
) -> i32 {
    if out_public_params.is_null() {
        return STATUS_INVALID_ARGUMENT;
    }

    unsafe {
        *out_public_params = std::ptr::null_mut();
    }

    if secret_params.is_null() {
        return STATUS_INVALID_ARGUMENT;
    }

    let result = catch_unwind(AssertUnwindSafe(|| {
        let params = unsafe { &*secret_params.cast::<GroupSecretParams>() };
        let public_params = params.get_public_params();
        let boxed = Box::new(public_params);
        unsafe {
            *out_public_params = Box::into_raw(boxed).cast::<c_void>();
        }
        STATUS_OK
    }));

    match result {
        Ok(code) => code,
        Err(_) => {
            unsafe {
                *out_public_params = std::ptr::null_mut();
            }
            STATUS_PANIC
        }
    }
}

#[no_mangle]
pub extern "C" fn signal_zkgroup_group_public_params_free(public_params: *mut c_void) {
    wipe_boxed_value(public_params.cast::<GroupPublicParams>());
}

#[no_mangle]
pub extern "C" fn signal_zkgroup_group_public_params_get_serialized_len(
    public_params: *const c_void,
    out_len: *mut usize,
) -> i32 {
    if public_params.is_null() {
        return STATUS_INVALID_ARGUMENT;
    }

    let result = catch_unwind(AssertUnwindSafe(|| {
        let pp = unsafe { &*public_params.cast::<GroupPublicParams>() };
        get_serialized_len(pp, out_len)
    }));

    match result {
        Ok(code) => code,
        Err(_) => STATUS_PANIC,
    }
}

#[no_mangle]
pub extern "C" fn signal_zkgroup_group_public_params_serialize(
    public_params: *const c_void,
    out_buffer: *mut u8,
    buffer_len: usize,
) -> i32 {
    if public_params.is_null() {
        return STATUS_INVALID_ARGUMENT;
    }

    let result = catch_unwind(AssertUnwindSafe(|| {
        let pp = unsafe { &*public_params.cast::<GroupPublicParams>() };
        write_serialized_to_buffer(pp, out_buffer, buffer_len)
    }));

    match result {
        Ok(code) => code,
        Err(_) => STATUS_PANIC,
    }
}

#[no_mangle]
pub extern "C" fn signal_zkgroup_group_public_params_deserialize(
    bytes: *const u8,
    bytes_len: usize,
    out_public_params: *mut *mut c_void,
) -> i32 {
    if out_public_params.is_null() {
        return STATUS_INVALID_ARGUMENT;
    }

    unsafe {
        *out_public_params = std::ptr::null_mut();
    }

    if bytes.is_null() || bytes_len == 0 {
        return STATUS_INVALID_ARGUMENT;
    }

    let result = catch_unwind(AssertUnwindSafe(|| {
        let slice = unsafe { std::slice::from_raw_parts(bytes, bytes_len) };
        let pp: GroupPublicParams = match zkgroup::deserialize(slice) {
            Ok(v) => v,
            Err(_) => return STATUS_DESERIALIZATION_FAILURE,
        };

        let boxed = Box::new(pp);
        unsafe {
            *out_public_params = Box::into_raw(boxed).cast::<c_void>();
        }
        STATUS_OK
    }));

    match result {
        Ok(code) => code,
        Err(_) => {
            unsafe {
                *out_public_params = std::ptr::null_mut();
            }
            STATUS_PANIC
        }
    }
}

#[no_mangle]
pub extern "C" fn signal_zkgroup_server_secret_params_generate(
    randomness32: *const u8,
    randomness_len: usize,
    out_server_secret_params: *mut *mut c_void,
) -> i32 {
    if out_server_secret_params.is_null() {
        return STATUS_INVALID_ARGUMENT;
    }

    unsafe {
        *out_server_secret_params = std::ptr::null_mut();
    }

    if randomness32.is_null() || randomness_len != GROUP_MASTER_KEY_LEN {
        return STATUS_INVALID_ARGUMENT;
    }

    let result = catch_unwind(AssertUnwindSafe(|| {
        let randomness = unsafe {
            let slice = std::slice::from_raw_parts(randomness32, randomness_len);
            let Ok(arr) = <[u8; GROUP_MASTER_KEY_LEN]>::try_from(slice) else {
                return STATUS_INVALID_ARGUMENT;
            };
            arr
        };

        let params = ServerSecretParams::generate(randomness);
        let boxed = Box::new(params);
        unsafe {
            *out_server_secret_params = Box::into_raw(boxed).cast::<c_void>();
        }
        STATUS_OK
    }));

    match result {
        Ok(code) => code,
        Err(_) => {
            unsafe {
                *out_server_secret_params = std::ptr::null_mut();
            }
            STATUS_PANIC
        }
    }
}

#[no_mangle]
pub extern "C" fn signal_zkgroup_server_secret_params_free(server_secret_params: *mut c_void) {
    free_boxed_value(server_secret_params.cast::<ServerSecretParams>());
}

#[no_mangle]
pub extern "C" fn signal_zkgroup_server_public_params_free(server_public_params: *mut c_void) {
    free_boxed_value(server_public_params.cast::<ServerPublicParams>());
}

#[no_mangle]
pub extern "C" fn signal_zkgroup_server_secret_params_get_public_params(
    server_secret_params: *const c_void,
    out_server_public_params: *mut *mut c_void,
) -> i32 {
    if out_server_public_params.is_null() {
        return STATUS_INVALID_ARGUMENT;
    }

    unsafe {
        *out_server_public_params = std::ptr::null_mut();
    }

    if server_secret_params.is_null() {
        return STATUS_INVALID_ARGUMENT;
    }

    let result = catch_unwind(AssertUnwindSafe(|| {
        let params = unsafe { &*server_secret_params.cast::<ServerSecretParams>() };
        let public_params = params.get_public_params();
        let boxed = Box::new(public_params);
        unsafe {
            *out_server_public_params = Box::into_raw(boxed).cast::<c_void>();
        }
        STATUS_OK
    }));

    match result {
        Ok(code) => code,
        Err(_) => {
            unsafe {
                *out_server_public_params = std::ptr::null_mut();
            }
            STATUS_PANIC
        }
    }
}

#[no_mangle]
pub extern "C" fn signal_zkgroup_server_public_params_get_serialized_len(
    server_public_params: *const c_void,
    out_len: *mut usize,
) -> i32 {
    if server_public_params.is_null() {
        return STATUS_INVALID_ARGUMENT;
    }

    let result = catch_unwind(AssertUnwindSafe(|| {
        let sp = unsafe { &*server_public_params.cast::<ServerPublicParams>() };
        get_serialized_len(sp, out_len)
    }));

    match result {
        Ok(code) => code,
        Err(_) => STATUS_PANIC,
    }
}

#[no_mangle]
pub extern "C" fn signal_zkgroup_server_public_params_serialize(
    server_public_params: *const c_void,
    out_buffer: *mut u8,
    buffer_len: usize,
) -> i32 {
    if server_public_params.is_null() {
        return STATUS_INVALID_ARGUMENT;
    }

    let result = catch_unwind(AssertUnwindSafe(|| {
        let sp = unsafe { &*server_public_params.cast::<ServerPublicParams>() };
        write_serialized_to_buffer(sp, out_buffer, buffer_len)
    }));

    match result {
        Ok(code) => code,
        Err(_) => STATUS_PANIC,
    }
}

#[no_mangle]
pub extern "C" fn signal_zkgroup_server_public_params_deserialize(
    bytes: *const u8,
    bytes_len: usize,
    out_server_public_params: *mut *mut c_void,
) -> i32 {
    if out_server_public_params.is_null() {
        return STATUS_INVALID_ARGUMENT;
    }

    unsafe {
        *out_server_public_params = std::ptr::null_mut();
    }

    if bytes.is_null() || bytes_len == 0 {
        return STATUS_INVALID_ARGUMENT;
    }

    let result = catch_unwind(AssertUnwindSafe(|| {
        let slice = unsafe { std::slice::from_raw_parts(bytes, bytes_len) };
        let sp: ServerPublicParams = match zkgroup::deserialize(slice) {
            Ok(v) => v,
            Err(_) => return STATUS_DESERIALIZATION_FAILURE,
        };

        let boxed = Box::new(sp);
        unsafe {
            *out_server_public_params = Box::into_raw(boxed).cast::<c_void>();
        }
        STATUS_OK
    }));

    match result {
        Ok(code) => code,
        Err(_) => {
            unsafe {
                *out_server_public_params = std::ptr::null_mut();
            }
            STATUS_PANIC
        }
    }
}

#[no_mangle]
pub extern "C" fn signal_zkgroup_auth_credential_with_pni_response_free(response: *mut c_void) {
    free_boxed_value(response.cast::<AuthCredentialWithPniZkcResponse>());
}

#[no_mangle]
pub extern "C" fn signal_zkgroup_auth_credential_with_pni_free(credential: *mut c_void) {
    free_boxed_value(credential.cast::<AuthCredentialWithPniZkc>());
}

#[no_mangle]
pub extern "C" fn signal_zkgroup_auth_credential_with_pni_presentation_free(presentation: *mut c_void) {
    free_boxed_value(presentation.cast::<AuthCredentialWithPniZkcPresentation>());
}

#[no_mangle]
pub extern "C" fn signal_zkgroup_auth_credential_with_pni_issue_credential(
    aci_bytes: *const u8,
    aci_len: usize,
    pni_bytes: *const u8,
    pni_len: usize,
    redemption_time_epoch_seconds: u64,
    server_secret_params: *const c_void,
    randomness32: *const u8,
    randomness_len: usize,
    out_response: *mut *mut c_void,
) -> i32 {
    if out_response.is_null() {
        return STATUS_INVALID_ARGUMENT;
    }

    unsafe {
        *out_response = std::ptr::null_mut();
    }

    if aci_bytes.is_null() || pni_bytes.is_null() || aci_len != UUID_LEN || pni_len != UUID_LEN {
        return STATUS_INVALID_ARGUMENT;
    }
    if server_secret_params.is_null() {
        return STATUS_INVALID_ARGUMENT;
    }
    if randomness32.is_null() || randomness_len != GROUP_MASTER_KEY_LEN {
        return STATUS_INVALID_ARGUMENT;
    }

    let result = catch_unwind(AssertUnwindSafe(|| {
        let aci_arr = unsafe {
            let slice = std::slice::from_raw_parts(aci_bytes, aci_len);
            let Ok(arr) = <[u8; UUID_LEN]>::try_from(slice) else {
                return STATUS_INVALID_ARGUMENT;
            };
            arr
        };
        let pni_arr = unsafe {
            let slice = std::slice::from_raw_parts(pni_bytes, pni_len);
            let Ok(arr) = <[u8; UUID_LEN]>::try_from(slice) else {
                return STATUS_INVALID_ARGUMENT;
            };
            arr
        };
        let randomness = unsafe {
            let slice = std::slice::from_raw_parts(randomness32, randomness_len);
            let Ok(arr) = <[u8; GROUP_MASTER_KEY_LEN]>::try_from(slice) else {
                return STATUS_INVALID_ARGUMENT;
            };
            arr
        };

        let aci = Aci::from_uuid_bytes(aci_arr);
        let pni = Pni::from_uuid_bytes(pni_arr);
        let redemption_time = Timestamp::from_epoch_seconds(redemption_time_epoch_seconds);

        let params = unsafe { &*server_secret_params.cast::<ServerSecretParams>() };
        let response = AuthCredentialWithPniZkcResponse::issue_credential(aci, pni, redemption_time, params, randomness);
        let boxed = Box::new(response);
        unsafe {
            *out_response = Box::into_raw(boxed).cast::<c_void>();
        }
        STATUS_OK
    }));

    match result {
        Ok(code) => code,
        Err(_) => {
            unsafe {
                *out_response = std::ptr::null_mut();
            }
            STATUS_PANIC
        }
    }
}

#[no_mangle]
pub extern "C" fn signal_zkgroup_auth_credential_with_pni_response_receive(
    response: *const c_void,
    aci_bytes: *const u8,
    aci_len: usize,
    pni_bytes: *const u8,
    pni_len: usize,
    redemption_time_epoch_seconds: u64,
    server_public_params: *const c_void,
    out_credential: *mut *mut c_void,
) -> i32 {
    if out_credential.is_null() {
        return STATUS_INVALID_ARGUMENT;
    }

    unsafe {
        *out_credential = std::ptr::null_mut();
    }

    if response.is_null() || server_public_params.is_null() {
        return STATUS_INVALID_ARGUMENT;
    }
    if aci_bytes.is_null() || pni_bytes.is_null() || aci_len != UUID_LEN || pni_len != UUID_LEN {
        return STATUS_INVALID_ARGUMENT;
    }

    let result = catch_unwind(AssertUnwindSafe(|| {
        let aci_arr = unsafe {
            let slice = std::slice::from_raw_parts(aci_bytes, aci_len);
            let Ok(arr) = <[u8; UUID_LEN]>::try_from(slice) else {
                return STATUS_INVALID_ARGUMENT;
            };
            arr
        };
        let pni_arr = unsafe {
            let slice = std::slice::from_raw_parts(pni_bytes, pni_len);
            let Ok(arr) = <[u8; UUID_LEN]>::try_from(slice) else {
                return STATUS_INVALID_ARGUMENT;
            };
            arr
        };

        let aci = Aci::from_uuid_bytes(aci_arr);
        let pni = Pni::from_uuid_bytes(pni_arr);
        let redemption_time = Timestamp::from_epoch_seconds(redemption_time_epoch_seconds);

        let response_ref = unsafe { &*response.cast::<AuthCredentialWithPniZkcResponse>() };
        let public_params = unsafe { &*server_public_params.cast::<ServerPublicParams>() };

        let credential = match response_ref.clone().receive(aci, pni, redemption_time, public_params) {
            Ok(v) => v,
            Err(_) => return STATUS_VERIFICATION_FAILURE,
        };

        let boxed = Box::new(credential);
        unsafe {
            *out_credential = Box::into_raw(boxed).cast::<c_void>();
        }
        STATUS_OK
    }));

    match result {
        Ok(code) => code,
        Err(_) => {
            unsafe {
                *out_credential = std::ptr::null_mut();
            }
            STATUS_PANIC
        }
    }
}

#[no_mangle]
pub extern "C" fn signal_zkgroup_auth_credential_with_pni_present(
    credential: *const c_void,
    server_public_params: *const c_void,
    group_secret_params: *const c_void,
    randomness32: *const u8,
    randomness_len: usize,
    out_presentation: *mut *mut c_void,
) -> i32 {
    if out_presentation.is_null() {
        return STATUS_INVALID_ARGUMENT;
    }

    unsafe {
        *out_presentation = std::ptr::null_mut();
    }

    if credential.is_null() || server_public_params.is_null() || group_secret_params.is_null() {
        return STATUS_INVALID_ARGUMENT;
    }
    if randomness32.is_null() || randomness_len != GROUP_MASTER_KEY_LEN {
        return STATUS_INVALID_ARGUMENT;
    }

    let result = catch_unwind(AssertUnwindSafe(|| {
        let randomness = unsafe {
            let slice = std::slice::from_raw_parts(randomness32, randomness_len);
            let Ok(arr) = <[u8; GROUP_MASTER_KEY_LEN]>::try_from(slice) else {
                return STATUS_INVALID_ARGUMENT;
            };
            arr
        };

        let credential_ref = unsafe { &*credential.cast::<AuthCredentialWithPniZkc>() };
        let public_params = unsafe { &*server_public_params.cast::<ServerPublicParams>() };
        let group_secret = unsafe { &*group_secret_params.cast::<GroupSecretParams>() };

        let presentation = credential_ref.present(public_params, group_secret, randomness);
        let boxed = Box::new(presentation);
        unsafe {
            *out_presentation = Box::into_raw(boxed).cast::<c_void>();
        }
        STATUS_OK
    }));

    match result {
        Ok(code) => code,
        Err(_) => {
            unsafe {
                *out_presentation = std::ptr::null_mut();
            }
            STATUS_PANIC
        }
    }
}

#[no_mangle]
pub extern "C" fn signal_zkgroup_auth_credential_with_pni_presentation_verify(
    presentation: *const c_void,
    server_secret_params: *const c_void,
    group_public_params: *const c_void,
    redemption_time_epoch_seconds: u64,
) -> i32 {
    if presentation.is_null() || server_secret_params.is_null() || group_public_params.is_null() {
        return STATUS_INVALID_ARGUMENT;
    }

    let result = catch_unwind(AssertUnwindSafe(|| {
        let pres = unsafe { &*presentation.cast::<AuthCredentialWithPniZkcPresentation>() };
        let server = unsafe { &*server_secret_params.cast::<ServerSecretParams>() };
        let group_public = unsafe { &*group_public_params.cast::<GroupPublicParams>() };
        let redemption_time = Timestamp::from_epoch_seconds(redemption_time_epoch_seconds);

        match pres.verify(server, group_public, redemption_time) {
            Ok(_) => STATUS_OK,
            Err(_) => STATUS_VERIFICATION_FAILURE,
        }
    }));

    match result {
        Ok(code) => code,
        Err(_) => STATUS_PANIC,
    }
}

#[no_mangle]
pub extern "C" fn signal_zkgroup_group_secret_params_get_blob_key(
    secret_params: *const c_void,
    out_buffer: *mut u8,
    buffer_len: usize,
) -> i32 {
    if secret_params.is_null() || out_buffer.is_null() || buffer_len != GROUP_MASTER_KEY_LEN {
        return STATUS_INVALID_ARGUMENT;
    }

    let result = catch_unwind(AssertUnwindSafe(|| {
        let params = unsafe { &*secret_params.cast::<GroupSecretParams>() };

        let master_key = params.get_master_key();
        let mut master_key_bytes = zkgroup::serialize(&master_key);
        if master_key_bytes.len() != GROUP_MASTER_KEY_LEN {
            master_key_bytes.zeroize();
            return STATUS_PANIC;
        }

        let mut sho = Sho::new(GROUP_SECRET_PARAMS_DERIVE_LABEL, &master_key_bytes);
        let _group_id: [u8; GROUP_MASTER_KEY_LEN] = sho.squeeze_as_array();
        let mut blob_key: [u8; GROUP_MASTER_KEY_LEN] = sho.squeeze_as_array();

        unsafe {
            std::ptr::copy_nonoverlapping(blob_key.as_ptr(), out_buffer, GROUP_MASTER_KEY_LEN);
        }

        blob_key.zeroize();
        master_key_bytes.zeroize();

        STATUS_OK
    }));

    match result {
        Ok(code) => code,
        Err(_) => STATUS_PANIC,
    }
}

#[cfg(test)]
#[no_mangle]
pub extern "C" fn signal_zkgroup__test_only_panic(out_ptr: *mut *mut c_void) -> i32 {
    if out_ptr.is_null() {
        return STATUS_INVALID_ARGUMENT;
    }

    unsafe {
        *out_ptr = std::ptr::null_mut();
    }

    let result = catch_unwind(AssertUnwindSafe(|| {
        panic!("intentional panic for test");
    }));

    match result {
        Ok(_) => STATUS_OK,
        Err(_) => {
            unsafe {
                *out_ptr = std::ptr::null_mut();
            }
            STATUS_PANIC
        }
    }
}

#[no_mangle]
pub extern "C" fn signal_zkgroup_group_master_key_free(master_key: *mut c_void) {
    wipe_boxed_value(master_key.cast::<GroupMasterKey>());
}

#[no_mangle]
pub extern "C" fn signal_zkgroup_group_secret_params_free(secret_params: *mut c_void) {
    wipe_boxed_value(secret_params.cast::<GroupSecretParams>());
}

#[no_mangle]
pub extern "C" fn signal_zkgroup_group_secret_params_generate(
    randomness32: *const u8,
    randomness_len: usize,
    out_secret_params: *mut *mut c_void,
) -> i32 {
    if out_secret_params.is_null() {
        return STATUS_INVALID_ARGUMENT;
    }

    unsafe {
        *out_secret_params = std::ptr::null_mut();
    }

    if randomness32.is_null() || randomness_len != GROUP_MASTER_KEY_LEN {
        return STATUS_INVALID_ARGUMENT;
    }

    let result = catch_unwind(AssertUnwindSafe(|| {
        let randomness = unsafe {
            let slice = std::slice::from_raw_parts(randomness32, randomness_len);
            let Ok(arr) = <[u8; GROUP_MASTER_KEY_LEN]>::try_from(slice) else {
                return STATUS_INVALID_ARGUMENT;
            };
            arr
        };

        let params = GroupSecretParams::generate(randomness);
        let boxed = Box::new(params);
        unsafe {
            *out_secret_params = Box::into_raw(boxed).cast::<c_void>();
        }
        STATUS_OK
    }));

    match result {
        Ok(code) => code,
        Err(_) => {
            unsafe {
                *out_secret_params = std::ptr::null_mut();
            }
            STATUS_PANIC
        }
    }
}

#[no_mangle]
pub extern "C" fn signal_zkgroup_group_secret_params_get_master_key(
    secret_params: *const c_void,
    out_master_key: *mut *mut c_void,
) -> i32 {
    if out_master_key.is_null() {
        return STATUS_INVALID_ARGUMENT;
    }

    unsafe {
        *out_master_key = std::ptr::null_mut();
    }

    if secret_params.is_null() {
        return STATUS_INVALID_ARGUMENT;
    }

    let result = catch_unwind(AssertUnwindSafe(|| {
        let params = unsafe { &*secret_params.cast::<GroupSecretParams>() };
        let master_key = params.get_master_key();
        let boxed = Box::new(master_key);
        unsafe {
            *out_master_key = Box::into_raw(boxed).cast::<c_void>();
        }
        STATUS_OK
    }));

    match result {
        Ok(code) => code,
        Err(_) => {
            unsafe {
                *out_master_key = std::ptr::null_mut();
            }
            STATUS_PANIC
        }
    }
}

#[no_mangle]
pub extern "C" fn signal_zkgroup_group_secret_params_derive_from_master_key(
    master_key: *const c_void,
    out_secret_params: *mut *mut c_void,
) -> i32 {
    if out_secret_params.is_null() {
        return STATUS_INVALID_ARGUMENT;
    }

    unsafe {
        *out_secret_params = std::ptr::null_mut();
    }

    if master_key.is_null() {
        return STATUS_INVALID_ARGUMENT;
    }

    let result = catch_unwind(AssertUnwindSafe(|| {
        let mk = unsafe { &*master_key.cast::<GroupMasterKey>() };
        let params = GroupSecretParams::derive_from_master_key(*mk);
        let boxed = Box::new(params);
        unsafe {
            *out_secret_params = Box::into_raw(boxed).cast::<c_void>();
        }
        STATUS_OK
    }));

    match result {
        Ok(code) => code,
        Err(_) => {
            unsafe {
                *out_secret_params = std::ptr::null_mut();
            }
            STATUS_PANIC
        }
    }
}

#[no_mangle]
pub extern "C" fn signal_zkgroup_group_master_key_serialize(
    master_key: *const c_void,
    out_buffer: *mut u8,
    buffer_len: usize,
) -> i32 {
    if master_key.is_null() || out_buffer.is_null() || buffer_len != GROUP_MASTER_KEY_LEN {
        return STATUS_INVALID_ARGUMENT;
    }

    let result = catch_unwind(AssertUnwindSafe(|| {
        let mk = unsafe { &*master_key.cast::<GroupMasterKey>() };
        let mut serialized = zkgroup::serialize(mk);
        if serialized.len() != GROUP_MASTER_KEY_LEN {
            serialized.zeroize();
            return STATUS_PANIC;
        }
        unsafe {
            std::ptr::copy_nonoverlapping(serialized.as_ptr(), out_buffer, GROUP_MASTER_KEY_LEN);
        }
        serialized.zeroize();
        STATUS_OK
    }));

    match result {
        Ok(code) => code,
        Err(_) => STATUS_PANIC,
    }
}

#[no_mangle]
pub extern "C" fn signal_zkgroup_group_master_key_deserialize(
    bytes: *const u8,
    bytes_len: usize,
    out_master_key: *mut *mut c_void,
) -> i32 {
    if out_master_key.is_null() {
        return STATUS_INVALID_ARGUMENT;
    }

    unsafe {
        *out_master_key = std::ptr::null_mut();
    }

    if bytes.is_null() || bytes_len != GROUP_MASTER_KEY_LEN {
        return STATUS_INVALID_ARGUMENT;
    }

    let result = catch_unwind(AssertUnwindSafe(|| {
        let slice = unsafe { std::slice::from_raw_parts(bytes, bytes_len) };
        let mk: GroupMasterKey = match zkgroup::deserialize(slice) {
            Ok(v) => v,
            Err(_) => return STATUS_DESERIALIZATION_FAILURE,
        };

        let boxed = Box::new(mk);
        unsafe {
            *out_master_key = Box::into_raw(boxed).cast::<c_void>();
        }
        STATUS_OK
    }));

    match result {
        Ok(code) => code,
        Err(_) => {
            unsafe {
                *out_master_key = std::ptr::null_mut();
            }
            STATUS_PANIC
        }
    }
}

// SenderKeyRecord functions
#[no_mangle]
pub extern "C" fn signal_protocol_sender_key_record_new(out_record: *mut *mut c_void) -> i32 {
    if out_record.is_null() {
        return STATUS_INVALID_ARGUMENT;
    }

    unsafe {
        *out_record = std::ptr::null_mut();
    }

    let result = catch_unwind(AssertUnwindSafe(|| {
        // Note: Creating an empty SenderKeyRecord requires access to private libsignal APIs
        // (new_empty() is private, and protobuf structures are also private)
        // A proper implementation would require key material generation
        STATUS_PANIC
    }));

    match result {
        Ok(code) => code,
        Err(_) => STATUS_PANIC,
    }
}

#[no_mangle]
pub extern "C" fn signal_protocol_sender_key_record_free(record: *mut c_void) {
    free_boxed_value(record.cast::<SenderKeyRecord>());
}

#[no_mangle]
pub extern "C" fn signal_protocol_sender_key_record_serialize_len(
    record: *const c_void,
    out_len: *mut usize,
) -> i32 {
    if record.is_null() || out_len.is_null() {
        return STATUS_INVALID_ARGUMENT;
    }

    let result = catch_unwind(AssertUnwindSafe(|| {
        let rec = unsafe { &*record.cast::<SenderKeyRecord>() };
        let serialized = rec.serialize();
        let serialized_bytes = match serialized {
            Ok(v) => v,
            Err(_) => return STATUS_PANIC,
        };
        unsafe {
            *out_len = serialized_bytes.len();
        }
        STATUS_OK
    }));

    match result {
        Ok(code) => code,
        Err(_) => STATUS_PANIC,
    }
}

#[no_mangle]
pub extern "C" fn signal_protocol_sender_key_record_serialize(
    record: *const c_void,
    out_buffer: *mut u8,
    buffer_len: usize,
) -> i32 {
    if record.is_null() || out_buffer.is_null() {
        return STATUS_INVALID_ARGUMENT;
    }

    let result = catch_unwind(AssertUnwindSafe(|| {
        let rec = unsafe { &*record.cast::<SenderKeyRecord>() };
        let serialized = rec.serialize();
        let serialized_bytes = match serialized {
            Ok(v) => v,
            Err(_) => return STATUS_PANIC,
        };
        if buffer_len < serialized_bytes.len() {
            return STATUS_INVALID_ARGUMENT;
        }

        unsafe {
            std::ptr::copy_nonoverlapping(serialized_bytes.as_ptr(), out_buffer, serialized_bytes.len());
        }

        STATUS_OK
    }));

    match result {
        Ok(code) => code,
        Err(_) => STATUS_PANIC,
    }
}

#[no_mangle]
pub extern "C" fn signal_protocol_sender_key_record_deserialize(
    bytes: *const u8,
    bytes_len: usize,
    out_record: *mut *mut c_void,
) -> i32 {
    if out_record.is_null() {
        return STATUS_INVALID_ARGUMENT;
    }

    unsafe {
        *out_record = std::ptr::null_mut();
    }

    if bytes.is_null() || bytes_len == 0 {
        return STATUS_INVALID_ARGUMENT;
    }

    let result = catch_unwind(AssertUnwindSafe(|| {
        let slice = unsafe { std::slice::from_raw_parts(bytes, bytes_len) };
        let rec: SenderKeyRecord = match SenderKeyRecord::deserialize(slice) {
            Ok(v) => v,
            Err(_) => return STATUS_DESERIALIZATION_FAILURE,
        };

        let boxed = Box::new(rec);
        unsafe {
            *out_record = Box::into_raw(boxed).cast::<c_void>();
        }
        STATUS_OK
    }));

    match result {
        Ok(code) => code,
        Err(_) => {
            unsafe {
                *out_record = std::ptr::null_mut();
            }
            STATUS_PANIC
        }
    }
}

// SenderAddress functions
#[no_mangle]
pub extern "C" fn signal_protocol_sender_address_new(
    uuid_bytes: *const u8,
    uuid_len: usize,
    device_id: u32,
    out_address: *mut *mut c_void,
) -> i32 {
    if out_address.is_null() {
        return STATUS_INVALID_ARGUMENT;
    }

    unsafe {
        *out_address = std::ptr::null_mut();
    }

    if uuid_bytes.is_null() || uuid_len != UUID_LEN {
        return STATUS_INVALID_ARGUMENT;
    }

    let result = catch_unwind(AssertUnwindSafe(|| {
        let uuid_arr = unsafe {
            let slice = std::slice::from_raw_parts(uuid_bytes, uuid_len);
            let Ok(arr) = <[u8; UUID_LEN]>::try_from(slice) else {
                return STATUS_INVALID_ARGUMENT;
            };
            arr
        };

        let _aci = Aci::from_uuid_bytes(uuid_arr);
        let name = uuid::Uuid::from_bytes(uuid_arr).to_string();
        let device_id_obj = match libsignal_core::DeviceId::new(device_id as u8) {
            Ok(d) => d,
            Err(_) => return STATUS_INVALID_ARGUMENT,
        };
        let address = ProtocolAddress::new(name, device_id_obj);
        let boxed = Box::new(address);
        unsafe {
            *out_address = Box::into_raw(boxed).cast::<c_void>();
        }
        STATUS_OK
    }));

    match result {
        Ok(code) => code,
        Err(_) => STATUS_PANIC,
    }
}

#[no_mangle]
pub extern "C" fn signal_protocol_sender_address_free(address: *mut c_void) {
    free_boxed_value(address.cast::<ProtocolAddress>());
}

// SenderKeyDistributionMessage functions
#[no_mangle]
pub extern "C" fn signal_protocol_sender_key_distribution_message_free(message: *mut c_void) {
    free_boxed_value(message.cast::<SenderKeyDistributionMessage>());
}

#[no_mangle]
pub extern "C" fn signal_protocol_sender_key_distribution_message_serialize_len(
    message: *const c_void,
    out_len: *mut usize,
) -> i32 {
    if message.is_null() || out_len.is_null() {
        return STATUS_INVALID_ARGUMENT;
    }

    let result = catch_unwind(AssertUnwindSafe(|| {
        let msg = unsafe { &*message.cast::<SenderKeyDistributionMessage>() };
        let serialized = msg.serialized();
        unsafe {
            *out_len = serialized.len();
        }
        STATUS_OK
    }));

    match result {
        Ok(code) => code,
        Err(_) => STATUS_PANIC,
    }
}

#[no_mangle]
pub extern "C" fn signal_protocol_sender_key_distribution_message_serialize(
    message: *const c_void,
    out_buffer: *mut u8,
    buffer_len: usize,
) -> i32 {
    if message.is_null() || out_buffer.is_null() {
        return STATUS_INVALID_ARGUMENT;
    }

    let result = catch_unwind(AssertUnwindSafe(|| {
        let msg = unsafe { &*message.cast::<SenderKeyDistributionMessage>() };
        let serialized = msg.serialized();
        if buffer_len < serialized.len() {
            return STATUS_INVALID_ARGUMENT;
        }

        unsafe {
            std::ptr::copy_nonoverlapping(serialized.as_ptr(), out_buffer, serialized.len());
        }

        STATUS_OK
    }));

    match result {
        Ok(code) => code,
        Err(_) => STATUS_PANIC,
    }
}

#[no_mangle]
pub extern "C" fn signal_protocol_sender_key_distribution_message_deserialize(
    bytes: *const u8,
    bytes_len: usize,
    out_message: *mut *mut c_void,
) -> i32 {
    if out_message.is_null() {
        return STATUS_INVALID_ARGUMENT;
    }

    unsafe {
        *out_message = std::ptr::null_mut();
    }

    if bytes.is_null() || bytes_len == 0 {
        return STATUS_INVALID_ARGUMENT;
    }

    let result = catch_unwind(AssertUnwindSafe(|| {
        let slice = unsafe { std::slice::from_raw_parts(bytes, bytes_len) };
        let msg: SenderKeyDistributionMessage = match SenderKeyDistributionMessage::try_from(slice) {
            Ok(v) => v,
            Err(_) => return STATUS_DESERIALIZATION_FAILURE,
        };

        let boxed = Box::new(msg);
        unsafe {
            *out_message = Box::into_raw(boxed).cast::<c_void>();
        }
        STATUS_OK
    }));

    match result {
        Ok(code) => code,
        Err(_) => {
            unsafe {
                *out_message = std::ptr::null_mut();
            }
            STATUS_PANIC
        }
    }
}

#[no_mangle]
pub extern "C" fn signal_protocol_sender_key_distribution_message_create(
    sender_address: *const c_void,
    distribution_id_bytes: *const u8,
    distribution_id_len: usize,
    record: *const c_void,
    out_message: *mut *mut c_void,
) -> i32 {
    if out_message.is_null() {
        return STATUS_INVALID_ARGUMENT;
    }

    unsafe {
        *out_message = std::ptr::null_mut();
    }

    if sender_address.is_null() || record.is_null() {
        return STATUS_INVALID_ARGUMENT;
    }
    if distribution_id_bytes.is_null() || distribution_id_len != UUID_LEN {
        return STATUS_INVALID_ARGUMENT;
    }

    let result = catch_unwind(AssertUnwindSafe(|| {
        // Note: The actual libsignal API for creating SenderKeyDistributionMessage
        // requires chain keys and signing keys which are complex to generate.
        // For now, this is a placeholder that returns an error.
        // In a real implementation, you would need to extract chain keys from the SenderKeyRecord
        // and generate appropriate signing keys.
        STATUS_PANIC
    }));

    match result {
        Ok(code) => code,
        Err(_) => {
            unsafe {
                *out_message = std::ptr::null_mut();
            }
            STATUS_PANIC
        }
    }
}

#[no_mangle]
pub extern "C" fn signal_protocol_sender_key_distribution_message_process(
    sender_address: *const c_void,
    message: *const c_void,
    record: *const c_void,
) -> i32 {
    if sender_address.is_null() || message.is_null() || record.is_null() {
        return STATUS_INVALID_ARGUMENT;
    }

    let result = catch_unwind(AssertUnwindSafe(|| {
        // Note: Processing a distribution message requires updating the SenderKeyRecord
        // with chain keys from the message. This is complex and requires more API knowledge.
        // For now, this is a placeholder.
        STATUS_PANIC
    }));

    match result {
        Ok(code) => code,
        Err(_) => STATUS_PANIC,
    }
}

// SenderKeyMessage functions
#[no_mangle]
pub extern "C" fn signal_protocol_sender_key_message_free(message: *mut c_void) {
    free_boxed_value(message.cast::<SenderKeyMessage>());
}

#[no_mangle]
pub extern "C" fn signal_protocol_sender_key_message_serialize_len(
    message: *const c_void,
    out_len: *mut usize,
) -> i32 {
    if message.is_null() || out_len.is_null() {
        return STATUS_INVALID_ARGUMENT;
    }

    let result = catch_unwind(AssertUnwindSafe(|| {
        let msg = unsafe { &*message.cast::<SenderKeyMessage>() };
        let serialized = msg.serialized();
        unsafe {
            *out_len = serialized.len();
        }
        STATUS_OK
    }));

    match result {
        Ok(code) => code,
        Err(_) => STATUS_PANIC,
    }
}

#[no_mangle]
pub extern "C" fn signal_protocol_sender_key_message_serialize(
    message: *const c_void,
    out_buffer: *mut u8,
    buffer_len: usize,
) -> i32 {
    if message.is_null() || out_buffer.is_null() {
        return STATUS_INVALID_ARGUMENT;
    }

    let result = catch_unwind(AssertUnwindSafe(|| {
        let msg = unsafe { &*message.cast::<SenderKeyMessage>() };
        let serialized = msg.serialized();
        if buffer_len < serialized.len() {
            return STATUS_INVALID_ARGUMENT;
        }

        unsafe {
            std::ptr::copy_nonoverlapping(serialized.as_ptr(), out_buffer, serialized.len());
        }

        STATUS_OK
    }));

    match result {
        Ok(code) => code,
        Err(_) => STATUS_PANIC,
    }
}

#[no_mangle]
pub extern "C" fn signal_protocol_sender_key_message_deserialize(
    bytes: *const u8,
    bytes_len: usize,
    out_message: *mut *mut c_void,
) -> i32 {
    if out_message.is_null() {
        return STATUS_INVALID_ARGUMENT;
    }

    unsafe {
        *out_message = std::ptr::null_mut();
    }

    if bytes.is_null() || bytes_len == 0 {
        return STATUS_INVALID_ARGUMENT;
    }

    let result = catch_unwind(AssertUnwindSafe(|| {
        let slice = unsafe { std::slice::from_raw_parts(bytes, bytes_len) };
        let msg: SenderKeyMessage = match SenderKeyMessage::try_from(slice) {
            Ok(v) => v,
            Err(_) => return STATUS_DESERIALIZATION_FAILURE,
        };

        let boxed = Box::new(msg);
        unsafe {
            *out_message = Box::into_raw(boxed).cast::<c_void>();
        }
        STATUS_OK
    }));

    match result {
        Ok(code) => code,
        Err(_) => {
            unsafe {
                *out_message = std::ptr::null_mut();
            }
            STATUS_PANIC
        }
    }
}

#[no_mangle]
pub extern "C" fn signal_protocol_sender_key_message_get_key_id(
    message: *const c_void,
    out_key_id: *mut u32,
) -> i32 {
    if message.is_null() || out_key_id.is_null() {
        return STATUS_INVALID_ARGUMENT;
    }

    let result = catch_unwind(AssertUnwindSafe(|| {
        let msg = unsafe { &*message.cast::<SenderKeyMessage>() };
        // SenderKeyMessage has chain_id and iteration, not key_id
        // We'll return chain_id as a proxy for key_id
        let key_id = msg.chain_id();
        unsafe {
            *out_key_id = key_id;
        }
        STATUS_OK
    }));

    match result {
        Ok(code) => code,
        Err(_) => STATUS_PANIC,
    }
}

// GroupCipher functions
#[no_mangle]
pub extern "C" fn signal_protocol_group_cipher_encrypt(
    sender_address: *const c_void,
    record: *const c_void,
    plaintext: *const u8,
    _plaintext_len: usize,
    out_message: *mut *mut c_void,
    out_new_record: *mut *mut c_void,
) -> i32 {
    if out_message.is_null() || out_new_record.is_null() {
        return STATUS_INVALID_ARGUMENT;
    }

    unsafe {
        *out_message = std::ptr::null_mut();
        *out_new_record = std::ptr::null_mut();
    }

    if sender_address.is_null() || record.is_null() || plaintext.is_null() {
        return STATUS_INVALID_ARGUMENT;
    }

    let result = catch_unwind(AssertUnwindSafe(|| {
        // Note: The actual libsignal GroupCipher API is more complex and requires
        // proper key management and random number generation.
        // For now, this is a placeholder that returns an error.
        STATUS_PANIC
    }));

    match result {
        Ok(code) => code,
        Err(_) => {
            unsafe {
                *out_message = std::ptr::null_mut();
                *out_new_record = std::ptr::null_mut();
            }
            STATUS_PANIC
        }
    }
}

#[no_mangle]
pub extern "C" fn signal_protocol_group_cipher_decrypt(
    sender_address: *const c_void,
    record: *const c_void,
    message: *const c_void,
    out_plaintext: *mut *mut u8,
    out_plaintext_len: *mut usize,
    out_new_record: *mut *mut c_void,
) -> i32 {
    if out_plaintext.is_null() || out_plaintext_len.is_null() || out_new_record.is_null() {
        return STATUS_INVALID_ARGUMENT;
    }

    unsafe {
        *out_plaintext = std::ptr::null_mut();
        *out_plaintext_len = 0;
        *out_new_record = std::ptr::null_mut();
    }

    if sender_address.is_null() || record.is_null() || message.is_null() {
        return STATUS_INVALID_ARGUMENT;
    }

    let result = catch_unwind(AssertUnwindSafe(|| {
        // Note: The actual libsignal GroupCipher API is more complex and requires
        // proper key management.
        // For now, this is a placeholder that returns an error.
        STATUS_PANIC
    }));

    match result {
        Ok(code) => code,
        Err(_) => {
            unsafe {
                *out_plaintext = std::ptr::null_mut();
                *out_plaintext_len = 0;
                *out_new_record = std::ptr::null_mut();
            }
            STATUS_PANIC
        }
    }
}

#[no_mangle]
pub extern "C" fn signal_protocol_group_cipher_free_plaintext(plaintext: *mut u8, len: usize) {
    if !plaintext.is_null() && len > 0 {
        unsafe {
            let layout = std::alloc::Layout::from_size_align(len, 1).unwrap();
            std::alloc::dealloc(plaintext, layout);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_secret_params_given_valid_randomness_returns_non_null_handle() {
        // Arrange
        let randomness = [7u8; GROUP_MASTER_KEY_LEN];
        let mut out: *mut c_void = std::ptr::null_mut();

        // Act
        let status = signal_zkgroup_group_secret_params_generate(
            randomness.as_ptr(),
            randomness.len(),
            &mut out,
        );

        // Assert
        assert_eq!(status, STATUS_OK);
        assert!(!out.is_null());

        signal_zkgroup_group_secret_params_free(out);
    }

    #[test]
    fn get_master_key_given_valid_secret_params_returns_non_null_master_key_handle() {
        // Arrange
        let randomness = [1u8; GROUP_MASTER_KEY_LEN];
        let mut secret_params: *mut c_void = std::ptr::null_mut();
        assert_eq!(
            signal_zkgroup_group_secret_params_generate(
                randomness.as_ptr(),
                randomness.len(),
                &mut secret_params,
            ),
            STATUS_OK
        );
        let mut master_key: *mut c_void = std::ptr::null_mut();

        // Act
        let status = signal_zkgroup_group_secret_params_get_master_key(secret_params, &mut master_key);

        // Assert
        assert_eq!(status, STATUS_OK);
        assert!(!master_key.is_null());

        signal_zkgroup_group_master_key_free(master_key);
        signal_zkgroup_group_secret_params_free(secret_params);
    }

    #[test]
    fn serialize_deserialize_master_key_round_trip_stable() {
        // Arrange
        let randomness = [2u8; GROUP_MASTER_KEY_LEN];
        let mut secret_params: *mut c_void = std::ptr::null_mut();
        assert_eq!(
            signal_zkgroup_group_secret_params_generate(
                randomness.as_ptr(),
                randomness.len(),
                &mut secret_params,
            ),
            STATUS_OK
        );
        let mut master_key: *mut c_void = std::ptr::null_mut();
        assert_eq!(
            signal_zkgroup_group_secret_params_get_master_key(secret_params, &mut master_key),
            STATUS_OK
        );

        let mut buf_a = [0u8; GROUP_MASTER_KEY_LEN];

        // Act
        assert_eq!(
            signal_zkgroup_group_master_key_serialize(master_key, buf_a.as_mut_ptr(), buf_a.len()),
            STATUS_OK
        );

        let mut master_key_b: *mut c_void = std::ptr::null_mut();
        assert_eq!(
            signal_zkgroup_group_master_key_deserialize(buf_a.as_ptr(), buf_a.len(), &mut master_key_b),
            STATUS_OK
        );

        let mut buf_b = [0u8; GROUP_MASTER_KEY_LEN];
        assert_eq!(
            signal_zkgroup_group_master_key_serialize(master_key_b, buf_b.as_mut_ptr(), buf_b.len()),
            STATUS_OK
        );

        // Assert
        assert_eq!(buf_a, buf_b);

        signal_zkgroup_group_master_key_free(master_key_b);
        signal_zkgroup_group_master_key_free(master_key);
        signal_zkgroup_group_secret_params_free(secret_params);
    }

    #[test]
    fn serialize_master_key_given_wrong_buffer_len_returns_invalid_argument() {
        // Arrange
        let randomness = [3u8; GROUP_MASTER_KEY_LEN];
        let mut secret_params: *mut c_void = std::ptr::null_mut();
        assert_eq!(
            signal_zkgroup_group_secret_params_generate(
                randomness.as_ptr(),
                randomness.len(),
                &mut secret_params,
            ),
            STATUS_OK
        );
        let mut master_key: *mut c_void = std::ptr::null_mut();
        assert_eq!(
            signal_zkgroup_group_secret_params_get_master_key(secret_params, &mut master_key),
            STATUS_OK
        );

        let mut buf = [0u8; GROUP_MASTER_KEY_LEN - 1];

        // Act
        let status = signal_zkgroup_group_master_key_serialize(master_key, buf.as_mut_ptr(), buf.len());

        // Assert
        assert_eq!(status, STATUS_INVALID_ARGUMENT);

        signal_zkgroup_group_master_key_free(master_key);
        signal_zkgroup_group_secret_params_free(secret_params);
    }

    #[test]
    fn deserialize_master_key_given_wrong_length_returns_invalid_argument_and_null_out() {
        // Arrange
        let buf = [0u8; GROUP_MASTER_KEY_LEN - 1];
        let mut out: *mut c_void = 0x1usize as *mut c_void;

        // Act
        let status = signal_zkgroup_group_master_key_deserialize(buf.as_ptr(), buf.len(), &mut out);

        // Assert
        assert_eq!(status, STATUS_INVALID_ARGUMENT);
        assert!(out.is_null());
    }

    #[test]
    fn free_functions_accept_null_no_crash() {
        // Arrange
        let p: *mut c_void = std::ptr::null_mut();

        // Act + Assert
        signal_zkgroup_group_master_key_free(p);
        signal_zkgroup_group_secret_params_free(p);
    }

    #[test]
    fn panic_is_caught_returns_status2_and_null_out_pointers() {
        // Arrange
        let mut out: *mut c_void = 0x1usize as *mut c_void;

        // Act
        let status = super::signal_zkgroup__test_only_panic(&mut out);

        // Assert
        assert_eq!(status, STATUS_PANIC);
        assert!(out.is_null());
    }
}