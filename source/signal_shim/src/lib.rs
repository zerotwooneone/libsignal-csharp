// We include this to ensure the compiler actually downloads and links the Signal library,
// even if we aren't calling its specific cryptographic functions in this dummy test.
use core::ffi::c_void;
use std::panic::{AssertUnwindSafe, catch_unwind};
use zeroize::Zeroize;

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
const STATUS_DESERIALIZATION_FAILURE: i32 = 4;

const GROUP_MASTER_KEY_LEN: usize = 32;

type GroupMasterKey = zkgroup::groups::GroupMasterKey;
type GroupSecretParams = zkgroup::groups::GroupSecretParams;

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