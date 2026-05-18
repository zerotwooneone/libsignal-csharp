using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Security.Cryptography;

namespace Signal.Interop;

/// <summary>
/// This class must be marked 'partial' because the [LibraryImport] source generator 
/// will write the actual implementation behind the scenes.
/// </summary>
public static partial class SignalCrypto
{
    // Omit the .dll, .so, or .dylib extension so the runtime automatically resolves 
    // the correct file based on the operating system.
    private const string DllName = "signal_shim";

    private const int StatusOk = 0;
    private const int StatusInvalidArgument = 1;
    private const int StatusPanic = 2;
    private const int StatusDeserializationFailure = 4;

    public const int GroupMasterKeyLength = 32;

    internal static partial class Native
    {
        [LibraryImport(DllName, EntryPoint = "signal_shim_test_connection")]
        [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
        internal static partial int signal_shim_test_connection();

        [LibraryImport(DllName, EntryPoint = "signal_zkgroup_group_master_key_free")]
        [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
        internal static partial void signal_zkgroup_group_master_key_free(nint masterKey);

        [LibraryImport(DllName, EntryPoint = "signal_zkgroup_group_secret_params_free")]
        [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
        internal static partial void signal_zkgroup_group_secret_params_free(nint secretParams);

        [LibraryImport(DllName, EntryPoint = "signal_zkgroup_group_secret_params_generate")]
        [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
        internal static unsafe partial int signal_zkgroup_group_secret_params_generate(
            byte* randomness32,
            nuint randomnessLen,
            out nint outSecretParams);

        [LibraryImport(DllName, EntryPoint = "signal_zkgroup_group_secret_params_get_master_key")]
        [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
        internal static partial int signal_zkgroup_group_secret_params_get_master_key(
            nint secretParams,
            out nint outMasterKey);

        [LibraryImport(DllName, EntryPoint = "signal_zkgroup_group_secret_params_derive_from_master_key")]
        [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
        internal static partial int signal_zkgroup_group_secret_params_derive_from_master_key(
            nint masterKey,
            out nint outSecretParams);

        [LibraryImport(DllName, EntryPoint = "signal_zkgroup_group_master_key_serialize")]
        [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
        internal static unsafe partial int signal_zkgroup_group_master_key_serialize(
            nint masterKey,
            byte* outBuffer,
            nuint bufferLen);

        [LibraryImport(DllName, EntryPoint = "signal_zkgroup_group_master_key_deserialize")]
        [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
        internal static unsafe partial int signal_zkgroup_group_master_key_deserialize(
            byte* bytes,
            nuint bytesLen,
            out nint outMasterKey);
    }

    public static int TestConnection()
    {
        return Native.signal_shim_test_connection();
    }

    public static GroupSecretParamsSafeHandle GenerateGroupSecretParams(ReadOnlySpan<byte> randomness32)
    {
        if (randomness32.Length != GroupMasterKeyLength)
        {
            throw new ArgumentException($"Randomness must be exactly {GroupMasterKeyLength} bytes.", nameof(randomness32));
        }

        unsafe
        {
            fixed (byte* pRandomness = randomness32)
            {
                int status = Native.signal_zkgroup_group_secret_params_generate(
                    pRandomness,
                    (nuint)randomness32.Length,
                    out nint secretParams);
                ThrowOnError(status);
                return new GroupSecretParamsSafeHandle(secretParams);
            }
        }
    }

    public static GroupMasterKeySafeHandle GetGroupMasterKey(GroupSecretParamsSafeHandle secretParams)
    {
        ArgumentNullException.ThrowIfNull(secretParams);
        if (secretParams.IsInvalid)
        {
            throw new ArgumentException("Handle is invalid.", nameof(secretParams));
        }

        bool addedRef = false;
        try
        {
            secretParams.DangerousAddRef(ref addedRef);
            nint handle = secretParams.DangerousGetHandle();

            int status = Native.signal_zkgroup_group_secret_params_get_master_key(handle, out nint masterKey);
            ThrowOnError(status);
            return new GroupMasterKeySafeHandle(masterKey);
        }
        finally
        {
            if (addedRef)
            {
                secretParams.DangerousRelease();
            }
        }
    }

    public static GroupSecretParamsSafeHandle DeriveGroupSecretParams(GroupMasterKeySafeHandle masterKey)
    {
        ArgumentNullException.ThrowIfNull(masterKey);
        if (masterKey.IsInvalid)
        {
            throw new ArgumentException("Handle is invalid.", nameof(masterKey));
        }

        bool addedRef = false;
        try
        {
            masterKey.DangerousAddRef(ref addedRef);
            nint handle = masterKey.DangerousGetHandle();

            int status = Native.signal_zkgroup_group_secret_params_derive_from_master_key(handle, out nint secretParams);
            ThrowOnError(status);
            return new GroupSecretParamsSafeHandle(secretParams);
        }
        finally
        {
            if (addedRef)
            {
                masterKey.DangerousRelease();
            }
        }
    }

    public static byte[] SerializeGroupMasterKey(GroupMasterKeySafeHandle masterKey)
    {
        ArgumentNullException.ThrowIfNull(masterKey);
        if (masterKey.IsInvalid)
        {
            throw new ArgumentException("Handle is invalid.", nameof(masterKey));
        }

        byte[] bytes = new byte[GroupMasterKeyLength];
        SerializeGroupMasterKey(masterKey, bytes);
        return bytes;
    }

    public static void SerializeGroupMasterKey(GroupMasterKeySafeHandle masterKey, Span<byte> buffer32)
    {
        ArgumentNullException.ThrowIfNull(masterKey);
        if (masterKey.IsInvalid)
        {
            throw new ArgumentException("Handle is invalid.", nameof(masterKey));
        }
        if (buffer32.Length != GroupMasterKeyLength)
        {
            throw new ArgumentException($"Buffer must be exactly {GroupMasterKeyLength} bytes.", nameof(buffer32));
        }

        bool addedRef = false;
        try
        {
            masterKey.DangerousAddRef(ref addedRef);
            nint handle = masterKey.DangerousGetHandle();

            unsafe
            {
                fixed (byte* pBuffer = buffer32)
                {
                    int status = Native.signal_zkgroup_group_master_key_serialize(handle, pBuffer, (nuint)buffer32.Length);
                    ThrowOnError(status);
                }
            }
        }
        finally
        {
            if (addedRef)
            {
                masterKey.DangerousRelease();
            }
        }
    }

    public static GroupMasterKeySafeHandle DeserializeGroupMasterKey(ReadOnlySpan<byte> bytes32)
    {
        if (bytes32.Length != GroupMasterKeyLength)
        {
            throw new ArgumentException($"Serialized master key must be exactly {GroupMasterKeyLength} bytes.", nameof(bytes32));
        }

        unsafe
        {
            fixed (byte* pBytes = bytes32)
            {
                int status = Native.signal_zkgroup_group_master_key_deserialize(pBytes, (nuint)bytes32.Length, out nint masterKey);
                ThrowOnError(status);
                return new GroupMasterKeySafeHandle(masterKey);
            }
        }
    }

    private static void ThrowOnError(int status)
    {
        if (status == StatusOk)
        {
            return;
        }

        if (status == StatusInvalidArgument)
        {
            throw new ArgumentException("Native call reported invalid argument.");
        }

        if (status == StatusDeserializationFailure)
        {
            throw new CryptographicException("Native call failed to deserialize the provided bytes.");
        }

        if (status == StatusPanic)
        {
            throw new CryptographicException("Native call panicked.");
        }

        throw new CryptographicException($"Native call failed with status {status}.");
    }
}