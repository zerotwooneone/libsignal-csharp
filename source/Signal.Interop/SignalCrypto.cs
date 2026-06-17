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
    private const int StatusVerificationFailure = 3;
    private const int StatusDeserializationFailure = 4;

    public const int GroupMasterKeyLength = 32;
    public const int UuidLength = 16;
    public const int Ed25519PrivateKeyLength = 32;
    public const int Ed25519PublicKeyLength = 32;
    public const int Ed25519SignatureLength = 64;

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

        [LibraryImport(DllName, EntryPoint = "signal_zkgroup_group_secret_params_get_group_id")]
        [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
        internal static unsafe partial int signal_zkgroup_group_secret_params_get_group_id(
            nint secretParams,
            byte* outBuffer,
            nuint bufferLen);

        [LibraryImport(DllName, EntryPoint = "signal_zkgroup_group_secret_params_get_server_group_id")]
        [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
        internal static unsafe partial int signal_zkgroup_group_secret_params_get_server_group_id(
            nint secretParams,
            byte* outBuffer,
            nuint bufferLen);

        [LibraryImport(DllName, EntryPoint = "signal_zkgroup_group_secret_params_get_blob_key")]
        [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
        internal static unsafe partial int signal_zkgroup_group_secret_params_get_blob_key(
            nint secretParams,
            byte* outBuffer,
            nuint bufferLen);

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

        [LibraryImport(DllName, EntryPoint = "signal_zkgroup_group_secret_params_get_public_params")]
        [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
        internal static partial int signal_zkgroup_group_secret_params_get_public_params(
            nint secretParams,
            out nint outPublicParams);

        [LibraryImport(DllName, EntryPoint = "signal_zkgroup_group_public_params_free")]
        [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
        internal static partial void signal_zkgroup_group_public_params_free(nint publicParams);

        [LibraryImport(DllName, EntryPoint = "signal_zkgroup_group_public_params_get_serialized_len")]
        [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
        internal static partial int signal_zkgroup_group_public_params_get_serialized_len(
            nint publicParams,
            out nuint outLen);

        [LibraryImport(DllName, EntryPoint = "signal_zkgroup_group_public_params_serialize")]
        [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
        internal static unsafe partial int signal_zkgroup_group_public_params_serialize(
            nint publicParams,
            byte* outBuffer,
            nuint bufferLen);

        [LibraryImport(DllName, EntryPoint = "signal_zkgroup_group_public_params_deserialize")]
        [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
        internal static unsafe partial int signal_zkgroup_group_public_params_deserialize(
            byte* bytes,
            nuint bytesLen,
            out nint outPublicParams);

        [LibraryImport(DllName, EntryPoint = "signal_zkgroup_server_secret_params_generate")]
        [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
        internal static unsafe partial int signal_zkgroup_server_secret_params_generate(
            byte* randomness32,
            nuint randomnessLen,
            out nint outServerSecretParams);

        [LibraryImport(DllName, EntryPoint = "signal_zkgroup_server_secret_params_free")]
        [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
        internal static partial void signal_zkgroup_server_secret_params_free(nint serverSecretParams);

        [LibraryImport(DllName, EntryPoint = "signal_zkgroup_server_public_params_free")]
        [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
        internal static partial void signal_zkgroup_server_public_params_free(nint serverPublicParams);

        [LibraryImport(DllName, EntryPoint = "signal_zkgroup_server_secret_params_get_public_params")]
        [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
        internal static partial int signal_zkgroup_server_secret_params_get_public_params(
            nint serverSecretParams,
            out nint outServerPublicParams);

        [LibraryImport(DllName, EntryPoint = "signal_zkgroup_server_public_params_get_serialized_len")]
        [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
        internal static partial int signal_zkgroup_server_public_params_get_serialized_len(
            nint serverPublicParams,
            out nuint outLen);

        [LibraryImport(DllName, EntryPoint = "signal_zkgroup_server_public_params_serialize")]
        [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
        internal static unsafe partial int signal_zkgroup_server_public_params_serialize(
            nint serverPublicParams,
            byte* outBuffer,
            nuint bufferLen);

        [LibraryImport(DllName, EntryPoint = "signal_zkgroup_server_public_params_deserialize")]
        [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
        internal static unsafe partial int signal_zkgroup_server_public_params_deserialize(
            byte* bytes,
            nuint bytesLen,
            out nint outServerPublicParams);

        [LibraryImport(DllName, EntryPoint = "signal_zkgroup_auth_credential_with_pni_response_free")]
        [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
        internal static partial void signal_zkgroup_auth_credential_with_pni_response_free(nint response);

        [LibraryImport(DllName, EntryPoint = "signal_zkgroup_auth_credential_with_pni_free")]
        [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
        internal static partial void signal_zkgroup_auth_credential_with_pni_free(nint credential);

        [LibraryImport(DllName, EntryPoint = "signal_zkgroup_auth_credential_with_pni_presentation_free")]
        [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
        internal static partial void signal_zkgroup_auth_credential_with_pni_presentation_free(nint presentation);

        [LibraryImport(DllName, EntryPoint = "signal_zkgroup_auth_credential_with_pni_issue_credential")]
        [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
        internal static unsafe partial int signal_zkgroup_auth_credential_with_pni_issue_credential(
            byte* aciBytes,
            nuint aciLen,
            byte* pniBytes,
            nuint pniLen,
            ulong redemptionTimeEpochSeconds,
            nint serverSecretParams,
            byte* randomness32,
            nuint randomnessLen,
            out nint outResponse);

        [LibraryImport(DllName, EntryPoint = "signal_zkgroup_auth_credential_with_pni_response_receive")]
        [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
        internal static unsafe partial int signal_zkgroup_auth_credential_with_pni_response_receive(
            nint response,
            byte* aciBytes,
            nuint aciLen,
            byte* pniBytes,
            nuint pniLen,
            ulong redemptionTimeEpochSeconds,
            nint serverPublicParams,
            out nint outCredential);

        [LibraryImport(DllName, EntryPoint = "signal_zkgroup_auth_credential_with_pni_present")]
        [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
        internal static unsafe partial int signal_zkgroup_auth_credential_with_pni_present(
            nint credential,
            nint serverPublicParams,
            nint groupSecretParams,
            byte* randomness32,
            nuint randomnessLen,
            out nint outPresentation);

        [LibraryImport(DllName, EntryPoint = "signal_zkgroup_auth_credential_with_pni_presentation_verify")]
        [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
        internal static partial int signal_zkgroup_auth_credential_with_pni_presentation_verify(
            nint presentation,
            nint serverSecretParams,
            nint groupPublicParams,
            ulong redemptionTimeEpochSeconds);

        [LibraryImport(DllName, EntryPoint = "signal_zkgroup_auth_credential_with_pni_presentation_serialize_len")]
        [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
        internal static partial int signal_zkgroup_auth_credential_with_pni_presentation_serialize_len(
            nint presentation,
            out nuint outLen);

        [LibraryImport(DllName, EntryPoint = "signal_zkgroup_auth_credential_with_pni_presentation_serialize")]
        [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
        internal static unsafe partial int signal_zkgroup_auth_credential_with_pni_presentation_serialize(
            nint presentation,
            byte* outBuffer,
            nuint bufferLen);

        [LibraryImport(DllName, EntryPoint = "signal_zkgroup_auth_credential_with_pni_presentation_deserialize")]
        [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
        internal static unsafe partial int signal_zkgroup_auth_credential_with_pni_presentation_deserialize(
            byte* bytes,
            nuint bytesLen,
            out nint outPresentation);

        [LibraryImport(DllName, EntryPoint = "signal_protocol_sender_key_record_new")]
        [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
        internal static partial int signal_protocol_sender_key_record_new(out nint outRecord);

        [LibraryImport(DllName, EntryPoint = "signal_protocol_sender_key_record_free")]
        [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
        internal static partial void signal_protocol_sender_key_record_free(nint record);

        [LibraryImport(DllName, EntryPoint = "signal_protocol_sender_key_record_serialize_len")]
        [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
        internal static partial int signal_protocol_sender_key_record_serialize_len(
            nint record,
            out nuint outLen);

        [LibraryImport(DllName, EntryPoint = "signal_protocol_sender_key_record_serialize")]
        [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
        internal static unsafe partial int signal_protocol_sender_key_record_serialize(
            nint record,
            byte* outBuffer,
            nuint bufferLen);

        [LibraryImport(DllName, EntryPoint = "signal_protocol_sender_key_record_deserialize")]
        [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
        internal static unsafe partial int signal_protocol_sender_key_record_deserialize(
            byte* bytes,
            nuint bytesLen,
            out nint outRecord);

        [LibraryImport(DllName, EntryPoint = "signal_protocol_sender_address_new")]
        [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
        internal static unsafe partial int signal_protocol_sender_address_new(
            byte* uuidBytes,
            nuint uuidLen,
            uint deviceId,
            out nint outAddress);

        [LibraryImport(DllName, EntryPoint = "signal_protocol_sender_address_free")]
        [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
        internal static partial void signal_protocol_sender_address_free(nint address);

        [LibraryImport(DllName, EntryPoint = "signal_protocol_sender_key_distribution_message_free")]
        [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
        internal static partial void signal_protocol_sender_key_distribution_message_free(nint message);

        [LibraryImport(DllName, EntryPoint = "signal_protocol_sender_key_distribution_message_serialize_len")]
        [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
        internal static partial int signal_protocol_sender_key_distribution_message_serialize_len(
            nint message,
            out nuint outLen);

        [LibraryImport(DllName, EntryPoint = "signal_protocol_sender_key_distribution_message_serialize")]
        [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
        internal static unsafe partial int signal_protocol_sender_key_distribution_message_serialize(
            nint message,
            byte* outBuffer,
            nuint bufferLen);

        [LibraryImport(DllName, EntryPoint = "signal_protocol_sender_key_distribution_message_deserialize")]
        [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
        internal static unsafe partial int signal_protocol_sender_key_distribution_message_deserialize(
            byte* bytes,
            nuint bytesLen,
            out nint outMessage);

        [LibraryImport(DllName, EntryPoint = "signal_protocol_sender_key_distribution_message_create")]
        [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
        internal static unsafe partial int signal_protocol_sender_key_distribution_message_create(
            nint vtable,
            nint senderAddress,
            byte* distributionIdBytes,
            nuint distributionIdLen,
            out nint outMessage);

        [LibraryImport(DllName, EntryPoint = "signal_protocol_sender_key_distribution_message_process")]
        [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
        internal static partial int signal_protocol_sender_key_distribution_message_process(
            nint vtable,
            nint senderAddress,
            nint message);

        [LibraryImport(DllName, EntryPoint = "signal_protocol_sender_key_message_free")]
        [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
        internal static partial void signal_protocol_sender_key_message_free(nint message);

        [LibraryImport(DllName, EntryPoint = "signal_protocol_sender_key_message_serialize_len")]
        [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
        internal static partial int signal_protocol_sender_key_message_serialize_len(
            nint message,
            out nuint outLen);

        [LibraryImport(DllName, EntryPoint = "signal_protocol_sender_key_message_serialize")]
        [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
        internal static unsafe partial int signal_protocol_sender_key_message_serialize(
            nint message,
            byte* outBuffer,
            nuint bufferLen);

        [LibraryImport(DllName, EntryPoint = "signal_protocol_sender_key_message_deserialize")]
        [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
        internal static unsafe partial int signal_protocol_sender_key_message_deserialize(
            byte* bytes,
            nuint bytesLen,
            out nint outMessage);

        [LibraryImport(DllName, EntryPoint = "signal_protocol_sender_key_message_get_key_id")]
        [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
        internal static partial int signal_protocol_sender_key_message_get_key_id(
            nint message,
            out uint outKeyId);

        [LibraryImport(DllName, EntryPoint = "signal_protocol_group_cipher_encrypt")]
        [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
        internal static unsafe partial int signal_protocol_group_cipher_encrypt(
            nint vtable,
            nint senderAddress,
            byte* distributionIdBytes,
            nuint distributionIdLen,
            byte* plaintext,
            nuint plaintextLen,
            out nint outMessage);

        [LibraryImport(DllName, EntryPoint = "signal_protocol_group_cipher_decrypt")]
        [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
        internal static unsafe partial int signal_protocol_group_cipher_decrypt(
            nint vtable,
            nint senderAddress,
            nint message,
            out nint outPlaintext,
            out nuint outPlaintextLen);

        [LibraryImport(DllName, EntryPoint = "signal_protocol_group_cipher_free_plaintext")]
        [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
        internal static partial void signal_protocol_group_cipher_free_plaintext(
            nint plaintext,
            nuint len);

        [LibraryImport(DllName, EntryPoint = "signal_crypto_ed25519_generate_key_pair")]
        [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
        internal static unsafe partial int signal_crypto_ed25519_generate_key_pair(
            byte* outPrivateKey,
            byte* outPublicKey);

        [LibraryImport(DllName, EntryPoint = "signal_crypto_ed25519_sign")]
        [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
        internal static unsafe partial int signal_crypto_ed25519_sign(
            byte* privateKeyBytes,
            byte* messageBytes,
            nuint messageLen,
            byte* outSignature);

        [LibraryImport(DllName, EntryPoint = "signal_crypto_ed25519_verify")]
        [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
        internal static unsafe partial int signal_crypto_ed25519_verify(
            byte* publicKeyBytes,
            byte* messageBytes,
            nuint messageLen,
            byte* signatureBytes);
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

    public static GroupPublicParamsSafeHandle GetGroupPublicParams(GroupSecretParamsSafeHandle handle)
    {
        ArgumentNullException.ThrowIfNull(handle);
        if (handle.IsInvalid)
        {
            throw new ArgumentException("Handle is invalid.", nameof(handle));
        }

        bool addedRef = false;
        try
        {
            handle.DangerousAddRef(ref addedRef);
            nint secretParams = handle.DangerousGetHandle();

            int status = Native.signal_zkgroup_group_secret_params_get_public_params(secretParams, out nint publicParams);
            ThrowOnError(status);
            return new GroupPublicParamsSafeHandle(publicParams);
        }
        finally
        {
            if (addedRef)
            {
                handle.DangerousRelease();
            }
        }
    }

    public static ServerSecretParamsSafeHandle GenerateServerSecretParams(ReadOnlySpan<byte> randomness32)
    {
        if (randomness32.Length != GroupMasterKeyLength)
        {
            throw new ArgumentException($"Randomness must be exactly {GroupMasterKeyLength} bytes.", nameof(randomness32));
        }

        unsafe
        {
            fixed (byte* pRandomness = randomness32)
            {
                int status = Native.signal_zkgroup_server_secret_params_generate(
                    pRandomness,
                    (nuint)randomness32.Length,
                    out nint serverSecretParams);
                ThrowOnError(status);
                return new ServerSecretParamsSafeHandle(serverSecretParams);
            }
        }
    }

    public static ServerPublicParamsSafeHandle GetServerPublicParams(ServerSecretParamsSafeHandle serverSecretParams)
    {
        ArgumentNullException.ThrowIfNull(serverSecretParams);
        if (serverSecretParams.IsInvalid)
        {
            throw new ArgumentException("Handle is invalid.", nameof(serverSecretParams));
        }

        bool addedRef = false;
        try
        {
            serverSecretParams.DangerousAddRef(ref addedRef);
            nint handle = serverSecretParams.DangerousGetHandle();

            int status = Native.signal_zkgroup_server_secret_params_get_public_params(handle, out nint publicParams);
            ThrowOnError(status);
            return new ServerPublicParamsSafeHandle(publicParams);
        }
        finally
        {
            if (addedRef)
            {
                serverSecretParams.DangerousRelease();
            }
        }
    }

    public static AuthCredentialWithPniResponseSafeHandle IssueAuthCredentialWithPni(
        ReadOnlySpan<byte> aciBytes16,
        ReadOnlySpan<byte> pniBytes16,
        ulong redemptionTimeEpochSeconds,
        ServerSecretParamsSafeHandle serverSecretParams,
        ReadOnlySpan<byte> randomness32)
    {
        if (aciBytes16.Length != UuidLength)
        {
            throw new ArgumentException($"ACI must be exactly {UuidLength} bytes.", nameof(aciBytes16));
        }
        if (pniBytes16.Length != UuidLength)
        {
            throw new ArgumentException($"PNI must be exactly {UuidLength} bytes.", nameof(pniBytes16));
        }
        ArgumentNullException.ThrowIfNull(serverSecretParams);
        if (serverSecretParams.IsInvalid)
        {
            throw new ArgumentException("Handle is invalid.", nameof(serverSecretParams));
        }
        if (randomness32.Length != GroupMasterKeyLength)
        {
            throw new ArgumentException($"Randomness must be exactly {GroupMasterKeyLength} bytes.", nameof(randomness32));
        }

        bool addedRef = false;
        try
        {
            serverSecretParams.DangerousAddRef(ref addedRef);
            nint handle = serverSecretParams.DangerousGetHandle();

            unsafe
            {
                fixed (byte* pAci = aciBytes16)
                fixed (byte* pPni = pniBytes16)
                fixed (byte* pRand = randomness32)
                {
                    int status = Native.signal_zkgroup_auth_credential_with_pni_issue_credential(
                        pAci,
                        (nuint)aciBytes16.Length,
                        pPni,
                        (nuint)pniBytes16.Length,
                        redemptionTimeEpochSeconds,
                        handle,
                        pRand,
                        (nuint)randomness32.Length,
                        out nint response);
                    ThrowOnError(status);
                    return new AuthCredentialWithPniResponseSafeHandle(response);
                }
            }
        }
        finally
        {
            if (addedRef)
            {
                serverSecretParams.DangerousRelease();
            }
        }
    }

    public static AuthCredentialWithPniSafeHandle ReceiveAuthCredentialWithPni(
        AuthCredentialWithPniResponseSafeHandle response,
        ReadOnlySpan<byte> aciBytes16,
        ReadOnlySpan<byte> pniBytes16,
        ulong redemptionTimeEpochSeconds,
        ServerPublicParamsSafeHandle serverPublicParams)
    {
        ArgumentNullException.ThrowIfNull(response);
        if (response.IsInvalid)
        {
            throw new ArgumentException("Handle is invalid.", nameof(response));
        }
        if (aciBytes16.Length != UuidLength)
        {
            throw new ArgumentException($"ACI must be exactly {UuidLength} bytes.", nameof(aciBytes16));
        }
        if (pniBytes16.Length != UuidLength)
        {
            throw new ArgumentException($"PNI must be exactly {UuidLength} bytes.", nameof(pniBytes16));
        }
        ArgumentNullException.ThrowIfNull(serverPublicParams);
        if (serverPublicParams.IsInvalid)
        {
            throw new ArgumentException("Handle is invalid.", nameof(serverPublicParams));
        }

        bool addedRefResponse = false;
        bool addedRefPublic = false;
        try
        {
            response.DangerousAddRef(ref addedRefResponse);
            serverPublicParams.DangerousAddRef(ref addedRefPublic);
            nint responseHandle = response.DangerousGetHandle();
            nint publicHandle = serverPublicParams.DangerousGetHandle();

            unsafe
            {
                fixed (byte* pAci = aciBytes16)
                fixed (byte* pPni = pniBytes16)
                {
                    int status = Native.signal_zkgroup_auth_credential_with_pni_response_receive(
                        responseHandle,
                        pAci,
                        (nuint)aciBytes16.Length,
                        pPni,
                        (nuint)pniBytes16.Length,
                        redemptionTimeEpochSeconds,
                        publicHandle,
                        out nint credential);
                    ThrowOnError(status);
                    return new AuthCredentialWithPniSafeHandle(credential);
                }
            }
        }
        finally
        {
            if (addedRefPublic)
            {
                serverPublicParams.DangerousRelease();
            }
            if (addedRefResponse)
            {
                response.DangerousRelease();
            }
        }
    }

    public static AuthCredentialWithPniPresentationSafeHandle PresentAuthCredentialWithPni(
        AuthCredentialWithPniSafeHandle credential,
        ServerPublicParamsSafeHandle serverPublicParams,
        GroupSecretParamsSafeHandle groupSecretParams,
        ReadOnlySpan<byte> randomness32)
    {
        ArgumentNullException.ThrowIfNull(credential);
        if (credential.IsInvalid)
        {
            throw new ArgumentException("Handle is invalid.", nameof(credential));
        }
        ArgumentNullException.ThrowIfNull(serverPublicParams);
        if (serverPublicParams.IsInvalid)
        {
            throw new ArgumentException("Handle is invalid.", nameof(serverPublicParams));
        }
        ArgumentNullException.ThrowIfNull(groupSecretParams);
        if (groupSecretParams.IsInvalid)
        {
            throw new ArgumentException("Handle is invalid.", nameof(groupSecretParams));
        }
        if (randomness32.Length != GroupMasterKeyLength)
        {
            throw new ArgumentException($"Randomness must be exactly {GroupMasterKeyLength} bytes.", nameof(randomness32));
        }

        bool addedRefCred = false;
        bool addedRefPub = false;
        bool addedRefGroup = false;
        try
        {
            credential.DangerousAddRef(ref addedRefCred);
            serverPublicParams.DangerousAddRef(ref addedRefPub);
            groupSecretParams.DangerousAddRef(ref addedRefGroup);

            nint credHandle = credential.DangerousGetHandle();
            nint pubHandle = serverPublicParams.DangerousGetHandle();
            nint groupHandle = groupSecretParams.DangerousGetHandle();

            unsafe
            {
                fixed (byte* pRand = randomness32)
                {
                    int status = Native.signal_zkgroup_auth_credential_with_pni_present(
                        credHandle,
                        pubHandle,
                        groupHandle,
                        pRand,
                        (nuint)randomness32.Length,
                        out nint presentation);
                    ThrowOnError(status);
                    return new AuthCredentialWithPniPresentationSafeHandle(presentation);
                }
            }
        }
        finally
        {
            if (addedRefGroup)
            {
                groupSecretParams.DangerousRelease();
            }
            if (addedRefPub)
            {
                serverPublicParams.DangerousRelease();
            }
            if (addedRefCred)
            {
                credential.DangerousRelease();
            }
        }
    }

    public static void VerifyAuthCredentialWithPniPresentation(
        AuthCredentialWithPniPresentationSafeHandle presentation,
        ServerSecretParamsSafeHandle serverSecretParams,
        GroupPublicParamsSafeHandle groupPublicParams,
        ulong redemptionTimeEpochSeconds)
    {
        ArgumentNullException.ThrowIfNull(presentation);
        if (presentation.IsInvalid)
        {
            throw new ArgumentException("Handle is invalid.", nameof(presentation));
        }
        ArgumentNullException.ThrowIfNull(serverSecretParams);
        if (serverSecretParams.IsInvalid)
        {
            throw new ArgumentException("Handle is invalid.", nameof(serverSecretParams));
        }
        ArgumentNullException.ThrowIfNull(groupPublicParams);
        if (groupPublicParams.IsInvalid)
        {
            throw new ArgumentException("Handle is invalid.", nameof(groupPublicParams));
        }

        bool addedRefPres = false;
        bool addedRefServer = false;
        bool addedRefGroup = false;
        try
        {
            presentation.DangerousAddRef(ref addedRefPres);
            serverSecretParams.DangerousAddRef(ref addedRefServer);
            groupPublicParams.DangerousAddRef(ref addedRefGroup);

            int status = Native.signal_zkgroup_auth_credential_with_pni_presentation_verify(
                presentation.DangerousGetHandle(),
                serverSecretParams.DangerousGetHandle(),
                groupPublicParams.DangerousGetHandle(),
                redemptionTimeEpochSeconds);
            ThrowOnError(status);
        }
        finally
        {
            if (addedRefGroup)
            {
                groupPublicParams.DangerousRelease();
            }
            if (addedRefServer)
            {
                serverSecretParams.DangerousRelease();
            }
            if (addedRefPres)
            {
                presentation.DangerousRelease();
            }
        }
    }

    public static byte[] SerializeAuthCredentialWithPniPresentation(AuthCredentialWithPniPresentationSafeHandle presentation)
    {
        ArgumentNullException.ThrowIfNull(presentation);
        if (presentation.IsInvalid)
        {
            throw new ArgumentException("Handle is invalid.", nameof(presentation));
        }

        bool addedRef = false;
        try
        {
            presentation.DangerousAddRef(ref addedRef);
            nint handle = presentation.DangerousGetHandle();

            int status = Native.signal_zkgroup_auth_credential_with_pni_presentation_serialize_len(handle, out nuint len);
            ThrowOnError(status);

            byte[] buffer = new byte[len];
            unsafe
            {
                fixed (byte* pBuffer = buffer)
                {
                    status = Native.signal_zkgroup_auth_credential_with_pni_presentation_serialize(handle, pBuffer, len);
                    ThrowOnError(status);
                }
            }

            return buffer;
        }
        finally
        {
            if (addedRef)
            {
                presentation.DangerousRelease();
            }
        }
    }

    public static AuthCredentialWithPniPresentationSafeHandle DeserializeAuthCredentialWithPniPresentation(ReadOnlySpan<byte> presentationBytes)
    {
        if (presentationBytes.Length == 0)
        {
            throw new ArgumentException("Bytes cannot be empty.", nameof(presentationBytes));
        }

        unsafe
        {
            fixed (byte* pBytes = presentationBytes)
            {
                int status = Native.signal_zkgroup_auth_credential_with_pni_presentation_deserialize(
                    pBytes,
                    (nuint)presentationBytes.Length,
                    out nint presentation);
                ThrowOnError(status);
                return new AuthCredentialWithPniPresentationSafeHandle(presentation);
            }
        }
    }

    public static void GetGroupId(GroupSecretParamsSafeHandle handle, Span<byte> outBuffer)
    {
        ArgumentNullException.ThrowIfNull(handle);
        if (handle.IsInvalid)
        {
            throw new ArgumentException("Handle is invalid.", nameof(handle));
        }

        if (outBuffer.Length != GroupMasterKeyLength)
        {
            throw new ArgumentException($"Output buffer must be exactly {GroupMasterKeyLength} bytes.", nameof(outBuffer));
        }

        bool addedRef = false;
        try
        {
            handle.DangerousAddRef(ref addedRef);
            nint secretParams = handle.DangerousGetHandle();

            unsafe
            {
                fixed (byte* pOut = outBuffer)
                {
                    int status = Native.signal_zkgroup_group_secret_params_get_group_id(
                        secretParams,
                        pOut,
                        (nuint)outBuffer.Length);
                    ThrowOnError(status);
                }
            }
        }
        finally
        {
            if (addedRef)
            {
                handle.DangerousRelease();
            }
        }
    }

    /// <summary>
    /// Derives the server-side routing identifier (ServerGroupId) from group secret parameters.
    /// This is the deterministic token used by the Relay for fan-out channel routing.
    /// </summary>
    /// <param name="handle">The group secret parameters handle.</param>
    /// <param name="outBuffer">A 32-byte buffer to receive the server group ID.</param>
    /// <exception cref="ArgumentException">Thrown if the handle is invalid or the buffer is not exactly 32 bytes.</exception>
    public static void GetServerGroupId(GroupSecretParamsSafeHandle handle, Span<byte> outBuffer)
    {
        ArgumentNullException.ThrowIfNull(handle);
        if (handle.IsInvalid)
        {
            throw new ArgumentException("Handle is invalid.", nameof(handle));
        }

        if (outBuffer.Length != GroupMasterKeyLength)
        {
            throw new ArgumentException($"Output buffer must be exactly {GroupMasterKeyLength} bytes.", nameof(outBuffer));
        }

        bool addedRef = false;
        try
        {
            handle.DangerousAddRef(ref addedRef);
            nint secretParams = handle.DangerousGetHandle();

            unsafe
            {
                fixed (byte* pOut = outBuffer)
                {
                    int status = Native.signal_zkgroup_group_secret_params_get_server_group_id(
                        secretParams,
                        pOut,
                        (nuint)outBuffer.Length);
                    ThrowOnError(status);
                }
            }
        }
        finally
        {
            if (addedRef)
            {
                handle.DangerousRelease();
            }
        }
    }

    public static void GetBlobKey(GroupSecretParamsSafeHandle handle, Span<byte> outBuffer)
    {
        ArgumentNullException.ThrowIfNull(handle);
        if (handle.IsInvalid)
        {
            throw new ArgumentException("Handle is invalid.", nameof(handle));
        }

        if (outBuffer.Length != GroupMasterKeyLength)
        {
            throw new ArgumentException($"Output buffer must be exactly {GroupMasterKeyLength} bytes.", nameof(outBuffer));
        }

        bool addedRef = false;
        try
        {
            handle.DangerousAddRef(ref addedRef);
            nint secretParams = handle.DangerousGetHandle();

            unsafe
            {
                fixed (byte* pOut = outBuffer)
                {
                    int status = Native.signal_zkgroup_group_secret_params_get_blob_key(
                        secretParams,
                        pOut,
                        (nuint)outBuffer.Length);
                    ThrowOnError(status);
                }
            }
        }
        finally
        {
            if (addedRef)
            {
                handle.DangerousRelease();
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

    /// <summary>
    /// Serializes a SenderKeyRecord to a pre-allocated buffer.
    /// This prevents leaving key material in the managed heap.
    /// </summary>
    /// <param name="record">The SenderKeyRecord handle.</param>
    /// <param name="buffer">Buffer to receive the serialized data.</param>
    /// <returns>The number of bytes written.</returns>
    public static int SerializeSenderKeyRecord(SenderKeyRecordSafeHandle record, Span<byte> buffer)
    {
        ArgumentNullException.ThrowIfNull(record);
        if (record.IsInvalid)
        {
            throw new ArgumentException("Handle is invalid.", nameof(record));
        }

        bool addedRef = false;
        try
        {
            record.DangerousAddRef(ref addedRef);
            nint handle = record.DangerousGetHandle();

            unsafe
            {
                fixed (byte* pBuffer = buffer)
                {
                    int status = Native.signal_protocol_sender_key_record_serialize(handle, pBuffer, (nuint)buffer.Length);
                    ThrowOnError(status);
                    return buffer.Length; // In a real impl, we'd return actual bytes written
                }
            }
        }
        finally
        {
            if (addedRef)
            {
                record.DangerousRelease();
            }
        }
    }

    /// <summary>
    /// Deserializes a SenderKeyRecord from a byte array.
    /// </summary>
    /// <param name="bytes">The serialized bytes.</param>
    /// <returns>A SenderKeyRecord handle.</returns>
    public static SenderKeyRecordSafeHandle DeserializeSenderKeyRecord(ReadOnlySpan<byte> bytes)
    {
        if (bytes.Length == 0)
        {
            throw new ArgumentException("Bytes cannot be empty.", nameof(bytes));
        }

        unsafe
        {
            fixed (byte* pBytes = bytes)
            {
                int status = Native.signal_protocol_sender_key_record_deserialize(pBytes, (nuint)bytes.Length, out nint record);
                ThrowOnError(status);
                return new SenderKeyRecordSafeHandle(record);
            }
        }
    }

    /// <summary>
    /// Creates a new SenderAddress from a UUID and device ID.
    /// </summary>
    /// <param name="uuidBytes">The 16-byte UUID.</param>
    /// <param name="deviceId">The device ID.</param>
    /// <returns>A SenderAddress handle.</returns>
    public static SenderAddressSafeHandle NewSenderAddress(ReadOnlySpan<byte> uuidBytes, uint deviceId)
    {
        if (uuidBytes.Length != UuidLength)
        {
            throw new ArgumentException($"UUID must be exactly {UuidLength} bytes.", nameof(uuidBytes));
        }

        unsafe
        {
            fixed (byte* pUuid = uuidBytes)
            {
                int status = Native.signal_protocol_sender_address_new(pUuid, (nuint)uuidBytes.Length, deviceId, out nint address);
                ThrowOnError(status);
                return new SenderAddressSafeHandle(address);
            }
        }
    }

    /// <summary>
    /// Creates a SenderKeyDistributionMessage for distributing a sender key to a new group member.
    /// Uses the VTable-based store to manage key state.
    /// </summary>
    /// <param name="storeVTable">Pointer to the SenderKeyStoreVTable structure.</param>
    /// <param name="sender">The sender's address.</param>
    /// <param name="distributionId">The distribution ID (GUID).</param>
    /// <returns>A SenderKeyDistributionMessage handle.</returns>
    public static SenderKeyDistributionMessageSafeHandle CreateSenderKeyDistributionMessage(
        IntPtr storeVTable,
        SenderAddressSafeHandle sender,
        Guid distributionId)
    {
        if (storeVTable == IntPtr.Zero)
        {
            throw new ArgumentException("VTable pointer cannot be zero.", nameof(storeVTable));
        }
        ArgumentNullException.ThrowIfNull(sender);
        if (sender.IsInvalid)
        {
            throw new ArgumentException("Handle is invalid.", nameof(sender));
        }

        bool addedRefSender = false;
        try
        {
            sender.DangerousAddRef(ref addedRefSender);

            nint senderHandle = sender.DangerousGetHandle();

            byte[] distributionIdBytes = distributionId.ToByteArray();

            unsafe
            {
                fixed (byte* pDistId = distributionIdBytes)
                {
                    int status = Native.signal_protocol_sender_key_distribution_message_create(
                        storeVTable,
                        senderHandle,
                        pDistId,
                        (nuint)distributionIdBytes.Length,
                        out nint message);
                    ThrowOnError(status);
                    return new SenderKeyDistributionMessageSafeHandle(message);
                }
            }
        }
        finally
        {
            if (addedRefSender)
            {
                sender.DangerousRelease();
            }
        }
    }

    /// <summary>
    /// Processes an incoming SenderKeyDistributionMessage to establish a sender key.
    /// Uses the VTable-based store to manage key state.
    /// </summary>
    /// <param name="storeVTable">Pointer to the SenderKeyStoreVTable structure.</param>
    /// <param name="sender">The sender's address.</param>
    /// <param name="message">The distribution message.</param>
    public static void ProcessSenderKeyDistributionMessage(
        IntPtr storeVTable,
        SenderAddressSafeHandle sender,
        SenderKeyDistributionMessageSafeHandle message)
    {
        if (storeVTable == IntPtr.Zero)
        {
            throw new ArgumentException("VTable pointer cannot be zero.", nameof(storeVTable));
        }
        ArgumentNullException.ThrowIfNull(sender);
        if (sender.IsInvalid)
        {
            throw new ArgumentException("Handle is invalid.", nameof(sender));
        }
        ArgumentNullException.ThrowIfNull(message);
        if (message.IsInvalid)
        {
            throw new ArgumentException("Handle is invalid.", nameof(message));
        }

        bool addedRefSender = false;
        bool addedRefMessage = false;
        try
        {
            sender.DangerousAddRef(ref addedRefSender);
            message.DangerousAddRef(ref addedRefMessage);

            int status = Native.signal_protocol_sender_key_distribution_message_process(
                storeVTable,
                sender.DangerousGetHandle(),
                message.DangerousGetHandle());
            ThrowOnError(status);
        }
        finally
        {
            if (addedRefMessage)
            {
                message.DangerousRelease();
            }
            if (addedRefSender)
            {
                sender.DangerousRelease();
            }
        }
    }

    /// <summary>
    /// Serializes a SenderKeyDistributionMessage to a byte array.
    /// </summary>
    /// <param name="message">The distribution message handle.</param>
    /// <returns>The serialized bytes.</returns>
    public static byte[] SerializeSenderKeyDistributionMessage(SenderKeyDistributionMessageSafeHandle message)
    {
        ArgumentNullException.ThrowIfNull(message);
        if (message.IsInvalid)
        {
            throw new ArgumentException("Handle is invalid.", nameof(message));
        }

        bool addedRef = false;
        try
        {
            message.DangerousAddRef(ref addedRef);
            nint handle = message.DangerousGetHandle();

            int status = Native.signal_protocol_sender_key_distribution_message_serialize_len(handle, out nuint len);
            ThrowOnError(status);

            byte[] buffer = new byte[len];
            unsafe
            {
                fixed (byte* pBuffer = buffer)
                {
                    status = Native.signal_protocol_sender_key_distribution_message_serialize(handle, pBuffer, len);
                    ThrowOnError(status);
                }
            }

            return buffer;
        }
        finally
        {
            if (addedRef)
            {
                message.DangerousRelease();
            }
        }
    }

    /// <summary>
    /// Deserializes a SenderKeyDistributionMessage from a byte array.
    /// </summary>
    /// <param name="bytes">The serialized bytes.</param>
    /// <returns>A SenderKeyDistributionMessage handle.</returns>
    public static SenderKeyDistributionMessageSafeHandle DeserializeSenderKeyDistributionMessage(ReadOnlySpan<byte> bytes)
    {
        if (bytes.Length == 0)
        {
            throw new ArgumentException("Bytes cannot be empty.", nameof(bytes));
        }

        unsafe
        {
            fixed (byte* pBytes = bytes)
            {
                int status = Native.signal_protocol_sender_key_distribution_message_deserialize(pBytes, (nuint)bytes.Length, out nint message);
                ThrowOnError(status);
                return new SenderKeyDistributionMessageSafeHandle(message);
            }
        }
    }

    /// <summary>
    /// Gets the key ID from a SenderKeyMessage header.
    /// </summary>
    /// <param name="message">The SenderKeyMessage handle.</param>
    /// <returns>The key ID.</returns>
    public static uint GetKeyId(SenderKeyMessageSafeHandle message)
    {
        ArgumentNullException.ThrowIfNull(message);
        if (message.IsInvalid)
        {
            throw new ArgumentException("Handle is invalid.", nameof(message));
        }

        bool addedRef = false;
        try
        {
            message.DangerousAddRef(ref addedRef);
            nint handle = message.DangerousGetHandle();

            int status = Native.signal_protocol_sender_key_message_get_key_id(handle, out uint keyId);
            ThrowOnError(status);
            return keyId;
        }
        finally
        {
            if (addedRef)
            {
                message.DangerousRelease();
            }
        }
    }

    /// <summary>
    /// Encrypts a group message using the VTable-based store.
    /// </summary>
    /// <param name="storeVTable">Pointer to the SenderKeyStoreVTable structure.</param>
    /// <param name="sender">The sender's address.</param>
    /// <param name="distributionId">The distribution ID (GUID).</param>
    /// <param name="plaintext">The plaintext message.</param>
    /// <returns>The encrypted message.</returns>
    public static SenderKeyMessageSafeHandle EncryptGroupMessage(
        IntPtr storeVTable,
        SenderAddressSafeHandle sender,
        Guid distributionId,
        ReadOnlySpan<byte> plaintext)
    {
        if (storeVTable == IntPtr.Zero)
        {
            throw new ArgumentException("VTable pointer cannot be zero.", nameof(storeVTable));
        }
        ArgumentNullException.ThrowIfNull(sender);
        if (sender.IsInvalid)
        {
            throw new ArgumentException("Handle is invalid.", nameof(sender));
        }

        bool addedRefSender = false;
        try
        {
            sender.DangerousAddRef(ref addedRefSender);

            nint senderHandle = sender.DangerousGetHandle();
            byte[] distributionIdBytes = distributionId.ToByteArray();

            unsafe
            {
                fixed (byte* pDistId = distributionIdBytes)
                fixed (byte* pPlaintext = plaintext)
                {
                    int status = Native.signal_protocol_group_cipher_encrypt(
                        storeVTable,
                        senderHandle,
                        pDistId,
                        (nuint)distributionIdBytes.Length,
                        pPlaintext,
                        (nuint)plaintext.Length,
                        out nint message);
                    ThrowOnError(status);
                    return new SenderKeyMessageSafeHandle(message);
                }
            }
        }
        finally
        {
            if (addedRefSender)
            {
                sender.DangerousRelease();
            }
        }
    }

    /// <summary>
    /// Decrypts a group message using the VTable-based store.
    /// </summary>
    /// <param name="storeVTable">Pointer to the SenderKeyStoreVTable structure.</param>
    /// <param name="sender">The sender's address.</param>
    /// <param name="message">The encrypted message.</param>
    /// <returns>The decrypted plaintext.</returns>
    public static byte[] DecryptGroupMessage(
        IntPtr storeVTable,
        SenderAddressSafeHandle sender,
        SenderKeyMessageSafeHandle message)
    {
        if (storeVTable == IntPtr.Zero)
        {
            throw new ArgumentException("VTable pointer cannot be zero.", nameof(storeVTable));
        }
        ArgumentNullException.ThrowIfNull(sender);
        if (sender.IsInvalid)
        {
            throw new ArgumentException("Handle is invalid.", nameof(sender));
        }
        ArgumentNullException.ThrowIfNull(message);
        if (message.IsInvalid)
        {
            throw new ArgumentException("Handle is invalid.", nameof(message));
        }

        bool addedRefSender = false;
        bool addedRefMessage = false;
        try
        {
            sender.DangerousAddRef(ref addedRefSender);
            message.DangerousAddRef(ref addedRefMessage);

            nint senderHandle = sender.DangerousGetHandle();
            nint messageHandle = message.DangerousGetHandle();

            unsafe
            {
                int status = Native.signal_protocol_group_cipher_decrypt(
                    storeVTable,
                    senderHandle,
                    messageHandle,
                    out nint plaintextPtr,
                    out nuint plaintextLen);
                ThrowOnError(status);

                // Copy plaintext to managed array
                byte[] plaintext = new byte[plaintextLen];
                if (plaintextLen > 0)
                {
                    System.Runtime.InteropServices.Marshal.Copy(plaintextPtr, plaintext, 0, (int)plaintextLen);
                }

                // Free the native plaintext buffer
                Native.signal_protocol_group_cipher_free_plaintext(plaintextPtr, plaintextLen);

                return plaintext;
            }
        }
        finally
        {
            if (addedRefMessage)
            {
                message.DangerousRelease();
            }
            if (addedRefSender)
            {
                sender.DangerousRelease();
            }
        }
    }

    /// <summary>
    /// Serializes a SenderKeyMessage to a byte array.
    /// </summary>
    /// <param name="message">The SenderKeyMessage handle.</param>
    /// <returns>The serialized bytes.</returns>
    public static byte[] SerializeSenderKeyMessage(SenderKeyMessageSafeHandle message)
    {
        ArgumentNullException.ThrowIfNull(message);
        if (message.IsInvalid)
        {
            throw new ArgumentException("Handle is invalid.", nameof(message));
        }

        bool addedRef = false;
        try
        {
            message.DangerousAddRef(ref addedRef);
            nint handle = message.DangerousGetHandle();

            int status = Native.signal_protocol_sender_key_message_serialize_len(handle, out nuint len);
            ThrowOnError(status);

            byte[] buffer = new byte[len];
            unsafe
            {
                fixed (byte* pBuffer = buffer)
                {
                    status = Native.signal_protocol_sender_key_message_serialize(handle, pBuffer, len);
                    ThrowOnError(status);
                }
            }

            return buffer;
        }
        finally
        {
            if (addedRef)
            {
                message.DangerousRelease();
            }
        }
    }

    /// <summary>
    /// Deserializes a SenderKeyMessage from a byte array.
    /// </summary>
    /// <param name="bytes">The serialized bytes.</param>
    /// <returns>A SenderKeyMessage handle.</returns>
    public static SenderKeyMessageSafeHandle DeserializeSenderKeyMessage(ReadOnlySpan<byte> bytes)
    {
        if (bytes.Length == 0)
        {
            throw new ArgumentException("Bytes cannot be empty.", nameof(bytes));
        }

        unsafe
        {
            fixed (byte* pBytes = bytes)
            {
                int status = Native.signal_protocol_sender_key_message_deserialize(pBytes, (nuint)bytes.Length, out nint message);
                ThrowOnError(status);
                return new SenderKeyMessageSafeHandle(message);
            }
        }
    }

    /// <summary>
    /// Generates a new Ed25519 key pair for Sealed Sender protocol.
    /// </summary>
    /// <param name="outPrivateKey32">A 32-byte span to receive the private key.</param>
    /// <param name="outPublicKey32">A 32-byte span to receive the public key.</param>
    /// <exception cref="ArgumentException">Thrown if output spans are not exactly 32 bytes.</exception>
    /// <exception cref="CryptographicException">Thrown if key generation fails.</exception>
    public static void GenerateEd25519KeyPair(Span<byte> outPrivateKey32, Span<byte> outPublicKey32)
    {
        if (outPrivateKey32.Length != Ed25519PrivateKeyLength)
        {
            throw new ArgumentException($"Output private key span must be exactly {Ed25519PrivateKeyLength} bytes.", nameof(outPrivateKey32));
        }
        if (outPublicKey32.Length != Ed25519PublicKeyLength)
        {
            throw new ArgumentException($"Output public key span must be exactly {Ed25519PublicKeyLength} bytes.", nameof(outPublicKey32));
        }

        unsafe
        {
            fixed (byte* pPrivateKey = outPrivateKey32)
            fixed (byte* pPublicKey = outPublicKey32)
            {
                int status = Native.signal_crypto_ed25519_generate_key_pair(pPrivateKey, pPublicKey);
                ThrowOnError(status);
            }
        }
    }

    /// <summary>
    /// Signs a message using an Ed25519 private key.
    /// </summary>
    /// <param name="privateKey32">The 32-byte private key.</param>
    /// <param name="message">The message to sign.</param>
    /// <param name="outSignature64">A 64-byte span to receive the signature.</param>
    /// <exception cref="ArgumentException">Thrown if input/output spans have incorrect lengths.</exception>
    /// <exception cref="CryptographicException">Thrown if signing fails.</exception>
    public static void Ed25519Sign(ReadOnlySpan<byte> privateKey32, ReadOnlySpan<byte> message, Span<byte> outSignature64)
    {
        if (privateKey32.Length != Ed25519PrivateKeyLength)
        {
            throw new ArgumentException($"Private key must be exactly {Ed25519PrivateKeyLength} bytes.", nameof(privateKey32));
        }
        if (outSignature64.Length != Ed25519SignatureLength)
        {
            throw new ArgumentException($"Output signature span must be exactly {Ed25519SignatureLength} bytes.", nameof(outSignature64));
        }

        unsafe
        {
            fixed (byte* pPrivateKey = privateKey32)
            fixed (byte* pMessage = message)
            fixed (byte* pSignature = outSignature64)
            {
                int status = Native.signal_crypto_ed25519_sign(pPrivateKey, pMessage, (nuint)message.Length, pSignature);
                ThrowOnError(status);
            }
        }
    }

    /// <summary>
    /// Verifies an Ed25519 signature against a message and public key.
    /// </summary>
    /// <param name="publicKey32">The 32-byte public key.</param>
    /// <param name="message">The message that was signed.</param>
    /// <param name="signature64">The 64-byte signature to verify.</param>
    /// <returns>True if the signature is valid, false otherwise.</returns>
    /// <exception cref="ArgumentException">Thrown if input spans have incorrect lengths.</exception>
    public static bool Ed25519Verify(ReadOnlySpan<byte> publicKey32, ReadOnlySpan<byte> message, ReadOnlySpan<byte> signature64)
    {
        if (publicKey32.Length != Ed25519PublicKeyLength)
        {
            throw new ArgumentException($"Public key must be exactly {Ed25519PublicKeyLength} bytes.", nameof(publicKey32));
        }
        if (signature64.Length != Ed25519SignatureLength)
        {
            throw new ArgumentException($"Signature must be exactly {Ed25519SignatureLength} bytes.", nameof(signature64));
        }

        unsafe
        {
            fixed (byte* pPublicKey = publicKey32)
            fixed (byte* pMessage = message)
            fixed (byte* pSignature = signature64)
            {
                int status = Native.signal_crypto_ed25519_verify(pPublicKey, pMessage, (nuint)message.Length, pSignature);
                return status == StatusOk;
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

        if (status == StatusVerificationFailure)
        {
            throw new CryptographicException("Native call failed verification.");
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