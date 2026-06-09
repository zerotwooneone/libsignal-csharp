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