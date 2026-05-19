using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using Signal.Interop;
using Xunit;

namespace Signal.Interop.Tests;

public class InteropTests
{
    [MethodImpl(MethodImplOptions.NoInlining)]
    private static void AllocateSecretParamsWithoutDispose()
    {
        Span<byte> randomness = stackalloc byte[SignalCrypto.GroupMasterKeyLength];
        randomness.Fill(4);
        _ = SignalCrypto.GenerateGroupSecretParams(randomness);
    }

    [Fact]
    public void RustBridge_TestConnection_Returns42()
    {
        // Act
        int result = SignalCrypto.TestConnection();

        // Assert
        Assert.Equal(42, result);
    }

    [Fact]
    public void GroupSecretParams_Generate_With32BytesRandomness_ReturnsInstance()
    {
        // Arrange
        Span<byte> randomness = stackalloc byte[SignalCrypto.GroupMasterKeyLength];
        randomness.Fill(7);

        // Act
        using GroupSecretParamsSafeHandle secretParams = SignalCrypto.GenerateGroupSecretParams(randomness);

        // Assert
        Assert.False(secretParams.IsInvalid);
    }

    [Fact]
    public void GroupSecretParams_GetGroupIdAndBlobKey_With32ByteBuffers_WritesBytes()
    {
        // Arrange
        Span<byte> randomness = stackalloc byte[SignalCrypto.GroupMasterKeyLength];
        randomness.Fill(9);

        using GroupSecretParamsSafeHandle secretParams = SignalCrypto.GenerateGroupSecretParams(randomness);

        Span<byte> groupId = stackalloc byte[SignalCrypto.GroupMasterKeyLength];
        Span<byte> blobKey = stackalloc byte[SignalCrypto.GroupMasterKeyLength];

        // Act
        SignalCrypto.GetGroupId(secretParams, groupId);
        SignalCrypto.GetBlobKey(secretParams, blobKey);

        // Assert
        bool anyGroupIdNonZero = false;
        bool anyBlobKeyNonZero = false;
        for (int i = 0; i < SignalCrypto.GroupMasterKeyLength; i++)
        {
            anyGroupIdNonZero |= groupId[i] != 0;
            anyBlobKeyNonZero |= blobKey[i] != 0;
        }

        Assert.True(anyGroupIdNonZero);
        Assert.True(anyBlobKeyNonZero);
    }

    [Fact]
    public void GroupSecretParams_GetBlobKey_IsDeterministicForMasterKey()
    {
        // Arrange
        Span<byte> randomness = stackalloc byte[SignalCrypto.GroupMasterKeyLength];
        randomness.Fill(11);

        using GroupSecretParamsSafeHandle secretParamsA = SignalCrypto.GenerateGroupSecretParams(randomness);
        using GroupMasterKeySafeHandle masterKey = SignalCrypto.GetGroupMasterKey(secretParamsA);
        using GroupSecretParamsSafeHandle secretParamsB = SignalCrypto.DeriveGroupSecretParams(masterKey);

        Span<byte> blobKeyA = stackalloc byte[SignalCrypto.GroupMasterKeyLength];
        Span<byte> blobKeyB = stackalloc byte[SignalCrypto.GroupMasterKeyLength];

        // Act
        SignalCrypto.GetBlobKey(secretParamsA, blobKeyA);
        SignalCrypto.GetBlobKey(secretParamsB, blobKeyB);

        // Assert
        for (int i = 0; i < SignalCrypto.GroupMasterKeyLength; i++)
        {
            Assert.Equal(blobKeyA[i], blobKeyB[i]);
        }
    }

    [Fact]
    public void GroupMasterKey_SerializeDeserialize_RoundTripsBytes()
    {
        // Arrange
        Span<byte> randomness = stackalloc byte[SignalCrypto.GroupMasterKeyLength];
        randomness.Fill(2);

        using GroupSecretParamsSafeHandle secretParams = SignalCrypto.GenerateGroupSecretParams(randomness);
        using GroupMasterKeySafeHandle masterKey = SignalCrypto.GetGroupMasterKey(secretParams);

        // Act
        byte[] bytesA = SignalCrypto.SerializeGroupMasterKey(masterKey);
        using GroupMasterKeySafeHandle masterKeyB = SignalCrypto.DeserializeGroupMasterKey(bytesA);
        byte[] bytesB = SignalCrypto.SerializeGroupMasterKey(masterKeyB);

        // Assert
        Assert.Equal(bytesA, bytesB);
    }

    [Fact]
    public void Generate_WithWrongLengthRandomness_ThrowsArgumentException()
    {
        // Arrange
        Span<byte> randomness = stackalloc byte[SignalCrypto.GroupMasterKeyLength - 1];

        // Act
        try
        {
            _ = SignalCrypto.GenerateGroupSecretParams(randomness);
        }
        catch (ArgumentException)
        {
            // Assert
            return;
        }

        Assert.Fail("Expected ArgumentException was not thrown.");
    }

    [Fact]
    public void GetGroupId_WithWrongLengthOutputBuffer_ThrowsArgumentException()
    {
        // Arrange
        Span<byte> randomness = stackalloc byte[SignalCrypto.GroupMasterKeyLength];
        randomness.Fill(12);
        using GroupSecretParamsSafeHandle secretParams = SignalCrypto.GenerateGroupSecretParams(randomness);

        Span<byte> outBuffer = stackalloc byte[SignalCrypto.GroupMasterKeyLength - 1];

        // Act
        try
        {
            SignalCrypto.GetGroupId(secretParams, outBuffer);
        }
        catch (ArgumentException)
        {
            // Assert
            return;
        }

        Assert.Fail("Expected ArgumentException was not thrown.");
    }

    [Fact]
    public void GetBlobKey_WithWrongLengthOutputBuffer_ThrowsArgumentException()
    {
        // Arrange
        Span<byte> randomness = stackalloc byte[SignalCrypto.GroupMasterKeyLength];
        randomness.Fill(13);
        using GroupSecretParamsSafeHandle secretParams = SignalCrypto.GenerateGroupSecretParams(randomness);

        Span<byte> outBuffer = stackalloc byte[SignalCrypto.GroupMasterKeyLength - 1];

        // Act
        try
        {
            SignalCrypto.GetBlobKey(secretParams, outBuffer);
        }
        catch (ArgumentException)
        {
            // Assert
            return;
        }

        Assert.Fail("Expected ArgumentException was not thrown.");
    }

    [Fact]
    public void DeserializeMasterKey_WithWrongLength_ThrowsArgumentException()
    {
        // Arrange
        Span<byte> bytes = stackalloc byte[SignalCrypto.GroupMasterKeyLength - 1];

        // Act
        try
        {
            _ = SignalCrypto.DeserializeGroupMasterKey(bytes);
        }
        catch (ArgumentException)
        {
            // Assert
            return;
        }

        Assert.Fail("Expected ArgumentException was not thrown.");
    }

    [Fact]
    public void SafeHandle_Dispose_IsIdempotent()
    {
        // Arrange
        Span<byte> randomness = stackalloc byte[SignalCrypto.GroupMasterKeyLength];
        randomness.Fill(3);

        GroupSecretParamsSafeHandle secretParams = SignalCrypto.GenerateGroupSecretParams(randomness);

        // Act
        secretParams.Dispose();
        secretParams.Dispose();

        // Assert
        Assert.True(secretParams.IsClosed);
    }

    [Fact]
    public void SafeHandle_Finalizer_DoesNotCrash()
    {
        // Act
        AllocateSecretParamsWithoutDispose();
        GC.Collect();
        GC.WaitForPendingFinalizers();
        GC.Collect();

        // Assert
        Assert.True(true);
    }

    [Fact]
    public async Task ConcurrentDispose_DoesNotCrash()
    {
        // Arrange
        Span<byte> randomness = stackalloc byte[SignalCrypto.GroupMasterKeyLength];
        randomness.Fill(5);
        GroupSecretParamsSafeHandle secretParams = SignalCrypto.GenerateGroupSecretParams(randomness);

        // Act
        Task t1 = Task.Run(() => secretParams.Dispose());
        Task t2 = Task.Run(() => secretParams.Dispose());
        await Task.WhenAll(t1, t2);

        // Assert
        Assert.True(secretParams.IsClosed);
    }
}