using System.Runtime.CompilerServices;
using System.Security.Cryptography;

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
    public void AuthCredentialWithPni_FullLoop_IssueReceivePresentVerify_Succeeds()
    {
        // Arrange
        Span<byte> serverRand = stackalloc byte[SignalCrypto.GroupMasterKeyLength];
        serverRand.Fill(1);
        using ServerSecretParamsSafeHandle serverSecret = SignalCrypto.GenerateServerSecretParams(serverRand);
        using ServerPublicParamsSafeHandle serverPublic = SignalCrypto.GetServerPublicParams(serverSecret);

        Span<byte> groupRand = stackalloc byte[SignalCrypto.GroupMasterKeyLength];
        groupRand.Fill(2);
        using GroupSecretParamsSafeHandle groupSecret = SignalCrypto.GenerateGroupSecretParams(groupRand);
        using GroupPublicParamsSafeHandle groupPublic = SignalCrypto.GetGroupPublicParams(groupSecret);

        Span<byte> aci = stackalloc byte[SignalCrypto.UuidLength];
        Span<byte> pni = stackalloc byte[SignalCrypto.UuidLength];
        aci.Fill((byte)'a');
        pni.Fill((byte)'p');

        const ulong redemptionTime = 12345UL * 86400UL;

        Span<byte> issueRand = stackalloc byte[SignalCrypto.GroupMasterKeyLength];
        issueRand.Fill(3);

        using AuthCredentialWithPniResponseSafeHandle response = SignalCrypto.IssueAuthCredentialWithPni(
            aci,
            pni,
            redemptionTime,
            serverSecret,
            issueRand);

        using AuthCredentialWithPniSafeHandle credential = SignalCrypto.ReceiveAuthCredentialWithPni(
            response,
            aci,
            pni,
            redemptionTime,
            serverPublic);

        Span<byte> presentRand = stackalloc byte[SignalCrypto.GroupMasterKeyLength];
        presentRand.Fill(4);

        using AuthCredentialWithPniPresentationSafeHandle presentation = SignalCrypto.PresentAuthCredentialWithPni(
            credential,
            serverPublic,
            groupSecret,
            presentRand);

        // Act
        SignalCrypto.VerifyAuthCredentialWithPniPresentation(
            presentation,
            serverSecret,
            groupPublic,
            redemptionTime);

        // Assert
        Assert.True(true);
    }

    [Fact]
    public void AuthCredentialWithPni_Verify_WithWrongRedemptionTime_ThrowsCryptographicException()
    {
        // Arrange
        Span<byte> serverRand = stackalloc byte[SignalCrypto.GroupMasterKeyLength];
        serverRand.Fill(5);
        using ServerSecretParamsSafeHandle serverSecret = SignalCrypto.GenerateServerSecretParams(serverRand);
        using ServerPublicParamsSafeHandle serverPublic = SignalCrypto.GetServerPublicParams(serverSecret);

        Span<byte> groupRand = stackalloc byte[SignalCrypto.GroupMasterKeyLength];
        groupRand.Fill(6);
        using GroupSecretParamsSafeHandle groupSecret = SignalCrypto.GenerateGroupSecretParams(groupRand);
        using GroupPublicParamsSafeHandle groupPublic = SignalCrypto.GetGroupPublicParams(groupSecret);

        Span<byte> aci = stackalloc byte[SignalCrypto.UuidLength];
        Span<byte> pni = stackalloc byte[SignalCrypto.UuidLength];
        aci.Fill((byte)'a');
        pni.Fill((byte)'p');

        const ulong redemptionTime = 20000UL * 86400UL;
        const ulong wrongRedemptionTime = 20001UL * 86400UL;

        Span<byte> issueRand = stackalloc byte[SignalCrypto.GroupMasterKeyLength];
        issueRand.Fill(7);
        using AuthCredentialWithPniResponseSafeHandle response = SignalCrypto.IssueAuthCredentialWithPni(
            aci,
            pni,
            redemptionTime,
            serverSecret,
            issueRand);

        using AuthCredentialWithPniSafeHandle credential = SignalCrypto.ReceiveAuthCredentialWithPni(
            response,
            aci,
            pni,
            redemptionTime,
            serverPublic);

        Span<byte> presentRand = stackalloc byte[SignalCrypto.GroupMasterKeyLength];
        presentRand.Fill(8);
        using AuthCredentialWithPniPresentationSafeHandle presentation = SignalCrypto.PresentAuthCredentialWithPni(
            credential,
            serverPublic,
            groupSecret,
            presentRand);

        // Act
        try
        {
            SignalCrypto.VerifyAuthCredentialWithPniPresentation(presentation, serverSecret, groupPublic, wrongRedemptionTime);
        }
        catch (CryptographicException)
        {
            // Assert
            return;
        }

        Assert.Fail("Expected CryptographicException was not thrown.");
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

    // Feature 1: ServerGroupId tests
    [Fact]
    public void GetServerGroupId_WithValidParams_Writes32Bytes()
    {
        // Arrange
        Span<byte> randomness = stackalloc byte[SignalCrypto.GroupMasterKeyLength];
        randomness.Fill(14);
        using GroupSecretParamsSafeHandle secretParams = SignalCrypto.GenerateGroupSecretParams(randomness);
        Span<byte> serverGroupId = stackalloc byte[SignalCrypto.GroupMasterKeyLength];

        // Act
        SignalCrypto.GetServerGroupId(secretParams, serverGroupId);

        // Assert
        bool anyNonZero = false;
        for (int i = 0; i < SignalCrypto.GroupMasterKeyLength; i++)
        {
            anyNonZero |= serverGroupId[i] != 0;
        }
        Assert.True(anyNonZero);
    }

    [Fact]
    public void GetServerGroupId_WithWrongLengthBuffer_ThrowsArgumentException()
    {
        // Arrange
        Span<byte> randomness = stackalloc byte[SignalCrypto.GroupMasterKeyLength];
        randomness.Fill(15);
        using GroupSecretParamsSafeHandle secretParams = SignalCrypto.GenerateGroupSecretParams(randomness);
        Span<byte> outBuffer = stackalloc byte[SignalCrypto.GroupMasterKeyLength - 1];

        // Act
        try
        {
            SignalCrypto.GetServerGroupId(secretParams, outBuffer);
        }
        catch (ArgumentException)
        {
            // Assert
            return;
        }

        Assert.Fail("Expected ArgumentException was not thrown.");
    }

    // Feature 2: SenderKeyRecord tests
    [Fact]
    public void SenderKeyRecord_SerializeDeserialize_RoundTrips()
    {
        // ARRANGE - Create a valid SenderKeyRecord via GroupSessionBuilder
        using var store = new InMemorySenderKeyStore();
        Span<byte> uuid = stackalloc byte[SignalCrypto.UuidLength];
        uuid.Fill((byte)'a');
        using var address = SignalCrypto.NewSenderAddress(uuid, 1);
        Guid distributionId = Guid.NewGuid();

        // Create a distribution message, which internally creates a SenderKeyRecord
        using var distributionMessage = SignalCrypto.CreateSenderKeyDistributionMessage(
            store.CreateVTable(), address, distributionId);

        // The store now contains a serialized SenderKeyRecord
        // Get it from the cache
        byte[] serializedRecord = store.Cache.Values.First();

        // ACT - Deserialize the record
        using var deserializedRecord = SignalCrypto.DeserializeSenderKeyRecord(serializedRecord);

        // ACT - Serialize it again (requires a buffer)
        byte[] reserializedRecord = new byte[serializedRecord.Length];
        int bytesWritten = SignalCrypto.SerializeSenderKeyRecord(deserializedRecord, reserializedRecord);

        // ASSERT - The reserialized bytes should match the original
        Assert.Equal(serializedRecord.Length, bytesWritten);
        Assert.Equal(serializedRecord, reserializedRecord);
    }

    [Fact]
    public void SenderKeyRecord_Deserialize_WithEmptyBytes_ThrowsArgumentException()
    {
        // Arrange
        byte[] bytes = Array.Empty<byte>();

        // Act
        try
        {
            _ = SignalCrypto.DeserializeSenderKeyRecord(bytes);
        }
        catch (ArgumentException)
        {
            // Assert
            return;
        }

        Assert.Fail("Expected ArgumentException was not thrown.");
    }

    // Feature 3: SenderAddress and SenderKeyDistributionMessage tests
    [Fact]
    public void NewSenderAddress_WithValidUuid_ReturnsValidHandle()
    {
        // Arrange
        Span<byte> uuid = stackalloc byte[SignalCrypto.UuidLength];
        uuid.Fill(16);
        uint deviceId = 1;

        // Act
        using SenderAddressSafeHandle address = SignalCrypto.NewSenderAddress(uuid, deviceId);

        // Assert
        Assert.False(address.IsInvalid);
    }

    [Fact]
    public void NewSenderAddress_WithWrongLength_ThrowsArgumentException()
    {
        // Arrange
        Span<byte> uuid = stackalloc byte[SignalCrypto.UuidLength - 1];
        uint deviceId = 1;

        // Act
        try
        {
            _ = SignalCrypto.NewSenderAddress(uuid, deviceId);
        }
        catch (ArgumentException)
        {
            // Assert
            return;
        }

        Assert.Fail("Expected ArgumentException was not thrown.");
    }

    [Fact]
    public void SenderKeyDistributionMessage_SerializeDeserialize_RoundTrips()
    {
        // ARRANGE - Create a valid SenderKeyDistributionMessage via GroupSessionBuilder
        using var store = new InMemorySenderKeyStore();
        Span<byte> uuid = stackalloc byte[SignalCrypto.UuidLength];
        uuid.Fill((byte)'a');
        using var address = SignalCrypto.NewSenderAddress(uuid, 1);
        Guid distributionId = Guid.NewGuid();

        using var distributionMessage = SignalCrypto.CreateSenderKeyDistributionMessage(
            store.CreateVTable(), address, distributionId);

        // ACT - Serialize the message
        byte[] serializedMessage = SignalCrypto.SerializeSenderKeyDistributionMessage(distributionMessage);

        // ACT - Deserialize it
        using var deserializedMessage = SignalCrypto.DeserializeSenderKeyDistributionMessage(serializedMessage);

        // ACT - Serialize it again
        byte[] reserializedMessage = SignalCrypto.SerializeSenderKeyDistributionMessage(deserializedMessage);

        // ASSERT - The reserialized bytes should match the original
        Assert.Equal(serializedMessage, reserializedMessage);
    }

    // Feature 4: GroupCipher and SenderKeyMessage tests
    [Fact]
    public void GetKeyId_WithValidMessage_ReturnsKeyId()
    {
        // ARRANGE - Create a valid SenderKeyMessage via GroupCipher
        using var store = new InMemorySenderKeyStore();
        Span<byte> uuid = stackalloc byte[SignalCrypto.UuidLength];
        uuid.Fill((byte)'a');
        using var address = SignalCrypto.NewSenderAddress(uuid, 1);
        Guid distributionId = Guid.NewGuid();

        // Establish session
        using var distributionMessage = SignalCrypto.CreateSenderKeyDistributionMessage(
            store.CreateVTable(), address, distributionId);

        // Encrypt a message
        byte[] plaintext = System.Text.Encoding.UTF8.GetBytes("test message");
        using var ciphertextMessage = SignalCrypto.EncryptGroupMessage(
            store.CreateVTable(), address, distributionId, plaintext);

        // ACT - Extract the key ID
        uint keyId = SignalCrypto.GetKeyId(ciphertextMessage);

        // ASSERT - Key ID should be valid (non-zero)
        Assert.NotEqual(0u, keyId);
    }

    [Fact]
    public void SenderKeyMessage_SerializeDeserialize_RoundTrips()
    {
        // ARRANGE - Create a valid SenderKeyMessage via GroupCipher
        using var store = new InMemorySenderKeyStore();
        Span<byte> uuid = stackalloc byte[SignalCrypto.UuidLength];
        uuid.Fill((byte)'a');
        using var address = SignalCrypto.NewSenderAddress(uuid, 1);
        Guid distributionId = Guid.NewGuid();

        // Establish session
        using var distributionMessage = SignalCrypto.CreateSenderKeyDistributionMessage(
            store.CreateVTable(), address, distributionId);

        // Encrypt a message
        byte[] plaintext = System.Text.Encoding.UTF8.GetBytes("test message");
        using var ciphertextMessage = SignalCrypto.EncryptGroupMessage(
            store.CreateVTable(), address, distributionId, plaintext);

        // ACT - Serialize the message
        byte[] serializedMessage = SignalCrypto.SerializeSenderKeyMessage(ciphertextMessage);

        // ACT - Deserialize it
        using var deserializedMessage = SignalCrypto.DeserializeSenderKeyMessage(serializedMessage);

        // ACT - Serialize it again
        byte[] reserializedMessage = SignalCrypto.SerializeSenderKeyMessage(deserializedMessage);

        // ASSERT - The reserialized bytes should match the original
        Assert.Equal(serializedMessage, reserializedMessage);
    }

    // Group V2 Round-Trip Tests
    [Fact]
    public void ProcessSenderKeyDistributionMessage_GivenValidMessageFromAlice_BobRegistersSessionWithoutError()
    {
        // ARRANGE
        using var aliceStore = new InMemorySenderKeyStore();
        using var bobStore = new InMemorySenderKeyStore();
        
        // Create Alice's address
        Span<byte> aliceUuid = stackalloc byte[SignalCrypto.UuidLength];
        aliceUuid.Fill((byte)'a');
        using var aliceAddress = SignalCrypto.NewSenderAddress(aliceUuid, 1);

        // Generate a distribution ID
        Guid distributionId = Guid.NewGuid();

        // ACT - Alice creates the distribution message (Simulating group invite)
        using var distributionMessage = SignalCrypto.CreateSenderKeyDistributionMessage(
            aliceStore.CreateVTable(), 
            aliceAddress,
            distributionId);

        // ACT - Bob processes Alice's message
        SignalCrypto.ProcessSenderKeyDistributionMessage(
            bobStore.CreateVTable(), 
            aliceAddress, 
            distributionMessage);

        // ASSERT
        // We do not reflect into the crypto state. We assert the behavioral side-effect:
        // Bob's store MUST now contain a record for Alice's address and distribution ID.
        // The cache key format is "senderAddressPtr:distributionId"
        Assert.True(bobStore.Cache.Count > 0);
    }

    [Fact]
    public void DecryptGroupMessage_GivenValidCiphertextFromAlice_BobRecoversOriginalPlaintext()
    {
        // ARRANGE - Fully establish the session first
        using var aliceStore = new InMemorySenderKeyStore();
        using var bobStore = new InMemorySenderKeyStore();
        
        // Create Alice's address
        Span<byte> aliceUuid = stackalloc byte[SignalCrypto.UuidLength];
        aliceUuid.Fill((byte)'a');
        using var aliceAddress = SignalCrypto.NewSenderAddress(aliceUuid, 1);
        
        // Generate a distribution ID
        Guid distributionId = Guid.NewGuid();

        // Alice creates the distribution message
        using var distributionMessage = SignalCrypto.CreateSenderKeyDistributionMessage(
            aliceStore.CreateVTable(), 
            aliceAddress,
            distributionId);
        
        // Bob processes Alice's message
        SignalCrypto.ProcessSenderKeyDistributionMessage(
            bobStore.CreateVTable(), 
            aliceAddress, 
            distributionMessage);

        var originalPlaintext = System.Text.Encoding.UTF8.GetBytes("The Relay is blind.");

        // ACT - Alice encrypts the message
        using var ciphertextMessage = SignalCrypto.EncryptGroupMessage(
            aliceStore.CreateVTable(), 
            aliceAddress,
            distributionId,
            originalPlaintext);

        // ACT - Bob decrypts the message
        var recoveredPlaintext = SignalCrypto.DecryptGroupMessage(
            bobStore.CreateVTable(), 
            aliceAddress, 
            ciphertextMessage);

        // ASSERT
        // Black Box check: the output must perfectly match the input.
        Assert.Equal(originalPlaintext, recoveredPlaintext);
    }
}