using Signal.Interop;
using Xunit;

namespace Signal.Interop.Tests;

/// <summary>
/// Tests for Ed25519 cryptographic operations (key generation, signing, verification).
/// These tests validate the FFI boundary and memory safety for Sealed Sender protocol.
/// </summary>
public class Ed25519CryptoTests
{
    [Fact]
    public void GenerateKeyPair_SignMessage_VerifySucceeds()
    {
        // ARRANGE
        byte[] privateKey = new byte[SignalCrypto.Ed25519PrivateKeyLength];
        byte[] publicKey = new byte[SignalCrypto.Ed25519PublicKeyLength];
        byte[] message = new byte[100];
        new Random().NextBytes(message);
        byte[] signature = new byte[SignalCrypto.Ed25519SignatureLength];

        // ACT - Generate key pair
        SignalCrypto.GenerateEd25519KeyPair(privateKey, publicKey);

        // ACT - Sign the message
        SignalCrypto.Ed25519Sign(privateKey, message, signature);

        // ACT - Verify the signature
        bool isValid = SignalCrypto.Ed25519Verify(publicKey, message, signature);

        // ASSERT - Signature should be valid
        Assert.True(isValid);
    }

    [Fact]
    public void Verify_WithBadSignature_ReturnsFalse()
    {
        // ARRANGE
        byte[] privateKey = new byte[SignalCrypto.Ed25519PrivateKeyLength];
        byte[] publicKey = new byte[SignalCrypto.Ed25519PublicKeyLength];
        byte[] message = new byte[100];
        new Random().NextBytes(message);
        byte[] signature = new byte[SignalCrypto.Ed25519SignatureLength];

        // Generate key pair and sign message
        SignalCrypto.GenerateEd25519KeyPair(privateKey, publicKey);
        SignalCrypto.Ed25519Sign(privateKey, message, signature);

        // ACT - Corrupt one byte of the signature
        signature[0] ^= 0xFF;

        // ACT - Verify the corrupted signature
        bool isValid = SignalCrypto.Ed25519Verify(publicKey, message, signature);

        // ASSERT - Signature should be invalid
        Assert.False(isValid);
    }

    [Fact]
    public void Verify_WithBadMessage_ReturnsFalse()
    {
        // ARRANGE
        byte[] privateKey = new byte[SignalCrypto.Ed25519PrivateKeyLength];
        byte[] publicKey = new byte[SignalCrypto.Ed25519PublicKeyLength];
        byte[] message = new byte[100];
        new Random().NextBytes(message);
        byte[] signature = new byte[SignalCrypto.Ed25519SignatureLength];

        // Generate key pair and sign message
        SignalCrypto.GenerateEd25519KeyPair(privateKey, publicKey);
        SignalCrypto.Ed25519Sign(privateKey, message, signature);

        // ACT - Corrupt one byte of the message
        message[0] ^= 0xFF;

        // ACT - Verify the signature against corrupted message
        bool isValid = SignalCrypto.Ed25519Verify(publicKey, message, signature);

        // ASSERT - Signature should be invalid
        Assert.False(isValid);
    }
}
