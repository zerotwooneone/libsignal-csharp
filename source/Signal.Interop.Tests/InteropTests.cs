using Xunit;
using Signal.Interop;

namespace Signal.Interop.Tests;

public class InteropTests
{
    [Fact]
    public void RustBridge_TestConnection_Returns42()
    {
        // Act
        int result = SignalCrypto.TestConnection();

        // Assert
        Assert.Equal(42, result);
    }
}