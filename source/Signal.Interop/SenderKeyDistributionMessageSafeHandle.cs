using System;
using System.Runtime.InteropServices;

namespace Signal.Interop;

/// <summary>
/// SafeHandle wrapper for the native SenderKeyDistributionMessage opaque handle.
/// Represents the distribution message sent when a peer joins a group.
/// </summary>
public sealed partial class SenderKeyDistributionMessageSafeHandle : SafeHandle
{
    private SenderKeyDistributionMessageSafeHandle() : base(IntPtr.Zero, ownsHandle: true)
    {
    }

    internal SenderKeyDistributionMessageSafeHandle(nint handle) : base(IntPtr.Zero, ownsHandle: true)
    {
        SetHandle(handle);
    }

    public override bool IsInvalid => handle == IntPtr.Zero;

    protected override bool ReleaseHandle()
    {
        SignalCrypto.Native.signal_protocol_sender_key_distribution_message_free(handle);
        return true;
    }
}
