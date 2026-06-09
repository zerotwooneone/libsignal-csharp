using System;
using System.Runtime.InteropServices;

namespace Signal.Interop;

public sealed partial class AuthCredentialWithPniResponseSafeHandle : SafeHandle
{
    private AuthCredentialWithPniResponseSafeHandle() : base(IntPtr.Zero, ownsHandle: true)
    {
    }

    internal AuthCredentialWithPniResponseSafeHandle(nint handle) : base(IntPtr.Zero, ownsHandle: true)
    {
        SetHandle(handle);
    }

    public override bool IsInvalid => handle == IntPtr.Zero;

    protected override bool ReleaseHandle()
    {
        SignalCrypto.Native.signal_zkgroup_auth_credential_with_pni_response_free(handle);
        return true;
    }
}
