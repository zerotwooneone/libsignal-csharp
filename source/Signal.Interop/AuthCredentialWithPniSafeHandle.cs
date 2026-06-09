using System;
using System.Runtime.InteropServices;

namespace Signal.Interop;

public sealed partial class AuthCredentialWithPniSafeHandle : SafeHandle
{
    private AuthCredentialWithPniSafeHandle() : base(IntPtr.Zero, ownsHandle: true)
    {
    }

    internal AuthCredentialWithPniSafeHandle(nint handle) : base(IntPtr.Zero, ownsHandle: true)
    {
        SetHandle(handle);
    }

    public override bool IsInvalid => handle == IntPtr.Zero;

    protected override bool ReleaseHandle()
    {
        SignalCrypto.Native.signal_zkgroup_auth_credential_with_pni_free(handle);
        return true;
    }
}
