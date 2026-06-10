using System.Runtime.InteropServices;
using Signal.Interop;

namespace Signal.Interop.Tests;

/// <summary>
/// In-memory implementation of SenderKeyStore for testing.
/// This isolates the cryptographic logic by providing a real VTable implementation
/// that stores SenderKeyRecords in memory instead of a database.
/// </summary>
public class InMemorySenderKeyStore : IDisposable
{
    // Cache key format: "senderAddressPtr:distributionId"
    // Using the pointer value as a simple key since we control the test setup
    private readonly Dictionary<string, byte[]> _cache = new();

    /// <summary>
    /// Gets the internal cache for test assertions.
    /// </summary>
    public IReadOnlyDictionary<string, byte[]> Cache => _cache;

    /// <summary>
    /// Load callback implementation for the VTable.
    /// </summary>
    private unsafe int LoadKey(
        IntPtr senderAddress,
        byte* distributionIdBytes,
        UIntPtr distributionIdLen,
        out IntPtr outRecord,
        out UIntPtr outLen)
    {
        outRecord = IntPtr.Zero;
        outLen = UIntPtr.Zero;

        try
        {
            // Extract distribution ID as GUID
            if (distributionIdLen != 16)
            {
                return 1; // Not found / invalid
            }

            Guid distributionId = new Guid(new ReadOnlySpan<byte>(distributionIdBytes, (int)distributionIdLen));
            
            // Create cache key using sender address pointer value
            string cacheKey = $"{senderAddress.ToInt64():X16}:{distributionId}";
            
            if (_cache.TryGetValue(cacheKey, out byte[]? recordBytes))
            {
                // Allocate memory for the record bytes
                IntPtr recordPtr = Marshal.AllocHGlobal(recordBytes.Length);
                Marshal.Copy(recordBytes, 0, recordPtr, recordBytes.Length);
                
                outRecord = recordPtr;
                outLen = (UIntPtr)recordBytes.Length;
                return 0; // Success
            }
            
            return 1; // Not found
        }
        catch
        {
            return -1; // Error
        }
    }

    /// <summary>
    /// Store callback implementation for the VTable.
    /// </summary>
    private unsafe int StoreKey(
        IntPtr senderAddress,
        byte* distributionIdBytes,
        UIntPtr distributionIdLen,
        byte* recordBytes,
        UIntPtr recordLen)
    {
        try
        {
            // Extract distribution ID as GUID
            if (distributionIdLen != 16)
            {
                return -1; // Invalid
            }

            Guid distributionId = new Guid(new ReadOnlySpan<byte>(distributionIdBytes, (int)distributionIdLen));
            
            // Copy record bytes to managed array
            byte[] recordArray = new byte[recordLen];
            Marshal.Copy(new IntPtr(recordBytes), recordArray, 0, (int)recordLen);
            
            // Create cache key using sender address pointer value
            string cacheKey = $"{senderAddress.ToInt64():X16}:{distributionId}";
            
            // Store in cache
            _cache[cacheKey] = recordArray;
            
            return 0; // Success
        }
        catch
        {
            return -1; // Error
        }
    }

    private Signal.Interop.LoadSenderKeyDelegate? _loadDelegate;
    private Signal.Interop.StoreSenderKeyDelegate? _storeDelegate;
    private GCHandle _loadDelegateHandle;
    private GCHandle _storeDelegateHandle;
    private GCHandle _vTableHandle;

    /// <summary>
    /// Creates a pointer to a SenderKeyStoreVTable wired to this in-memory store.
    /// The VTable struct is pinned in memory to prevent GC movement.
    /// </summary>
    public unsafe IntPtr CreateVTable()
    {
        // Create delegate instances and keep them alive
        // The delegates must be kept alive as long as the VTable is in use
        _loadDelegate = LoadKey;
        _storeDelegate = StoreKey;
        
        // Pin the delegates to prevent GC
        _loadDelegateHandle = GCHandle.Alloc(_loadDelegate);
        _storeDelegateHandle = GCHandle.Alloc(_storeDelegate);
        
        // Create function pointers
        IntPtr loadPtr = Marshal.GetFunctionPointerForDelegate(_loadDelegate);
        IntPtr storePtr = Marshal.GetFunctionPointerForDelegate(_storeDelegate);
        
        // Create and pin the VTable struct
        var vTable = new SenderKeyStoreVTable
        {
            LoadSenderKey = loadPtr,
            StoreSenderKey = storePtr
        };
        
        _vTableHandle = GCHandle.Alloc(vTable, GCHandleType.Pinned);
        return _vTableHandle.AddrOfPinnedObject();
    }

    /// <summary>
    /// Releases the delegate handles.
    /// </summary>
    public void Dispose()
    {
        if (_loadDelegateHandle.IsAllocated)
        {
            _loadDelegateHandle.Free();
        }
        if (_storeDelegateHandle.IsAllocated)
        {
            _storeDelegateHandle.Free();
        }
        if (_vTableHandle.IsAllocated)
        {
            _vTableHandle.Free();
        }
    }
}
