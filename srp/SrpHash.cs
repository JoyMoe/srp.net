using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace SecureRemotePassword;

/// <summary>
/// Hashing algorithm for the SRP-6a protocol.
/// </summary>
public class SrpHash : ISrpHash
{
    /// <summary>
    /// Initializes a new instance of the <see cref="SrpHash"/> class.
    /// </summary>
    /// <param name="hasherFactory">The hashing algorithm factory method.</param>
    /// <param name="algorithmName">The name of the algorithm.</param>
    public SrpHash(Func<HashAlgorithm> hasherFactory, string algorithmName = null) {
        HasherFactory = hasherFactory;
        AlgorithmName = algorithmName ?? Hasher.GetType().Name;
    }

    private Func<HashAlgorithm> HasherFactory { get; }

    private HashAlgorithm Hasher => HasherFactory();

    /// <summary>
    /// Computes the hash of the specified <see cref="string"/> or <see cref="SrpInteger"/> values.
    /// </summary>
    /// <param name="values">The values.</param>
    public SrpInteger ComputeHash(params object[] values) {
        return ComputeHash(Combine(values.Select(GetBytes).ToArray()));
    }

    /// <summary>
    /// Gets the size of the hash in bytes.
    /// </summary>
    public int HashSizeBytes => Hasher.HashSize / 8;

    /// <summary>
    /// Gets the name of the algorithm.
    /// </summary>
    public string AlgorithmName { get; }

    private SrpInteger ComputeHash(byte[] data) {
        var hash = Hasher.ComputeHash(data);
        return SrpInteger.FromByteArray(hash);

        // should yield the same result:
        // var hex = hash.Aggregate(new StringBuilder(), (sb, b) => sb.Append(b.ToString("X2")), sb => sb.ToString());
        // return SrpInteger.FromHex(hex);
    }

    /// <summary>
    /// Creates the hasher for the given hashing algorithm.
    /// </summary>
    /// <param name="algorithm">The name of the hashing algorithm.</param>
    public static HashAlgorithm CreateHasher(string algorithm) {
        return (HashAlgorithm)CryptoConfig.CreateFromName(algorithm);
    }

    private static byte[] EmptyBuffer { get; } = Array.Empty<byte>();

    private static byte[] GetBytes(object obj) {
        if (obj == null) {
            return EmptyBuffer;
        }

        var value = obj as string;
        if (!string.IsNullOrEmpty(value)) {
            return Encoding.UTF8.GetBytes(value);
        }

        var integer = obj as SrpInteger;
        if (integer != null) {
            return integer.ToByteArray();
        }

        return EmptyBuffer;
    }

    private static byte[] Combine(IList<byte[]> arrays) {
        var rv     = new byte[arrays.Sum(a => a.Length)];
        var offset = 0;

        foreach (var array in arrays) {
            Buffer.BlockCopy(array, 0, rv, offset, array.Length);
            offset += array.Length;
        }

        return rv;
    }
}
