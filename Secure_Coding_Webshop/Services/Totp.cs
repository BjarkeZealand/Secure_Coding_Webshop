using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;

namespace Secure_Coding_Webshop.Services;

/// <summary>TOTP efter RFC 6238 (HMAC-SHA1, 6 cifre, 30 sekunder) – kompatibel med Google Authenticator m.fl.</summary>
public static class Totp
{
    public const int StepSeconds = 30;

    public static long CurrentStep(DateTimeOffset now) => now.ToUnixTimeSeconds() / StepSeconds;

    public static string Compute(ReadOnlySpan<byte> key, long step)
    {
        Span<byte> message = stackalloc byte[8];
        BinaryPrimitives.WriteInt64BigEndian(message, step);

        Span<byte> hash = stackalloc byte[20];
        HMACSHA1.HashData(key, message, hash);

        var offset = hash[^1] & 0x0F;
        var binary = ((hash[offset] & 0x7F) << 24)
                   | (hash[offset + 1] << 16)
                   | (hash[offset + 2] << 8)
                   |  hash[offset + 3];
        return (binary % 1_000_000).ToString("D6");
    }

    /// <summary>Returnerer det step koden matchede (±1 step tolerance for clock drift), ellers null.</summary>
    public static long? Validate(byte[] key, string code, DateTimeOffset now, int window = 1)
    {
        if (code.Length != 6) return null;
        var provided = Encoding.ASCII.GetBytes(code);
        var current = CurrentStep(now);
        long? match = null;

        // Gennemløb altid alle step (ingen early return) og sammenlign i konstant tid
        for (var s = current - window; s <= current + window; s++)
        {
            var expected = Encoding.ASCII.GetBytes(Compute(key, s));
            if (CryptographicOperations.FixedTimeEquals(expected, provided)) match = s;
        }
        return match;
    }
}
