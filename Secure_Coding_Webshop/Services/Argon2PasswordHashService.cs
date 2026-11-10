using Secure_Coding_Webshop.Services.Interfaces;
using System.Security.Cryptography;
using System.Text;
using Konscious.Security.Cryptography;

namespace Secure_Coding_Webshop.Services
{
    public sealed class Argon2PasswordHashService : IPasswordHashService
    {
        private const int MemoryKiB = 19 * 1024;
        private const int Iterations = 2;
        private const int Parallelism = 1;
        private const int SaltBytes = 16;
        private const int HashBytes = 32;

        // Argon2 er bevidst dyrt: begræns samtidige hashes, så en bølge af requests ikke æder al hukommelse
        private static readonly SemaphoreSlim Gate = new(2, 2);

        public async Task<string> HashAsync(string normalizedPassword, CancellationToken ct)
        {
            var salt = RandomNumberGenerator.GetBytes(SaltBytes);
            await Gate.WaitAsync(ct);
            try
            {
                var hash = await Task.Run(() => Compute(normalizedPassword, salt, MemoryKiB, Iterations, Parallelism), ct);
                return $"$argon2id$v=19$m={MemoryKiB},t={Iterations},p={Parallelism}${ToB64(salt)}${ToB64(hash)}";
            }
            finally { Gate.Release(); }
        }

        public bool Verify(string normalizedPassword, string encodedHash)
        {
            try
            {
                var parts = encodedHash.Split('$'); // ["", "argon2id", "v=19", "m=..,t=..,p=..", salt, hash]
                if (parts.Length != 6 || parts[1] != "argon2id") return false;

                var p = parts[3].Split(',').Select(x => int.Parse(x[2..])).ToArray(); // m, t, p
                var salt = FromB64(parts[4]);
                var expected = FromB64(parts[5]);

                var actual = Compute(normalizedPassword, salt, p[0], p[1], p[2], expected.Length);
                return CryptographicOperations.FixedTimeEquals(actual, expected);
            }
            catch (Exception ex) when (ex is FormatException or IndexOutOfRangeException) { return false; }
        }

        private static byte[] Compute(string password, byte[] salt, int memoryKiB, int iterations, int parallelism, int length = HashBytes)
        {
            using var argon = new Argon2id(Encoding.UTF8.GetBytes(password))
            {
                Salt = salt,
                MemorySize = memoryKiB,
                Iterations = iterations,
                DegreeOfParallelism = parallelism
            };
            return argon.GetBytes(length);
        }

        private static string ToB64(byte[] b) => Convert.ToBase64String(b).TrimEnd('=');
        private static byte[] FromB64(string s) => Convert.FromBase64String(s.PadRight(s.Length + (4 - s.Length % 4) % 4, '='));
    }
}
