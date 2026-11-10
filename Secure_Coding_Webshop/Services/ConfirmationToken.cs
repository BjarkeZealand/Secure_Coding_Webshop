using Microsoft.AspNetCore.WebUtilities;
using System.Security.Cryptography;

namespace Secure_Coding_Webshop.Services
{
    public static class ConfirmationToken
    {
        private const int Bytes = 32;
        private const int EncodedLength = 43; // 32 bytes i base64url uden padding

        public static (string Token, byte[] Hash) Create()
        {
            var bytes = RandomNumberGenerator.GetBytes(Bytes);
            return (WebEncoders.Base64UrlEncode(bytes), SHA256.HashData(bytes));
        }

        public static bool TryHash(string? token, out byte[] hash)
        {
            hash = Array.Empty<byte>();
            if (token is null || token.Length != EncodedLength) return false;
            try
            {
                var bytes = WebEncoders.Base64UrlDecode(token);
                if (bytes.Length != Bytes) return false;
                hash = SHA256.HashData(bytes);
                return true;
            }
            catch (FormatException) { return false; }
        }
    }
}
