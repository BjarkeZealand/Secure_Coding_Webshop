namespace Secure_Coding_Webshop.Services.Interfaces
{
    public interface IPasswordHashService
    {
        /// <param name="normalizedPassword">Password efter NFKC-normalisering.</param>
        Task<string> HashAsync(string normalizedPassword, CancellationToken ct);
        bool Verify(string normalizedPassword, string encodedHash);
    }
}
