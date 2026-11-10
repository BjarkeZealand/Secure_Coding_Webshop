using Secure_Coding_Webshop.Models;

namespace Secure_Coding_Webshop.Repo.Interfaces
{
    public interface IUserRepository
    {
        /// <returns>true hvis kontoen blev oprettet, false hvis e-mailen allerede findes.</returns>
        Task<bool> RegisterAsync(NewUser user, string? ipAddress, CancellationToken ct);

        /// <returns>true hvis tokenet var gyldigt (og e-mailen nu er bekræftet).</returns>
        Task<bool> ConfirmEmailAsync(byte[] tokenHash, string? ipAddress, CancellationToken ct);
    }
}
