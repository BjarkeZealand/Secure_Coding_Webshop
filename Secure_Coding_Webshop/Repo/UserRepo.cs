using Secure_Coding_Webshop.Models;
using Secure_Coding_Webshop.Repo.Interfaces;
using Secure_Coding_Webshop.Repo.Shared.Factories.Interfaces;

namespace Secure_Coding_Webshop.Repo
{
    /// <summary>US1. Procedurerne er flyttet fra dbo til schema [app] (webshop_app har ikke adgang til dbo).</summary>
    public sealed class UserRepo : BaseRepo, IUserRepository
    {
        public UserRepo(ISqlConnectionFactory connections) : base(connections) { }

        public async Task<bool> RegisterAsync(NewUser user, string? ipAddress, CancellationToken ct)
        {
            var created = OutputBit("@Created");
            await ExecuteProcAsync("app.usp_User_Register", new[]
            {
                NVarChar("@Email", 254, user.Email),
                NVarChar("@DisplayName", 100, user.DisplayName),
                NVarChar("@PasswordHash", 255, user.PasswordHash),
                NVarChar("@PrivacyConsentVersion", 20, user.PrivacyConsentVersion),
                Binary32("@ConfirmTokenHash", user.ConfirmTokenHash),
                VarChar("@IpAddress", 45, ipAddress),
                created
            }, ct);
            return (bool)created.Value;
        }

        public async Task<bool> ConfirmEmailAsync(byte[] tokenHash, string? ipAddress, CancellationToken ct)
        {
            var confirmed = OutputBit("@Confirmed");
            await ExecuteProcAsync("app.usp_User_ConfirmEmail", new[]
            {
                Binary32("@TokenHash", tokenHash),
                VarChar("@IpAddress", 45, ipAddress),
                confirmed
            }, ct);
            return (bool)confirmed.Value;
        }
    }
}
