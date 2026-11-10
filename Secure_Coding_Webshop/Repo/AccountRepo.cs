using Secure_Coding_Webshop.Models;
using Secure_Coding_Webshop.Repo.Interfaces;
using Secure_Coding_Webshop.Repo.Shared.Factories.Interfaces;

namespace Secure_Coding_Webshop.Repo
{
    /// <summary>Konto: adgangskode (US6), MFA og enheder (US2), GDPR (US11). Identiteten kommer altid fra sessionens hash.</summary>
    public sealed class AccountRepo : BaseRepo, IAccountRepository
    {
        public AccountRepo(ISqlConnectionFactory connections) : base(connections) { }

        public Task<AccountProfile?> GetProfileAsync(byte[] sessionHash, string? ip, CancellationToken ct = default) =>
            QuerySingleProcAsync(
                "app.usp_User_GetProfile",
                [Binary32("@SessionIdHash", sessionHash), VarChar("@IpAddress", 45, ip)],
                r => new AccountProfile(r.GetString(0), r.GetString(1), r.GetByte(2), r.GetBoolean(3), r.GetBoolean(4), r.GetInt32(5)),
                ct);

        public Task<DeviceInfo?> RegisterDeviceAsync(byte[] sessionHash, byte[] deviceHash, CancellationToken ct = default) =>
            QuerySingleProcAsync(
                "app.usp_Login_RegisterDevice",
                [Binary32("@SessionIdHash", sessionHash), Binary32("@DeviceHash", deviceHash)],
                r => new DeviceInfo(r.GetBoolean(0), r.GetBoolean(1), r.GetString(2), r.GetString(3)),
                ct);

        public Task MarkReauthAsync(byte[] sessionHash, string? ip, CancellationToken ct = default) =>
            ExecuteProcAsync(
                "app.usp_Session_MarkReauth",
                [Binary32("@SessionIdHash", sessionHash), VarChar("@IpAddress", 45, ip)],
                ct);

        // ---------- US6 ----------
        public Task<PasswordChangeData?> GetPasswordDataAsync(byte[] sessionHash, string? ip, CancellationToken ct = default) =>
            QuerySingleProcAsync(
                "app.usp_Password_GetForChange",
                [Binary32("@SessionIdHash", sessionHash), VarChar("@IpAddress", 45, ip)],
                r => new PasswordChangeData(r.GetGuid(0), r.GetString(1), r.GetString(2), r.GetBoolean(3), r.GetByte(4)),
                ct);

        public async Task<PasswordChangeResult> ChangePasswordAsync(byte[] sessionHash, string oldHash, string newHash, string? ip, CancellationToken ct = default) =>
            await QuerySingleProcAsync(
                "app.usp_Password_Change",
                [Binary32("@SessionIdHash", sessionHash), NVarChar("@OldHash", 255, oldHash), NVarChar("@NewHash", 255, newHash), VarChar("@IpAddress", 45, ip)],
                r => new PasswordChangeResult(r.GetInt32(0), r.IsDBNull(1) ? null : r.GetString(1), r.IsDBNull(2) ? null : r.GetString(2)),
                ct)
            ?? throw new InvalidOperationException("usp_Password_Change returnerede ingen række");

        public async Task<ResetRequestResult> RequestPasswordResetAsync(string normalizedEmail, byte[] tokenHash, string? ip, CancellationToken ct = default) =>
            await QuerySingleProcAsync(
                "app.usp_PasswordReset_Request",
                [NVarChar("@Email", 254, normalizedEmail), Binary32("@TokenHash", tokenHash), VarChar("@IpAddress", 45, ip)],
                r => new ResetRequestResult(r.GetBoolean(0), r.IsDBNull(1) ? null : r.GetString(1)),
                ct)
            ?? throw new InvalidOperationException("usp_PasswordReset_Request returnerede ingen række");

        public Task<ResetTokenInfo?> ValidateResetTokenAsync(byte[] tokenHash, CancellationToken ct = default) =>
            QuerySingleProcAsync(
                "app.usp_PasswordReset_Validate",
                [Binary32("@TokenHash", tokenHash)],
                r => new ResetTokenInfo(r.GetGuid(0), r.GetByte(1), r.GetBoolean(2)),
                ct);

        public async Task<ResetCompleteResult> CompletePasswordResetAsync(byte[] tokenHash, string newHash, bool mfaVerified, string? ip, CancellationToken ct = default) =>
            await QuerySingleProcAsync(
                "app.usp_PasswordReset_Complete",
                [Binary32("@TokenHash", tokenHash), NVarChar("@NewHash", 255, newHash), Bit("@MfaVerified", mfaVerified), VarChar("@IpAddress", 45, ip)],
                r => new ResetCompleteResult(r.GetInt32(0), r.IsDBNull(1) ? null : r.GetString(1), r.IsDBNull(2) ? null : r.GetString(2)),
                ct)
            ?? throw new InvalidOperationException("usp_PasswordReset_Complete returnerede ingen række");

        // ---------- MFA ----------
        public Task<MfaSecretInfo?> GetMfaSecretAsync(byte[] sessionHash, string? ip, CancellationToken ct = default) =>
            QuerySingleProcAsync(
                "app.usp_Mfa_GetSecret",
                [Binary32("@SessionIdHash", sessionHash), VarChar("@IpAddress", 45, ip)],
                r => new MfaSecretInfo(r.GetBoolean(0), r.IsDBNull(1) ? null : r.GetFieldValue<byte[]>(1)),
                ct);

        public Task<bool> BeginMfaEnrollAsync(byte[] sessionHash, byte[] encryptedSecret, string? ip, CancellationToken ct = default) =>
            ScalarBoolProcAsync(
                "app.usp_Mfa_BeginEnroll",
                [Binary32("@SessionIdHash", sessionHash), VarBinary("@SecretEncrypted", 512, encryptedSecret), VarChar("@IpAddress", 45, ip)],
                ct);

        public Task<bool> ActivateMfaAsync(byte[] sessionHash, long step, IReadOnlyList<byte[]> backupCodeHashes, string? ip, CancellationToken ct = default) =>
            ScalarBoolProcAsync(
                "app.usp_Mfa_Activate",
                [Binary32("@SessionIdHash", sessionHash), BigInt("@Step", step), VarBinary("@BackupCodeHashes", 320, Pack(backupCodeHashes)), VarChar("@IpAddress", 45, ip)],
                ct);

        public Task<bool> DisableMfaAsync(byte[] sessionHash, string? ip, CancellationToken ct = default) =>
            ScalarBoolProcAsync(
                "app.usp_Mfa_Disable",
                [Binary32("@SessionIdHash", sessionHash), VarChar("@IpAddress", 45, ip)],
                ct);

        public Task<bool> ReplaceBackupCodesAsync(byte[] sessionHash, IReadOnlyList<byte[]> backupCodeHashes, string? ip, CancellationToken ct = default) =>
            ScalarBoolProcAsync(
                "app.usp_Mfa_ReplaceBackupCodes",
                [Binary32("@SessionIdHash", sessionHash), VarBinary("@BackupCodeHashes", 320, Pack(backupCodeHashes)), VarChar("@IpAddress", 45, ip)],
                ct);

        // ---------- GDPR ----------
        public Task<string?> ExportAsync(byte[] sessionHash, string? ip, CancellationToken ct = default) =>
            ScalarStringProcAsync(
                "app.usp_Account_Export",
                [Binary32("@SessionIdHash", sessionHash), VarChar("@IpAddress", 45, ip)],
                ct);

        public Task<bool> DeleteAccountAsync(byte[] sessionHash, string? ip, CancellationToken ct = default) =>
            ScalarBoolProcAsync(
                "app.usp_Account_Delete",
                [Binary32("@SessionIdHash", sessionHash), VarChar("@IpAddress", 45, ip)],
                ct);

        // Op til 10 SHA-256-hashes (32 byte hver) samles i ét VARBINARY(320)-parameter
        private static byte[] Pack(IReadOnlyList<byte[]> hashes)
        {
            if (hashes.Count is < 1 or > 10 || hashes.Any(h => h.Length != 32))
                throw new ArgumentException("Forventer 1-10 hashes på 32 byte", nameof(hashes));
            return hashes.SelectMany(h => h).ToArray();
        }
    }
}
