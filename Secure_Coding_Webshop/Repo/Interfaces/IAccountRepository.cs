using Secure_Coding_Webshop.Models;

namespace Secure_Coding_Webshop.Repo.Interfaces
{
    /// <summary>US2 (MFA, enheder), US6 (adgangskode), US11/GDPR.</summary>
    public interface IAccountRepository
    {
        Task<AccountProfile?> GetProfileAsync(byte[] sessionHash, string? ip, CancellationToken ct = default);
        Task<DeviceInfo?> RegisterDeviceAsync(byte[] sessionHash, byte[] deviceHash, CancellationToken ct = default);
        Task MarkReauthAsync(byte[] sessionHash, string? ip, CancellationToken ct = default);

        Task<PasswordChangeData?> GetPasswordDataAsync(byte[] sessionHash, string? ip, CancellationToken ct = default);
        Task<PasswordChangeResult> ChangePasswordAsync(byte[] sessionHash, string oldHash, string newHash, string? ip, CancellationToken ct = default);

        Task<ResetRequestResult> RequestPasswordResetAsync(string normalizedEmail, byte[] tokenHash, string? ip, CancellationToken ct = default);
        Task<ResetTokenInfo?> ValidateResetTokenAsync(byte[] tokenHash, CancellationToken ct = default);
        Task<ResetCompleteResult> CompletePasswordResetAsync(byte[] tokenHash, string newHash, bool mfaVerified, string? ip, CancellationToken ct = default);

        Task<MfaSecretInfo?> GetMfaSecretAsync(byte[] sessionHash, string? ip, CancellationToken ct = default);
        Task<bool> BeginMfaEnrollAsync(byte[] sessionHash, byte[] encryptedSecret, string? ip, CancellationToken ct = default);
        Task<bool> ActivateMfaAsync(byte[] sessionHash, long step, IReadOnlyList<byte[]> backupCodeHashes, string? ip, CancellationToken ct = default);
        Task<bool> DisableMfaAsync(byte[] sessionHash, string? ip, CancellationToken ct = default);
        Task<bool> ReplaceBackupCodesAsync(byte[] sessionHash, IReadOnlyList<byte[]> backupCodeHashes, string? ip, CancellationToken ct = default);

        Task<string?> ExportAsync(byte[] sessionHash, string? ip, CancellationToken ct = default);
        Task<bool> DeleteAccountAsync(byte[] sessionHash, string? ip, CancellationToken ct = default);
    }
}
