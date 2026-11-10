using Secure_Coding_Webshop.Models;

namespace Secure_Coding_Webshop.Repo.Interfaces
{
    public interface ILoginRepository
    {
        Task<CredentialRow?> GetCredentialsAsync(string normalizedEmail, CancellationToken ct = default);
        Task<MfaRow?> GetMfaDataAsync(Guid userId, CancellationToken ct = default);
        Task<ThrottleRow> GetThrottleAsync(byte[] emailHash, string ip, CancellationToken ct = default);

        /// <returns>true hvis kontoen blev låst af dette forsøg</returns>
        Task<bool> RecordAttemptAsync(byte[]? emailHash, string ip, bool succeeded, Guid? userId, CancellationToken ct = default);

        Task<bool> TryAdvanceMfaStepAsync(Guid userId, long step, CancellationToken ct = default);
        Task<bool> ConsumeBackupCodeAsync(Guid userId, byte[] codeHash, CancellationToken ct = default);

        Task LogSecurityEventAsync(string eventType, string severity, Guid? userId, string? ip, string? resource,
            string? details, Guid correlationId, CancellationToken ct = default);

        Task CreateSessionAsync(byte[] sessionIdHash, Guid userId, int absoluteHours, string? ip, string? userAgent, CancellationToken ct = default);
        Task<SessionInfo?> ValidateSessionAsync(byte[] sessionIdHash, CancellationToken ct = default);
        Task RevokeSessionAsync(byte[] sessionIdHash, CancellationToken ct = default);
    }
}
