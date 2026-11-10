using Microsoft.Data.SqlClient;
using Secure_Coding_Webshop.Models;
using Secure_Coding_Webshop.Repo.Interfaces;
using Secure_Coding_Webshop.Repo.Shared.Factories.Interfaces;

namespace Secure_Coding_Webshop.Repo
{
    /// <summary>Kun stored procedures i schema [app]. Alle værdier sendes som typede parametre.</summary>
    public sealed class LoginRepo : BaseRepo, ILoginRepository
    {
        public LoginRepo(ISqlConnectionFactory connections) : base(connections) { }

        public Task<CredentialRow?> GetCredentialsAsync(string normalizedEmail, CancellationToken ct = default) =>
            QuerySingleProcAsync(
                "app.usp_Login_GetCredentials",
                [NVarChar("@Email", 254, normalizedEmail)],
                r => new CredentialRow(
                    r.GetGuid(0), r.GetString(1), r.GetByte(2), r.GetBoolean(3), r.GetBoolean(4), UtcOrNull(r, 5)),
                ct);

        public Task<MfaRow?> GetMfaDataAsync(Guid userId, CancellationToken ct = default) =>
            QuerySingleProcAsync(
                "app.usp_Login_GetMfaData",
                [UniqueId("@UserId", userId)],
                r => new MfaRow(
                    r.GetGuid(0), r.GetByte(1), r.GetBoolean(2),
                    r.IsDBNull(3) ? null : r.GetFieldValue<byte[]>(3), UtcOrNull(r, 4)),
                ct);

        public async Task<ThrottleRow> GetThrottleAsync(byte[] emailHash, string ip, CancellationToken ct = default) =>
            await QuerySingleProcAsync(
                "app.usp_Login_GetThrottle",
                [Binary32("@EmailHash", emailHash), VarChar("@IpAddress", 45, ip)],
                r => new ThrottleRow(r.GetInt32(0), r.GetInt32(1)),
                ct)
            ?? throw new InvalidOperationException("usp_Login_GetThrottle returnerede ingen række");

        public Task<bool> RecordAttemptAsync(byte[]? emailHash, string ip, bool succeeded, Guid? userId, CancellationToken ct = default) =>
            ScalarBoolProcAsync(
                "app.usp_Login_RecordAttempt",
                [
                    Binary32("@EmailHash", emailHash),
                    VarChar("@IpAddress", 45, ip),
                    Bit("@Succeeded", succeeded),
                    UniqueId("@UserId", userId)
                ],
                ct);

        public Task<bool> TryAdvanceMfaStepAsync(Guid userId, long step, CancellationToken ct = default) =>
            ScalarBoolProcAsync(
                "app.usp_Mfa_TryAdvanceStep",
                [UniqueId("@UserId", userId), BigInt("@Step", step)],
                ct);

        public Task<bool> ConsumeBackupCodeAsync(Guid userId, byte[] codeHash, CancellationToken ct = default) =>
            ScalarBoolProcAsync(
                "app.usp_Mfa_ConsumeBackupCode",
                [UniqueId("@UserId", userId), Binary32("@CodeHash", codeHash)],
                ct);

        public Task LogSecurityEventAsync(string eventType, string severity, Guid? userId, string? ip, string? resource,
            string? details, Guid correlationId, CancellationToken ct = default) =>
            ExecuteProcAsync(
                "app.usp_SecurityEvent_Log",
                [
                    VarChar("@EventType", 50, eventType),
                    VarChar("@Severity", 10, severity),
                    UniqueId("@UserId", userId),
                    VarChar("@IpAddress", 45, ip),
                    NVarChar("@Resource", 200, resource),
                    NVarChar("@Details", 1000, details),
                    UniqueId("@CorrelationId", correlationId)
                ],
                ct);

        public Task CreateSessionAsync(byte[] sessionIdHash, Guid userId, int absoluteHours, string? ip, string? userAgent, CancellationToken ct = default) =>
            ExecuteProcAsync(
                "app.usp_Session_Create",
                [
                    Binary32("@SessionIdHash", sessionIdHash),
                    UniqueId("@UserId", userId),
                    Int("@AbsoluteHours", absoluteHours),
                    VarChar("@IpAddress", 45, ip),
                    NVarChar("@UserAgent", 300, userAgent)
                ],
                ct);

        public Task<SessionInfo?> ValidateSessionAsync(byte[] sessionIdHash, CancellationToken ct = default) =>
            QuerySingleProcAsync(
                "app.usp_Session_Validate",
                [Binary32("@SessionIdHash", sessionIdHash)],
                r => new SessionInfo(r.GetGuid(0), r.GetByte(1), r.GetString(2), r.GetBoolean(3)),
                ct);

        public Task RevokeSessionAsync(byte[] sessionIdHash, CancellationToken ct = default) =>
            ExecuteProcAsync(
                "app.usp_Session_Revoke",
                [Binary32("@SessionIdHash", sessionIdHash)],
                ct);

    }
}
