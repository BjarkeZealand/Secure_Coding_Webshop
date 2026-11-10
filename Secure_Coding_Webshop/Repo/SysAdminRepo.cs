using Secure_Coding_Webshop.Models;
using Secure_Coding_Webshop.Repo.Interfaces;
using Secure_Coding_Webshop.Repo.Shared.Factories.Interfaces;

namespace Secure_Coding_Webshop.Repo
{
    /// <summary>Kun schema [sysadmin]. Databasen kræver en SysAdmin-session; at se loggen bliver selv auditeret.</summary>
    public sealed class SysAdminRepo : BaseRepo, ISysAdminRepository
    {
        public SysAdminRepo(ISqlConnectionFactory connections) : base(connections) { }

        public async Task<PagedResult<SecurityEventRow>> SearchSecurityEventsAsync(
            byte[] sessionHash, SecurityEventFilter f, int page, int pageSize, string? ip, CancellationToken ct = default)
        {
            var total = 0;
            var items = await QueryListProcAsync(
                "sysadmin.usp_SecurityEvent_Search",
                [
                    Binary32("@SessionIdHash", sessionHash),
                    DateTimeUtc("@FromUtc", f.FromUtc), DateTimeUtc("@ToUtc", f.ToUtc),
                    VarChar("@EventType", 50, f.EventType), VarChar("@Severity", 10, f.Severity),
                    UniqueId("@FilterUserId", f.UserId), VarChar("@FilterIp", 45, f.Ip),
                    Int("@Page", page), Int("@PageSize", pageSize), VarChar("@IpAddress", 45, ip)
                ],
                r =>
                {
                    total = r.GetInt32(9);
                    return new SecurityEventRow(
                        r.GetInt64(0), Utc(r, 1), r.GetString(2), r.GetString(3),
                        r.IsDBNull(4) ? null : r.GetGuid(4), r.IsDBNull(5) ? null : r.GetString(5),
                        r.IsDBNull(6) ? null : r.GetString(6), r.IsDBNull(7) ? null : r.GetString(7),
                        r.IsDBNull(8) ? null : r.GetGuid(8));
                },
                ct, timeoutSeconds: 15);
            return new PagedResult<SecurityEventRow>(items, total, page, pageSize);
        }

        public async Task<PagedResult<AuditRow>> SearchAuditAsync(
            byte[] sessionHash, AuditFilter f, int page, int pageSize, string? ip, CancellationToken ct = default)
        {
            var total = 0;
            var items = await QueryListProcAsync(
                "sysadmin.usp_AuditLog_Search",
                [
                    Binary32("@SessionIdHash", sessionHash),
                    DateTimeUtc("@FromUtc", f.FromUtc), DateTimeUtc("@ToUtc", f.ToUtc),
                    VarChar("@Action", 50, f.Action), VarChar("@EntityType", 50, f.EntityType),
                    UniqueId("@ActorFilter", f.ActorUserId),
                    Int("@Page", page), Int("@PageSize", pageSize), VarChar("@IpAddress", 45, ip)
                ],
                r =>
                {
                    total = r.GetInt32(9);
                    return new AuditRow(
                        r.GetInt64(0), Utc(r, 1), r.IsDBNull(2) ? null : r.GetGuid(2), r.GetString(3), r.GetString(4),
                        r.IsDBNull(5) ? null : r.GetString(5), r.IsDBNull(6) ? null : r.GetString(6),
                        r.IsDBNull(7) ? null : r.GetString(7), r.IsDBNull(8) ? null : r.GetString(8));
                },
                ct, timeoutSeconds: 15);
            return new PagedResult<AuditRow>(items, total, page, pageSize);
        }

        public Task<IReadOnlyList<AlertRow>> GetAlertsAsync(byte[] sessionHash, int hours, string? ip, CancellationToken ct = default) =>
            QueryListProcAsync(
                "sysadmin.usp_Alerts_Get",
                [Binary32("@SessionIdHash", sessionHash), Int("@Hours", hours), VarChar("@IpAddress", 45, ip)],
                r => new AlertRow(r.GetString(0), r.GetString(1), r.GetInt32(2), Utc(r, 3), Utc(r, 4)),
                ct, timeoutSeconds: 15);

        public async Task<ChainResult> VerifyChainAsync(byte[] sessionHash, string logName, string? ip, CancellationToken ct = default) =>
            (await QueryListProcAsync(
                "sysadmin.usp_Log_VerifyChain",
                [Binary32("@SessionIdHash", sessionHash), VarChar("@LogName", 30, logName), VarChar("@IpAddress", 45, ip)],
                r => new ChainResult(r.GetString(0), r.GetInt64(1), r.GetInt64(2), r.IsDBNull(3) ? null : r.GetInt64(3)),
                ct, timeoutSeconds: 60)).Single();
    }
}
