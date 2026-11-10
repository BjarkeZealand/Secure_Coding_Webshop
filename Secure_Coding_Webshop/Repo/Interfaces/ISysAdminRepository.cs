using Secure_Coding_Webshop.Models;

namespace Secure_Coding_Webshop.Repo.Interfaces
{
    /// <summary>US10: kun SysAdmin.</summary>
    public interface ISysAdminRepository
    {
        Task<PagedResult<SecurityEventRow>> SearchSecurityEventsAsync(byte[] sessionHash, SecurityEventFilter filter, int page, int pageSize, string? ip, CancellationToken ct = default);
        Task<PagedResult<AuditRow>> SearchAuditAsync(byte[] sessionHash, AuditFilter filter, int page, int pageSize, string? ip, CancellationToken ct = default);
        Task<IReadOnlyList<AlertRow>> GetAlertsAsync(byte[] sessionHash, int hours, string? ip, CancellationToken ct = default);
        Task<ChainResult> VerifyChainAsync(byte[] sessionHash, string logName, string? ip, CancellationToken ct = default);
    }
}
