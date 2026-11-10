using Microsoft.AspNetCore.Mvc;
using Secure_Coding_Webshop.Models;
using Secure_Coding_Webshop.Repo.Interfaces;

namespace Secure_Coding_Webshop.Pages.SysAdmin
{
    public sealed class LogsModel : ShopPageModel
    {
        private const int PageSize = 50;
        private readonly ISysAdminRepository _sys;

        public LogsModel(ISysAdminRepository sys) => _sys = sys;

        [BindProperty(SupportsGet = true, Name = "log")] public string Log { get; set; } = "security";
        [BindProperty(SupportsGet = true, Name = "from")] public DateTime? From { get; set; }
        [BindProperty(SupportsGet = true, Name = "to")] public DateTime? To { get; set; }
        [BindProperty(SupportsGet = true, Name = "type")] public string? Type { get; set; }
        [BindProperty(SupportsGet = true, Name = "severity")] public string? Severity { get; set; }
        [BindProperty(SupportsGet = true, Name = "user")] public string? UserText { get; set; }
        [BindProperty(SupportsGet = true, Name = "p")] public int PageNo { get; set; } = 1;

        public PagedResult<SecurityEventRow> Events { get; private set; } = new([], 0, 1, PageSize);
        public PagedResult<AuditRow> Audit { get; private set; } = new([], 0, 1, PageSize);
        public int TotalPages => Log == "audit" ? Audit.TotalPages : Events.TotalPages;

        public IDictionary<string, string?> RouteFor(int page) => new Dictionary<string, string?>
        {
            ["log"] = Log, ["from"] = From?.ToString("yyyy-MM-dd"), ["to"] = To?.ToString("yyyy-MM-dd"),
            ["type"] = Type, ["severity"] = Severity, ["user"] = UserText, ["p"] = page.ToString()
        };

        public Task<IActionResult> OnGetAsync() => GuardAsync(async () =>
        {
            if (PageNo < 1) PageNo = 1;
            Guid? userId = Guid.TryParse(UserText, out var g) ? g : null;
            var from = From is { } f ? DateTime.SpecifyKind(f, DateTimeKind.Utc) : (DateTime?)null;
            var to = To is { } t ? DateTime.SpecifyKind(t.AddDays(1), DateTimeKind.Utc) : (DateTime?)null;   // "til" er inklusiv

            if (Log == "audit")
                Audit = await _sys.SearchAuditAsync(SessionHash, new AuditFilter(from, to, Type, null, userId), PageNo, PageSize, Ip, Ct);
            else
            {
                Log = "security";
                Events = await _sys.SearchSecurityEventsAsync(SessionHash,
                    new SecurityEventFilter(from, to, Type, string.IsNullOrEmpty(Severity) ? null : Severity, userId, null), PageNo, PageSize, Ip, Ct);
            }
            return Page();
        });
    }
}
