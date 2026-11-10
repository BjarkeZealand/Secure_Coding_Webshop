using Microsoft.AspNetCore.Mvc;
using Secure_Coding_Webshop.Models;
using Secure_Coding_Webshop.Repo.Interfaces;

namespace Secure_Coding_Webshop.Pages.SysAdmin
{
    public sealed class AlertsModel : ShopPageModel
    {
        private readonly ISysAdminRepository _sys;

        public AlertsModel(ISysAdminRepository sys) => _sys = sys;

        public IReadOnlyList<AlertRow> Alerts { get; private set; } = [];
        public ChainResult? Chain { get; private set; }

        public Task<IActionResult> OnGetAsync() => GuardAsync(async () =>
        {
            Alerts = await _sys.GetAlertsAsync(SessionHash, 24, Ip, Ct);
            return Page();
        });

        public Task<IActionResult> OnPostVerifyAsync(string log) => GuardAsync(async () =>
        {
            if (log is not ("SecurityEvents" or "AuditLog")) return BadRequest();
            Alerts = await _sys.GetAlertsAsync(SessionHash, 24, Ip, Ct);
            Chain = await _sys.VerifyChainAsync(SessionHash, log, Ip, Ct);
            return Page();
        });
    }
}
