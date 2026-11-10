using System.Text;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Secure_Coding_Webshop.Repo.Interfaces;
using Secure_Coding_Webshop.Services;

namespace Secure_Coding_Webshop.Pages.Account
{
    [Authorize]
    public sealed class PrivacyModel : ShopPageModel
    {
        private readonly IAccountRepository _repo;

        public PrivacyModel(IAccountRepository repo) => _repo = repo;

        public bool CanDelete => User.IsInRole(RoleNames.Customer);   // admin-konti fjernes af en DBA

        public void OnGet() { }

        public Task<IActionResult> OnPostExportAsync() => GuardAsync(async () =>
        {
            var json = await _repo.ExportAsync(SessionHash, Ip, Ct);
            return File(Encoding.UTF8.GetBytes(json ?? "{}"), "application/json", "mine-data.json");
        });

        // Databasen kræver re-authentication inden for 5 minutter
        public Task<IActionResult> OnPostDeleteAsync() => GuardAsync(async () =>
        {
            if (!await _repo.DeleteAccountAsync(SessionHash, Ip, Ct)) return Page();
            SessionCookie.Clear(Response);
            return RedirectToPage("/Index");
        });
    }
}
