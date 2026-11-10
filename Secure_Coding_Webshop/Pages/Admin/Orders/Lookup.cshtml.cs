using Microsoft.AspNetCore.Mvc;
using Secure_Coding_Webshop.Models;
using Secure_Coding_Webshop.Repo.Interfaces;

namespace Secure_Coding_Webshop.Pages.Admin.Orders
{
    public sealed class LookupModel : ShopPageModel
    {
        private readonly IAdminRepository _admin;

        public LookupModel(IAdminRepository admin) => _admin = admin;

        [BindProperty(SupportsGet = true, Name = "id")] public string? IdText { get; set; }
        public OrderDetail? Order { get; private set; }
        public bool NotFoundResult { get; private set; }

        public Task<IActionResult> OnGetAsync() => GuardAsync(async () =>
        {
            if (string.IsNullOrWhiteSpace(IdText)) return Page();
            if (!Guid.TryParse(IdText, out var id)) { NotFoundResult = true; return Page(); }

            Order = await _admin.GetOrderForSupportAsync(SessionHash, id, Ip, Ct);   // auditeres i databasen
            NotFoundResult = Order is null;
            return Page();
        });
    }
}
