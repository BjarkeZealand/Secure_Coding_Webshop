using Microsoft.AspNetCore.Mvc;
using Secure_Coding_Webshop.Models;
using Secure_Coding_Webshop.Repo.Interfaces;

namespace Secure_Coding_Webshop.Pages.Admin.Products
{
    // Adgang: konvention i Program.cs (AdminOnly) OG databasen (admin.usp_* kræver Admin-session)
    public sealed class IndexModel : ShopPageModel
    {
        private const int PageSize = 25;
        private readonly IAdminRepository _admin;

        public IndexModel(IAdminRepository admin) => _admin = admin;

        [BindProperty(SupportsGet = true, Name = "p")] public int PageNo { get; set; } = 1;
        public PagedResult<AdminProductItem> Result { get; private set; } = new([], 0, 1, PageSize);

        public Task<IActionResult> OnGetAsync() => GuardAsync(async () =>
        {
            if (PageNo < 1) PageNo = 1;
            Result = await _admin.ListProductsAsync(SessionHash, true, PageNo, PageSize, Ip, Ct);
            return Page();
        });

        // Sletning kræver re-authentication ≤ 5 min; GuardAsync sender til /Account/Reauth og tilbage
        public Task<IActionResult> OnPostDeleteAsync(int id) => GuardAsync(async () =>
        {
            await _admin.DeleteProductAsync(SessionHash, id, Ip, Ct);
            return RedirectToPage();
        });

        public Task<IActionResult> OnPostRestoreAsync(int id) => GuardAsync(async () =>
        {
            await _admin.RestoreProductAsync(SessionHash, id, Ip, Ct);
            return RedirectToPage();
        });
    }
}
