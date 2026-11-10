using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Secure_Coding_Webshop.Models;
using Secure_Coding_Webshop.Repo.Interfaces;

namespace Secure_Coding_Webshop.Pages.Orders
{
    [Authorize(Roles = "Customer,Admin")]
    public sealed class IndexModel : ShopPageModel
    {
        private const int PageSize = 20;
        private readonly IOrderRepository _orders;

        public IndexModel(IOrderRepository orders) => _orders = orders;

        [BindProperty(SupportsGet = true, Name = "p")] public int PageNo { get; set; } = 1;
        public PagedResult<OrderSummary> Result { get; private set; } = new([], 0, 1, PageSize);

        public Task<IActionResult> OnGetAsync() => GuardAsync(async () =>
        {
            if (PageNo < 1) PageNo = 1;
            Result = await _orders.ListMineAsync(SessionHash, PageNo, PageSize, Ip, Ct);
            return Page();
        });
    }
}
