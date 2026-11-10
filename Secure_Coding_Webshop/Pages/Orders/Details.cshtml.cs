using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Secure_Coding_Webshop.Models;
using Secure_Coding_Webshop.Repo.Interfaces;

namespace Secure_Coding_Webshop.Pages.Orders
{
    [Authorize(Roles = "Customer,Admin")]
    public sealed class DetailsModel : ShopPageModel
    {
        private readonly IOrderRepository _orders;

        public DetailsModel(IOrderRepository orders) => _orders = orders;

        public OrderDetail? Order { get; private set; }

        public Task<IActionResult> OnGetAsync(Guid id) => GuardAsync(async () =>
        {
            Order = await _orders.GetMineAsync(SessionHash, id, Ip, Ct);
            // Andres ordre og ikke-eksisterende ordrer giver NÅJAGTIG samme 404 (ingen oplysning om at id'et findes)
            return Order is null ? NotFound() : Page();
        });
    }
}
