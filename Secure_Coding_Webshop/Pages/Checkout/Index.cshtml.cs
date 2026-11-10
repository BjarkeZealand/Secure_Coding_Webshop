using System.ComponentModel.DataAnnotations;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Secure_Coding_Webshop.Models;
using Secure_Coding_Webshop.Repo.Interfaces;
using Secure_Coding_Webshop.Services;

namespace Secure_Coding_Webshop.Pages.Checkout
{
    [Authorize(Roles = "Customer,Admin")]       // SysAdmin handler ikke (RBAC-matrix); databasen tjekker det igen
    public sealed class IndexModel : ShopPageModel
    {
        private readonly ICartRepository _cart;
        private readonly IOrderRepository _orders;
        private readonly IPaymentGateway _gateway;

        public IndexModel(ICartRepository cart, IOrderRepository orders, IPaymentGateway gateway)
        {
            _cart = cart;
            _orders = orders;
            _gateway = gateway;
        }

        public sealed class CheckoutInput
        {
            public Guid IdempotencyKey { get; set; }
            [Required, StringLength(100)] public string Name { get; set; } = "";
            [Required, StringLength(200)] public string AddressLine { get; set; } = "";
            [Required, RegularExpression(@"^[0-9A-Za-z \-]{3,10}$")] public string PostalCode { get; set; } = "";
            [Required, StringLength(100)] public string City { get; set; } = "";
            [Required, RegularExpression(@"^[A-Z]{2}$")] public string Country { get; set; } = "DK";
        }

        [BindProperty] public CheckoutInput Input { get; set; } = new();
        public IReadOnlyList<CartLine> Lines { get; private set; } = [];
        public decimal Total => Lines.Sum(l => l.LineTotal);
        public bool EmailConfirmed => User.FindFirst("email_confirmed")?.Value == "true";

        public async Task OnGetAsync()
        {
            Input.IdempotencyKey = Guid.NewGuid();
            Lines = await _cart.GetAsync(SessionHash, null, Ip, Ct);
        }

        public Task<IActionResult> OnPostAsync() => GuardAsync(async () =>
        {
            Lines = await _cart.GetAsync(SessionHash, null, Ip, Ct);
            if (!ModelState.IsValid || Input.IdempotencyKey == Guid.Empty) return Page();

            var shipping = new ShippingAddress(Input.Name, Input.AddressLine, Input.PostalCode, Input.City, Input.Country);
            var created = await _orders.CreateAsync(SessionHash, Input.IdempotencyKey, shipping, Ip, Ct);

            switch (created.Status)
            {
                case OrderCreateStatus.Created when created.OrderId is { } orderId:
                    // Beløbet kommer fra databasen (created.TotalAmount), aldrig fra formularen
                    var checkout = _gateway.CreateCheckout(orderId, created.TotalAmount ?? 0m, "DKK");
                    await _orders.SetPaymentRefAsync(SessionHash, orderId, checkout.ProviderRef, Ip, Ct);
                    return LocalRedirect(checkout.RedirectUrl);
                case OrderCreateStatus.Replay when created.OrderId is { } existing:
                    // Dobbeltklik/genindlæsning: ingen ny ordre, vis den eksisterende
                    return RedirectToPage("/Orders/Details", new { id = existing });
                case OrderCreateStatus.EmptyCart:
                    ModelState.AddModelError(string.Empty, "Din kurv er tom.");
                    break;
                case OrderCreateStatus.TooManyPending:
                    ModelState.AddModelError(string.Empty, "Du har for mange ubetalte ordrer. Betal eller vent, til de udløber.");
                    break;
                default:
                    ModelState.AddModelError(string.Empty, "En eller flere varer er udsolgt eller ikke længere tilgængelige.");
                    break;
            }
            return Page();
        });
    }
}
