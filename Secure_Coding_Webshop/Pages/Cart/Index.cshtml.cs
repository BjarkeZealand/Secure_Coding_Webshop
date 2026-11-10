using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Secure_Coding_Webshop.Models;
using Secure_Coding_Webshop.Repo.Interfaces;
using Secure_Coding_Webshop.Services;

namespace Secure_Coding_Webshop.Pages.Cart
{
    public sealed class IndexModel : PageModel
    {
        private readonly ICartRepository _cart;

        public IndexModel(ICartRepository cart) => _cart = cart;

        public IReadOnlyList<CartLine> Lines { get; private set; } = [];
        public decimal Total => Lines.Where(l => l.IsActive).Sum(l => l.LineTotal);
        public string? Message { get; private set; }

        private (byte[]? Session, byte[]? Anon) Keys() =>
            User.Identity?.IsAuthenticated == true ? (User.GetSessionHash(), null) : (null, CartCookie.ReadHash(HttpContext));

        private async Task LoadAsync(CancellationToken ct)
        {
            var (s, a) = Keys();
            Lines = s is null && a is null ? [] : await _cart.GetAsync(s, a, HttpContext.ClientIp(), ct);
        }

        public async Task OnGetAsync(CancellationToken ct) => await LoadAsync(ct);

        public async Task<IActionResult> OnPostUpdateAsync(int productId, int quantity, CancellationToken ct)
        {
            var (s, a) = Keys();
            var result = await _cart.SetQuantityAsync(s, a, productId, quantity, HttpContext.ClientIp(), ct);
            Message = result switch
            {
                CartResult.Ok => "Kurven er opdateret.",
                CartResult.NotEnoughStock => "Der er ikke nok på lager.",
                CartResult.InvalidQuantity => "Vælg et antal mellem 0 og 99.",
                _ => "Varen findes ikke længere i kurven."
            };
            await LoadAsync(ct);
            return Page();
        }

        public async Task<IActionResult> OnPostRemoveAsync(int productId, CancellationToken ct)
        {
            var (s, a) = Keys();
            await _cart.RemoveAsync(s, a, productId, HttpContext.ClientIp(), ct);
            return RedirectToPage();
        }
    }
}
