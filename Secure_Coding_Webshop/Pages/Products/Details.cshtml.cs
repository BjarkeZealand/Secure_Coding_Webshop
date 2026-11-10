using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Secure_Coding_Webshop.Models;
using Secure_Coding_Webshop.Repo.Interfaces;
using Secure_Coding_Webshop.Services;

namespace Secure_Coding_Webshop.Pages.Products
{
    public sealed class DetailsModel : PageModel
    {
        private readonly IProductRepository _products;
        private readonly ICartRepository _cart;

        public DetailsModel(IProductRepository products, ICartRepository cart)
        {
            _products = products;
            _cart = cart;
        }

        public ProductDetail? Product { get; private set; }
        public string? Message { get; private set; }

        public async Task<IActionResult> OnGetAsync(int id, CancellationToken ct)
        {
            Product = await _products.GetAsync(id, ct);
            return Product is null ? NotFound() : Page();
        }

        public async Task<IActionResult> OnPostAddAsync(int id, int quantity, CancellationToken ct)
        {
            // Klienten sender KUN id og antal. Pris, navn og lager slås op i databasen.
            var session = User.Identity?.IsAuthenticated == true ? User.GetSessionHash() : null;
            var anon = session is null ? CartCookie.EnsureHash(HttpContext) : null;

            var result = await _cart.AddAsync(session, anon, id, quantity, HttpContext.ClientIp(), ct);
            Product = await _products.GetAsync(id, ct);
            if (Product is null) return NotFound();

            Message = result switch
            {
                CartResult.Ok => "Lagt i kurven.",
                CartResult.NotEnoughStock => "Der er ikke nok på lager.",
                CartResult.InvalidQuantity => "Vælg et antal mellem 1 og 99.",
                _ => "Produktet er ikke længere tilgængeligt."
            };
            return Page();
        }
    }
}
