using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Secure_Coding_Webshop.Models;
using Secure_Coding_Webshop.Repo.Interfaces;

namespace Secure_Coding_Webshop.Pages.Products
{
    public sealed class IndexModel : PageModel
    {
        private const int PageSize = 12;
        private static readonly HashSet<string> Sorts = ["name_asc", "name_desc", "price_asc", "price_desc", "newest"];
        private readonly IProductRepository _products;

        public IndexModel(IProductRepository products) => _products = products;

        [BindProperty(SupportsGet = true, Name = "q")] public string? Q { get; set; }
        [BindProperty(SupportsGet = true, Name = "category")] public int? Category { get; set; }
        [BindProperty(SupportsGet = true, Name = "sort")] public string Sort { get; set; } = "name_asc";
        [BindProperty(SupportsGet = true, Name = "p")] public int Page { get; set; } = 1;

        public PagedResult<ProductListItem> Result { get; private set; } = new([], 0, 1, PageSize);
        public IReadOnlyList<CategoryRow> Categories { get; private set; } = [];

        public async Task OnGetAsync(CancellationToken ct)
        {
            // Hvidliste og afgrænsning allerede her; databasen gør det igen (defence in depth)
            if (!Sorts.Contains(Sort)) Sort = "name_asc";
            if (Page < 1) Page = 1;
            if (Q is { Length: > 100 }) Q = Q[..100];

            Categories = await _products.ListCategoriesAsync(ct);
            Result = await _products.ListAsync(Q, Category, Sort, Page, PageSize, ct);
        }
    }
}
