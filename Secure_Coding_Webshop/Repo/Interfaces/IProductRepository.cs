using Secure_Coding_Webshop.Models;

namespace Secure_Coding_Webshop.Repo.Interfaces
{
    /// <summary>US3 + US7: offentligt katalog. Kræver ingen session.</summary>
    public interface IProductRepository
    {
        Task<PagedResult<ProductListItem>> ListAsync(string? search, int? categoryId, string sort, int page, int pageSize, CancellationToken ct = default);
        Task<ProductDetail?> GetAsync(int productId, CancellationToken ct = default);
        Task<IReadOnlyList<CategoryRow>> ListCategoriesAsync(CancellationToken ct = default);
    }
}
