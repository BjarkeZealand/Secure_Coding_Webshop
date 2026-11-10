using Secure_Coding_Webshop.Models;

namespace Secure_Coding_Webshop.Repo.Interfaces
{
    /// <summary>US9: kun Admin. Alle kald sender sessionens hash; databasen tjekker rollen.</summary>
    public interface IAdminRepository
    {
        Task<PagedResult<AdminProductItem>> ListProductsAsync(byte[] sessionHash, bool includeInactive, int page, int pageSize, string? ip, CancellationToken ct = default);
        Task<AdminProductDetail?> GetProductAsync(byte[] sessionHash, int productId, string? ip, CancellationToken ct = default);
        Task<IReadOnlyList<CategoryRow>> ListCategoriesAsync(byte[] sessionHash, string? ip, CancellationToken ct = default);
        /// <summary>Returnerer nyt id, eller null hvis kategorien ikke findes.</summary>
        Task<int?> CreateProductAsync(byte[] sessionHash, ProductInput input, string? ip, CancellationToken ct = default);
        /// <summary>0 ok, 1 ikke fundet, 2 kategori findes ikke. Kaster DbRuleException(Conflict) ved samtidig ændring.</summary>
        Task<int> UpdateProductAsync(byte[] sessionHash, int productId, ProductInput input, byte[] rowVersion, string? ip, CancellationToken ct = default);
        Task<bool> DeleteProductAsync(byte[] sessionHash, int productId, string? ip, CancellationToken ct = default);
        Task<bool> RestoreProductAsync(byte[] sessionHash, int productId, string? ip, CancellationToken ct = default);
        Task<OrderDetail?> GetOrderForSupportAsync(byte[] sessionHash, Guid orderId, string? ip, CancellationToken ct = default);
    }
}
