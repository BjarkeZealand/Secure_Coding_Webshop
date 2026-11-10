using Secure_Coding_Webshop.Models;
using Secure_Coding_Webshop.Repo.Interfaces;
using Secure_Coding_Webshop.Repo.Shared.Factories.Interfaces;

namespace Secure_Coding_Webshop.Repo
{
    public sealed class ProductRepo : BaseRepo, IProductRepository
    {
        public ProductRepo(ISqlConnectionFactory connections) : base(connections) { }

        public async Task<PagedResult<ProductListItem>> ListAsync(
            string? search, int? categoryId, string sort, int page, int pageSize, CancellationToken ct = default)
        {
            // TotalCount er sidste kolonne og ens på alle rækker
            var total = 0;
            var items = await QueryListProcAsync(
                "app.usp_Product_List",
                [
                    NVarChar("@SearchTerm", 100, search),
                    IntOrNull("@CategoryId", categoryId),
                    VarChar("@Sort", 20, sort),
                    Int("@Page", page),
                    Int("@PageSize", pageSize)
                ],
                r =>
                {
                    total = r.GetInt32(8);
                    return new ProductListItem(
                        r.GetInt32(0), r.GetInt32(1), r.GetString(2), r.GetString(3), r.GetString(4),
                        r.GetDecimal(5), r.GetInt32(6), r.IsDBNull(7) ? null : r.GetString(7));
                },
                ct);
            return new PagedResult<ProductListItem>(items, total, page, pageSize);
        }

        public Task<ProductDetail?> GetAsync(int productId, CancellationToken ct = default) =>
            QuerySingleProcAsync(
                "app.usp_Product_Get",
                [Int("@ProductId", productId)],
                r => new ProductDetail(
                    r.GetInt32(0), r.GetInt32(1), r.GetString(2), r.GetString(3), r.GetString(4),
                    r.GetDecimal(5), r.GetInt32(6), r.IsDBNull(7) ? null : r.GetString(7)),
                ct);

        public Task<IReadOnlyList<CategoryRow>> ListCategoriesAsync(CancellationToken ct = default) =>
            QueryListProcAsync("app.usp_Category_List", [], r => new CategoryRow(r.GetInt32(0), r.GetString(1)), ct);
    }
}
