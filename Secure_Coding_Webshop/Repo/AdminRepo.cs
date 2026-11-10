using Microsoft.Data.SqlClient;
using Secure_Coding_Webshop.Models;
using Secure_Coding_Webshop.Repo.Interfaces;
using Secure_Coding_Webshop.Repo.Shared.Factories.Interfaces;

namespace Secure_Coding_Webshop.Repo
{
    /// <summary>Kun schema [admin]. Databasen kræver en Admin-session, uanset hvad webappen mener.</summary>
    public sealed class AdminRepo : BaseRepo, IAdminRepository
    {
        public AdminRepo(ISqlConnectionFactory connections) : base(connections) { }

        public async Task<PagedResult<AdminProductItem>> ListProductsAsync(
            byte[] sessionHash, bool includeInactive, int page, int pageSize, string? ip, CancellationToken ct = default)
        {
            var total = 0;
            var items = await QueryListProcAsync(
                "admin.usp_Product_List",
                [Binary32("@SessionIdHash", sessionHash), Bit("@IncludeInactive", includeInactive), Int("@Page", page), Int("@PageSize", pageSize), VarChar("@IpAddress", 45, ip)],
                r =>
                {
                    total = r.GetInt32(8);
                    return new AdminProductItem(r.GetInt32(0), r.GetInt32(1), r.GetString(2), r.GetString(3), r.GetDecimal(4),
                        r.GetInt32(5), r.GetBoolean(6), UtcOrNull(r, 7));
                },
                ct);
            return new PagedResult<AdminProductItem>(items, total, page, pageSize);
        }

        public Task<AdminProductDetail?> GetProductAsync(byte[] sessionHash, int productId, string? ip, CancellationToken ct = default) =>
            QuerySingleProcAsync(
                "admin.usp_Product_Get",
                [Binary32("@SessionIdHash", sessionHash), Int("@ProductId", productId), VarChar("@IpAddress", 45, ip)],
                r => new AdminProductDetail(
                    r.GetInt32(0), r.GetInt32(1), r.GetString(2), r.GetString(3), r.GetDecimal(4), r.GetInt32(5),
                    r.IsDBNull(6) ? null : r.GetString(6), r.GetBoolean(7), r.GetFieldValue<byte[]>(8)),
                ct);

        public Task<IReadOnlyList<CategoryRow>> ListCategoriesAsync(byte[] sessionHash, string? ip, CancellationToken ct = default) =>
            QueryListProcAsync(
                "admin.usp_Category_List",
                [Binary32("@SessionIdHash", sessionHash), VarChar("@IpAddress", 45, ip)],
                r => new CategoryRow(r.GetInt32(0), r.GetString(1)), ct);

        public async Task<int?> CreateProductAsync(byte[] sessionHash, ProductInput input, string? ip, CancellationToken ct = default)
        {
            var row = await QuerySingleProcAsync(
                "admin.usp_Product_Create",
                [
                    Binary32("@SessionIdHash", sessionHash),
                    Int("@CategoryId", input.CategoryId),
                    NVarChar("@Name", 150, input.Name),
                    NVarChar("@Description", 2000, input.Description),
                    Money("@Price", input.Price),
                    Int("@StockQuantity", input.StockQuantity),
                    NVarChar("@ImageFileName", 100, input.ImageFileName),
                    VarChar("@IpAddress", 45, ip)
                ],
                r => new { Result = r.GetInt32(0), Id = r.IsDBNull(1) ? (int?)null : r.GetInt32(1) },
                ct);
            return row?.Result == 0 ? row.Id : null;
        }

        public Task<int> UpdateProductAsync(byte[] sessionHash, int productId, ProductInput input, byte[] rowVersion, string? ip, CancellationToken ct = default) =>
            ScalarIntProcAsync(
                "admin.usp_Product_Update",
                [
                    Binary32("@SessionIdHash", sessionHash),
                    Int("@ProductId", productId),
                    Int("@CategoryId", input.CategoryId),
                    NVarChar("@Name", 150, input.Name),
                    NVarChar("@Description", 2000, input.Description),
                    Money("@Price", input.Price),
                    Int("@StockQuantity", input.StockQuantity),
                    NVarChar("@ImageFileName", 100, input.ImageFileName),
                    Binary8("@RowVersion", rowVersion),
                    VarChar("@IpAddress", 45, ip)
                ],
                ct);

        public async Task<bool> DeleteProductAsync(byte[] sessionHash, int productId, string? ip, CancellationToken ct = default) =>
            await ScalarIntProcAsync(
                "admin.usp_Product_Delete",
                [Binary32("@SessionIdHash", sessionHash), Int("@ProductId", productId), VarChar("@IpAddress", 45, ip)],
                ct) == 0;

        public async Task<bool> RestoreProductAsync(byte[] sessionHash, int productId, string? ip, CancellationToken ct = default) =>
            await ScalarIntProcAsync(
                "admin.usp_Product_Restore",
                [Binary32("@SessionIdHash", sessionHash), Int("@ProductId", productId), VarChar("@IpAddress", 45, ip)],
                ct) == 0;

        public async Task<OrderDetail?> GetOrderForSupportAsync(byte[] sessionHash, Guid orderId, string? ip, CancellationToken ct = default)
        {
            var rows = await QueryListProcAsync(
                "admin.usp_Order_GetForSupport",
                [Binary32("@SessionIdHash", sessionHash), UniqueId("@OrderId", orderId), VarChar("@IpAddress", 45, ip)],
                r => (
                    Header: new OrderDetail(
                        r.GetGuid(0), r.GetString(1), Utc(r, 2), r.GetString(3), UtcOrNull(r, 4), r.GetDecimal(5), r.GetString(6).Trim(),
                        new ShippingAddress(r.GetString(7), r.GetString(8), r.GetString(9), r.GetString(10), r.GetString(11)),
                        []),
                    Line: new OrderLine(r.GetInt32(12), r.GetString(13), r.GetDecimal(14), r.GetInt32(15))),
                ct);
            return rows.Count == 0 ? null : rows[0].Header with { Lines = rows.Select(x => x.Line).ToList() };
        }
    }
}
