using Secure_Coding_Webshop.Models;
using Secure_Coding_Webshop.Repo.Interfaces;
using Secure_Coding_Webshop.Repo.Shared.Factories.Interfaces;

namespace Secure_Coding_Webshop.Repo
{
    public sealed class CartRepo : BaseRepo, ICartRepository
    {
        public CartRepo(ISqlConnectionFactory connections) : base(connections) { }

        public Task<IReadOnlyList<CartLine>> GetAsync(byte[]? sessionHash, byte[]? anonKeyHash, string? ip, CancellationToken ct = default) =>
            QueryListProcAsync(
                "app.usp_Cart_Get",
                [Binary32("@SessionIdHash", sessionHash), Binary32("@AnonKeyHash", anonKeyHash), VarChar("@IpAddress", 45, ip)],
                r => new CartLine(
                    r.GetInt32(0), r.GetString(1), r.GetDecimal(2), r.GetInt32(3), r.GetDecimal(4),
                    r.GetInt32(5), r.GetBoolean(6), r.IsDBNull(7) ? null : r.GetString(7)),
                ct);

        public async Task<CartResult> AddAsync(byte[]? sessionHash, byte[]? anonKeyHash, int productId, int quantity, string? ip, CancellationToken ct = default) =>
            (CartResult)await ScalarIntProcAsync(
                "app.usp_Cart_AddItem",
                [
                    Binary32("@SessionIdHash", sessionHash), Binary32("@AnonKeyHash", anonKeyHash),
                    Int("@ProductId", productId), Int("@Quantity", quantity), VarChar("@IpAddress", 45, ip)
                ],
                ct);

        public async Task<CartResult> SetQuantityAsync(byte[]? sessionHash, byte[]? anonKeyHash, int productId, int quantity, string? ip, CancellationToken ct = default) =>
            (CartResult)await ScalarIntProcAsync(
                "app.usp_Cart_SetQuantity",
                [
                    Binary32("@SessionIdHash", sessionHash), Binary32("@AnonKeyHash", anonKeyHash),
                    Int("@ProductId", productId), Int("@Quantity", quantity), VarChar("@IpAddress", 45, ip)
                ],
                ct);

        public Task RemoveAsync(byte[]? sessionHash, byte[]? anonKeyHash, int productId, string? ip, CancellationToken ct = default) =>
            ScalarIntProcAsync(
                "app.usp_Cart_RemoveItem",
                [Binary32("@SessionIdHash", sessionHash), Binary32("@AnonKeyHash", anonKeyHash), Int("@ProductId", productId), VarChar("@IpAddress", 45, ip)],
                ct);

        public async Task<bool> MergeAnonymousAsync(byte[] sessionHash, byte[] anonKeyHash, string? ip, CancellationToken ct = default) =>
            await ScalarIntProcAsync(
                "app.usp_Cart_MergeAnonymous",
                [Binary32("@SessionIdHash", sessionHash), Binary32("@AnonKeyHash", anonKeyHash), VarChar("@IpAddress", 45, ip)],
                ct) == 0;     // 0 = flettet, 1 = ingen anonym kurv
    }
}
