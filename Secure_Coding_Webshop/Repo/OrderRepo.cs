using Secure_Coding_Webshop.Models;
using Secure_Coding_Webshop.Repo.Interfaces;
using Secure_Coding_Webshop.Repo.Shared.Factories.Interfaces;

namespace Secure_Coding_Webshop.Repo
{
    public sealed class OrderRepo : BaseRepo, IOrderRepository
    {
        public OrderRepo(ISqlConnectionFactory connections) : base(connections) { }

        public async Task<OrderCreateResult> CreateAsync(
            byte[] sessionHash, Guid idempotencyKey, ShippingAddress shipping, string? ip, CancellationToken ct = default) =>
            await QuerySingleProcAsync(
                "app.usp_Order_Create",
                [
                    Binary32("@SessionIdHash", sessionHash),
                    UniqueId("@IdempotencyKey", idempotencyKey),
                    NVarChar("@ShipName", 100, shipping.Name),
                    NVarChar("@ShipAddressLine", 200, shipping.AddressLine),
                    NVarChar("@ShipPostalCode", 10, shipping.PostalCode),
                    NVarChar("@ShipCity", 100, shipping.City),
                    NVarChar("@ShipCountry", 2, shipping.Country),
                    VarChar("@IpAddress", 45, ip)
                ],
                r => new OrderCreateResult(
                    (OrderCreateStatus)r.GetInt32(0),
                    r.IsDBNull(1) ? null : r.GetGuid(1),
                    r.IsDBNull(2) ? null : r.GetDecimal(2)),
                ct)
            ?? throw new InvalidOperationException("usp_Order_Create returnerede ingen række");

        public Task<bool> SetPaymentRefAsync(byte[] sessionHash, Guid orderId, string providerRef, string? ip, CancellationToken ct = default) =>
            ScalarBoolProcAsync(
                "app.usp_Order_SetPaymentRef",
                [Binary32("@SessionIdHash", sessionHash), UniqueId("@OrderId", orderId), NVarChar("@ProviderRef", 100, providerRef), VarChar("@IpAddress", 45, ip)],
                ct);

        public async Task<PaymentApplyResult> ApplyPaymentEventAsync(
            string eventId, string eventType, Guid orderId, string providerRef, decimal? amountPaid, string? currency, CancellationToken ct = default) =>
            await QuerySingleProcAsync(
                "app.usp_Payment_ApplyEvent",
                [
                    NVarChar("@EventId", 100, eventId),
                    NVarChar("@EventType", 100, eventType),
                    UniqueId("@OrderId", orderId),
                    NVarChar("@ProviderRef", 100, providerRef),
                    Money("@AmountPaid", amountPaid),
                    new Microsoft.Data.SqlClient.SqlParameter("@Currency", System.Data.SqlDbType.Char, 3) { Value = (object?)currency ?? DBNull.Value }
                ],
                r => new PaymentApplyResult(
                    (PaymentApplyStatus)r.GetInt32(0), r.GetBoolean(1),
                    r.IsDBNull(2) ? null : r.GetString(2), r.GetGuid(3),
                    r.IsDBNull(4) ? null : r.GetString(4), r.IsDBNull(5) ? null : r.GetString(5),
                    r.IsDBNull(6) ? null : r.GetDecimal(6)),
                ct)
            ?? throw new InvalidOperationException("usp_Payment_ApplyEvent returnerede ingen række");

        public async Task<PagedResult<OrderSummary>> ListMineAsync(byte[] sessionHash, int page, int pageSize, string? ip, CancellationToken ct = default)
        {
            var total = 0;
            var items = await QueryListProcAsync(
                "app.usp_Order_ListMine",
                [Binary32("@SessionIdHash", sessionHash), Int("@Page", page), Int("@PageSize", pageSize), VarChar("@IpAddress", 45, ip)],
                r =>
                {
                    total = r.GetInt32(5);
                    return new OrderSummary(r.GetGuid(0), Utc(r, 1), r.GetString(2), r.GetDecimal(3), r.GetString(4).Trim());
                },
                ct);
            return new PagedResult<OrderSummary>(items, total, page, pageSize);
        }

        public async Task<OrderDetail?> GetMineAsync(byte[] sessionHash, Guid orderId, string? ip, CancellationToken ct = default)
        {
            var rows = await QueryListProcAsync(
                "app.usp_Order_GetMine",
                [Binary32("@SessionIdHash", sessionHash), UniqueId("@OrderId", orderId), VarChar("@IpAddress", 45, ip)],
                r => (
                    Header: new OrderDetail(
                        r.GetGuid(0), null, Utc(r, 1), r.GetString(2), UtcOrNull(r, 3), r.GetDecimal(4), r.GetString(5).Trim(),
                        new ShippingAddress(r.GetString(6), r.GetString(7), r.GetString(8), r.GetString(9), r.GetString(10)),
                        []),
                    Line: new OrderLine(r.GetInt32(11), r.GetString(12), r.GetDecimal(13), r.GetInt32(14))),
                ct);
            return rows.Count == 0 ? null : rows[0].Header with { Lines = rows.Select(x => x.Line).ToList() };
        }
    }
}
