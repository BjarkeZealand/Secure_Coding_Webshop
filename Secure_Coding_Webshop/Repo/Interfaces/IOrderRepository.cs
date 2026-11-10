using Secure_Coding_Webshop.Models;

namespace Secure_Coding_Webshop.Repo.Interfaces
{
    /// <summary>US5 + US8.</summary>
    public interface IOrderRepository
    {
        Task<OrderCreateResult> CreateAsync(byte[] sessionHash, Guid idempotencyKey, ShippingAddress shipping, string? ip, CancellationToken ct = default);
        Task<bool> SetPaymentRefAsync(byte[] sessionHash, Guid orderId, string providerRef, string? ip, CancellationToken ct = default);
        Task<PaymentApplyResult> ApplyPaymentEventAsync(string eventId, string eventType, Guid orderId, string providerRef, decimal? amountPaid, string? currency, CancellationToken ct = default);
        Task<PagedResult<OrderSummary>> ListMineAsync(byte[] sessionHash, int page, int pageSize, string? ip, CancellationToken ct = default);
        /// <summary>Null = findes ikke ELLER tilhører en anden (ens svar, 404).</summary>
        Task<OrderDetail?> GetMineAsync(byte[] sessionHash, Guid orderId, string? ip, CancellationToken ct = default);
    }
}
