using Secure_Coding_Webshop.Models;

namespace Secure_Coding_Webshop.Repo.Interfaces
{
    /// <summary>US4: ejeren udledes i databasen af session (bruger) eller anonym cookie-hash. Der findes ingen cart-id.</summary>
    public interface ICartRepository
    {
        Task<IReadOnlyList<CartLine>> GetAsync(byte[]? sessionHash, byte[]? anonKeyHash, string? ip, CancellationToken ct = default);
        Task<CartResult> AddAsync(byte[]? sessionHash, byte[]? anonKeyHash, int productId, int quantity, string? ip, CancellationToken ct = default);
        Task<CartResult> SetQuantityAsync(byte[]? sessionHash, byte[]? anonKeyHash, int productId, int quantity, string? ip, CancellationToken ct = default);
        Task RemoveAsync(byte[]? sessionHash, byte[]? anonKeyHash, int productId, string? ip, CancellationToken ct = default);
        /// <summary>Flet den anonyme kurv ind i brugerens kurv lige efter login. True hvis der fandtes en anonym kurv.</summary>
        Task<bool> MergeAnonymousAsync(byte[] sessionHash, byte[] anonKeyHash, string? ip, CancellationToken ct = default);
    }
}
