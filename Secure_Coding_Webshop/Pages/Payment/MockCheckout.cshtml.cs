using System.Text.Json;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Secure_Coding_Webshop.Repo.Interfaces;
using Secure_Coding_Webshop.Services;

namespace Secure_Coding_Webshop.Pages.Payment
{
    /// <summary>
    /// Kun til udvikling: spiller betalingsudbyderen. Siden bygger en signeret webhook og sender den gennem
    /// PRÆCIS samme kode som det rigtige endpoint (signatur, tidsstempel, replay, beløbstjek).
    /// </summary>
    [Authorize(Roles = "Customer,Admin")]
    public sealed class MockCheckoutModel : ShopPageModel
    {
        private readonly IPaymentWebhookService _webhook;
        private readonly IOrderRepository _orders;
        private readonly IConfiguration _config;
        private readonly IWebHostEnvironment _env;

        public MockCheckoutModel(IPaymentWebhookService webhook, IOrderRepository orders, IConfiguration config, IWebHostEnvironment env)
        {
            _webhook = webhook;
            _orders = orders;
            _config = config;
            _env = env;
        }

        public Guid OrderId { get; private set; }
        public string ProviderRef { get; private set; } = "";

        public IActionResult OnGet(Guid orderId, [FromQuery(Name = "ref")] string providerRef)
        {
            if (!_env.IsDevelopment()) return NotFound();
            OrderId = orderId;
            ProviderRef = providerRef;
            return Page();
        }

        public async Task<IActionResult> OnPostAsync(Guid orderId, string providerRef, string outcome)
        {
            if (!_env.IsDevelopment()) return NotFound();

            // Ordrens rigtige beløb hentes fra ordren (mock'en "kender" det, som en rigtig udbyder gør)
            var order = await _orders.GetMineAsync(SessionHash, orderId, Ip, Ct);
            if (order is null) return NotFound();

            var payload = JsonSerializer.Serialize(new
            {
                id = "evt_" + Guid.NewGuid().ToString("N"),
                type = outcome == "success" ? "payment_succeeded" : "payment_failed",
                orderId,
                providerRef,
                amount = order.TotalAmount,
                currency = order.Currency
            });
            var ts = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
            var header = WebhookSignature.Sign(_config["Payment:WebhookSecret"]!, ts, payload);

            await _webhook.HandleAsync(payload, header, Ct);
            return RedirectToPage("/Orders/Details", new { id = orderId });
        }
    }
}
