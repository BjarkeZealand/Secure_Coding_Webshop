using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Secure_Coding_Webshop.Models;
using Secure_Coding_Webshop.Repo.Interfaces;
using Secure_Coding_Webshop.Services.Interfaces;

namespace Secure_Coding_Webshop.Services
{
    public sealed record CheckoutSession(string ProviderRef, string RedirectUrl);

    /// <summary>
    /// Betalingsudbyder. I dette projekt findes kun en mock (kortdata håndteres ALDRIG af webshoppen):
    /// kunden sendes til udbyderens side, og udbyderen kalder vores webhook, når betalingen er afgjort.
    /// </summary>
    public interface IPaymentGateway
    {
        CheckoutSession CreateCheckout(Guid orderId, decimal amount, string currency);
    }

    public sealed class MockPaymentGateway : IPaymentGateway
    {
        public CheckoutSession CreateCheckout(Guid orderId, decimal amount, string currency)
        {
            var providerRef = "mock_" + Convert.ToHexString(RandomNumberGenerator.GetBytes(12)).ToLowerInvariant();
            return new CheckoutSession(providerRef, $"/Payment/MockCheckout?orderId={orderId}&ref={providerRef}");
        }
    }

    /// <summary>HMAC-SHA256 over "{timestamp}.{body}" i headeren "t=...,v1=...". Samme princip som Stripe.</summary>
    public static class WebhookSignature
    {
        public static readonly TimeSpan Tolerance = TimeSpan.FromMinutes(5);

        public static string Sign(string secret, long timestamp, string body)
        {
            var mac = HMACSHA256.HashData(Encoding.UTF8.GetBytes(secret), Encoding.UTF8.GetBytes($"{timestamp}.{body}"));
            return $"t={timestamp},v1={Convert.ToHexString(mac).ToLowerInvariant()}";
        }

        public static bool Verify(string secret, string? header, string body, DateTimeOffset now)
        {
            if (string.IsNullOrEmpty(header) || header.Length > 200) return false;

            long? t = null; string? v1 = null;
            foreach (var part in header.Split(','))
            {
                var kv = part.Split('=', 2);
                if (kv.Length != 2) continue;
                if (kv[0] == "t" && long.TryParse(kv[1], out var parsed)) t = parsed;
                else if (kv[0] == "v1") v1 = kv[1];
            }
            if (t is null || v1 is null) return false;

            // For gammel/ny tidsstempel = mulig replay af en opsnappet besked
            if (Math.Abs((now - DateTimeOffset.FromUnixTimeSeconds(t.Value)).TotalSeconds) > Tolerance.TotalSeconds) return false;

            var expected = Encoding.ASCII.GetBytes(Sign(secret, t.Value, body).Split("v1=")[1]);
            return CryptographicOperations.FixedTimeEquals(expected, Encoding.ASCII.GetBytes(v1));
        }
    }

    public sealed record PaymentWebhookPayload(string Id, string Type, Guid OrderId, string ProviderRef, decimal? Amount, string? Currency);

    public interface IPaymentWebhookService
    {
        /// <summary>Returnerer HTTP-statuskode: 200 behandlet (også dublet), 400 ugyldig, 401 forkert signatur.</summary>
        Task<int> HandleAsync(string rawBody, string? signatureHeader, CancellationToken ct);
    }

    public sealed class PaymentWebhookService : IPaymentWebhookService
    {
        private readonly IOrderRepository _orders;
        private readonly ILoginRepository _log;
        private readonly IEmailQueue _mail;
        private readonly string _secret;

        public PaymentWebhookService(IOrderRepository orders, ILoginRepository log, IEmailQueue mail, IConfiguration config)
        {
            _orders = orders;
            _log = log;
            _mail = mail;
            _secret = config["Payment:WebhookSecret"] is { Length: >= 32 } s
                ? s
                : throw new InvalidOperationException("Payment:WebhookSecret mangler (mindst 32 tegn, gem i user-secrets)");
        }

        public async Task<int> HandleAsync(string rawBody, string? signatureHeader, CancellationToken ct)
        {
            if (!WebhookSignature.Verify(_secret, signatureHeader, rawBody, DateTimeOffset.UtcNow))
            {
                await _log.LogSecurityEventAsync("WebhookSignatureInvalid", "Critical", null, null, "/api/payments/webhook", null, Guid.NewGuid(), ct);
                return 401;
            }

            PaymentWebhookPayload? p;
            try
            {
                p = JsonSerializer.Deserialize<PaymentWebhookPayload>(rawBody, new JsonSerializerOptions(JsonSerializerDefaults.Web));
            }
            catch (JsonException) { return 400; }
            if (p is null || string.IsNullOrWhiteSpace(p.Id) || string.IsNullOrWhiteSpace(p.ProviderRef) || p.Id.Length > 100 || p.ProviderRef.Length > 100)
                return 400;
            if (p.Type is not ("payment_succeeded" or "payment_failed")) return 400;

            var result = await _orders.ApplyPaymentEventAsync(p.Id, p.Type, p.OrderId, p.ProviderRef, p.Amount, p.Currency, ct);

            if (result.Transitioned && result.UserEmail is not null)
            {
                if (result.OrderStatus == "Paid")
                    _mail.TryEnqueue(new EmailMessage(result.UserEmail, "Ordrebekræftelse",
                        $"Hej {result.DisplayName},\n\nTak for din ordre. Vi har modtaget din betaling på {result.TotalAmount:N2} kr.\nOrdrenummer: {result.OrderId}"));
                else if (result.OrderStatus == "Failed")
                    _mail.TryEnqueue(new EmailMessage(result.UserEmail, "Betalingen mislykkedes",
                        $"Hej {result.DisplayName},\n\nDin betaling blev afvist, og varerne er frigivet igen. Du kan prøve igen fra kurven."));
            }
            // Altid 200 for behandlede beskeder (også dubletter/ukendte), så udbyderen ikke bliver ved med at gentage
            return 200;
        }
    }
}
