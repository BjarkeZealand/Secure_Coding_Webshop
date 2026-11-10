using System.Security.Cryptography;
using System.Text;
using Secure_Coding_Webshop.Models;
using Secure_Coding_Webshop.Repo.Interfaces;
using Secure_Coding_Webshop.Services.Interfaces;

namespace Secure_Coding_Webshop.Services
{
    public interface IPostLoginService
    {
        /// <summary>Kaldes lige efter at en session er oprettet: fletter anonym kurv og sender evt. "ny enhed"-mail. Fejl her må aldrig blokere login.</summary>
        Task RunAsync(HttpContext ctx, string sessionId, CancellationToken ct);
    }

    public sealed class PostLoginService : IPostLoginService
    {
        private readonly ICartRepository _cart;
        private readonly IAccountRepository _accounts;
        private readonly IEmailQueue _mail;
        private readonly ILogger<PostLoginService> _log;

        public PostLoginService(ICartRepository cart, IAccountRepository accounts, IEmailQueue mail, ILogger<PostLoginService> log)
        {
            _cart = cart;
            _accounts = accounts;
            _mail = mail;
            _log = log;
        }

        public async Task RunAsync(HttpContext ctx, string sessionId, CancellationToken ct)
        {
            var sessionHash = SessionIds.Hash(sessionId);
            var ip = ctx.ClientIp();

            try
            {
                if (CartCookie.ReadHash(ctx) is { } anon)
                {
                    await _cart.MergeAnonymousAsync(sessionHash, anon, ip, ct);
                    CartCookie.Clear(ctx);
                }
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                _log.LogWarning(ex, "Kunne ikke flette anonym kurv efter login");
            }

            try
            {
                var deviceHash = SHA256.HashData(Encoding.UTF8.GetBytes(ctx.Request.Headers.UserAgent.ToString()));
                var device = await _accounts.RegisterDeviceAsync(sessionHash, deviceHash, ct);
                if (device is { IsNew: true, HadPreviousDevices: true })
                    _mail.TryEnqueue(new EmailMessage(device.Email, "Nyt login på din konto",
                        $"Hej {device.DisplayName},\n\nDer er logget ind på din konto fra en ny enhed ({DateTime.UtcNow:yyyy-MM-dd HH:mm} UTC, IP {ip}).\n" +
                        "Var det dig, behøver du ikke gøre noget. Hvis ikke, så skift adgangskode med det samme."));
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                _log.LogWarning(ex, "Kunne ikke registrere enhed efter login");
            }
        }
    }
}
