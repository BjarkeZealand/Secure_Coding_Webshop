using Secure_Coding_Webshop.Repo.Interfaces;
using Secure_Coding_Webshop.Models;
using System.Diagnostics;

namespace Secure_Coding_Webshop.Repo
{
    /// <summary>
    /// Decorator: pakker et IUserRepository ind og logger varighed og fejl.
    /// Logger bevidst hverken e-mail, password-hash eller tokens.
    /// </summary>
    public sealed class LoggingUserRepo : IUserRepository
    {
        private readonly IUserRepository _inner;
        private readonly ILogger<LoggingUserRepo> _log;

        public LoggingUserRepo(IUserRepository inner, ILogger<LoggingUserRepo> log)
            => (_inner, _log) = (inner, log);

        public Task<bool> RegisterAsync(NewUser user, string? ipAddress, CancellationToken ct) =>
            Measure(nameof(RegisterAsync), () => _inner.RegisterAsync(user, ipAddress, ct));

        public Task<bool> ConfirmEmailAsync(byte[] tokenHash, string? ipAddress, CancellationToken ct) =>
            Measure(nameof(ConfirmEmailAsync), () => _inner.ConfirmEmailAsync(tokenHash, ipAddress, ct));

        private async Task<bool> Measure(string operation, Func<Task<bool>> action)
        {
            var sw = Stopwatch.StartNew();
            try
            {
                var result = await action();
                _log.LogInformation("{Operation} færdig på {Ms} ms (resultat: {Result})", operation, sw.ElapsedMilliseconds, result);
                return result;
            }
            catch (Exception ex)
            {
                _log.LogError(ex, "{Operation} fejlede efter {Ms} ms", operation, sw.ElapsedMilliseconds);
                throw;
            }
        }
    }
}
