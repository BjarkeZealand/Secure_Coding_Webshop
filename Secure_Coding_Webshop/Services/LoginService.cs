using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using Microsoft.AspNetCore.DataProtection;
using Secure_Coding_Webshop.Repo.Interfaces;
using Secure_Coding_Webshop.Services.Interfaces;

namespace Secure_Coding_Webshop.Services
{
    public enum LoginStatus { Success, RequiresMfa, Failed, Throttled }

    public sealed record LoginResult(LoginStatus Status, string? SessionId = null, string? MfaPendingToken = null);

    public interface ILoginService
    {
        Task<LoginResult> PasswordStepAsync(string email, string password, string? ip, string? userAgent, CancellationToken ct);
        Task<LoginResult> MfaStepAsync(string pendingToken, string code, string? ip, string? userAgent, CancellationToken ct);

        /// <summary>Tilbagekalder sessionen på serveren og logger udlogning.</summary>
        Task LogoutAsync(string sessionId, Guid? userId, string? ip, CancellationToken ct);

        /// <summary>Tilbagekalder stille (bruges når en ny session erstatter en gammel).</summary>
        Task RevokeAsync(string sessionId, CancellationToken ct);
    }

    public sealed partial class LoginService : ILoginService
    {
        private const int MaxFailedPerEmail = 5;     // pr. 15 min
        private const int MaxFailedPerIp = 20;       // pr. 15 min
        private const int SessionAbsoluteHours = 8;
        private static readonly TimeSpan MfaPendingLifetime = TimeSpan.FromMinutes(5);

        private readonly ILoginRepository _repo;
        private readonly IPasswordHashService _hasher;
        private readonly IDataProtector _secretProtector;                 // MfaSecretEncrypted
        private readonly ITimeLimitedDataProtector _pendingProtector;     // "kode mangler"-token mellem trin 1 og 2

        // Dummy-hash med samme Argon2id-parametre som rigtige hashes, så ukendte brugere koster lige meget tid.
        // HashAsync er async, så den kan ikke beregnes i konstruktøren; Lazy sikrer at den kun beregnes én gang.
        private readonly Lazy<Task<string>> _dummyHash;

        public LoginService(ILoginRepository repo, IPasswordHashService hasher, IDataProtectionProvider dataProtection)
        {
            _repo = repo;
            _hasher = hasher;

            // Samme purpose-streng SKAL bruges når MFA-secret krypteres ved tilmelding
            _secretProtector = dataProtection.CreateProtector("Secure_Coding_Webshop.MfaSecret.v1");
            _pendingProtector = dataProtection.CreateProtector("Secure_Coding_Webshop.MfaPending.v1").ToTimeLimitedDataProtector();

            _dummyHash = new Lazy<Task<string>>(() =>
                _hasher.HashAsync(Convert.ToBase64String(RandomNumberGenerator.GetBytes(32)), CancellationToken.None));

            // Start beregningen med det samme, så første login med ukendt e-mail ikke afslører sig ved at vente længere
            _ = _dummyHash.Value;
        }

        [GeneratedRegex(@"^\d{6}$")] private static partial Regex TotpFormat();
        [GeneratedRegex(@"^[A-Z0-9]{10}$")] private static partial Regex BackupFormat();

        /* ------------------------------ Trin 1: e-mail + password ------------------------------ */

        public async Task<LoginResult> PasswordStepAsync(string email, string password, string? ip, string? userAgent, CancellationToken ct)
        {
            var correlation = Guid.NewGuid();
            var ipAddr = ip ?? "unknown";
            var normEmail = NormalizeEmail(email);
            var emailHash = SHA256.HashData(Encoding.UTF8.GetBytes(normEmail));

            // IPasswordHashService forventer et allerede normaliseret password (samme NFKC som ved oprettelse i US1)
            var normalizedPassword = password.Normalize(NormalizationForm.FormKC);

            var throttle = await _repo.GetThrottleAsync(emailHash, ipAddr, ct);

            // IP-grænsen er uafhængig af kontoen => kan afsløres uden at lække om en konto findes
            if (throttle.FailedByIp >= MaxFailedPerIp)
            {
                await _repo.RecordAttemptAsync(null, ipAddr, false, null, ct);
                await LogAsync("LoginThrottled", "Warning", null, ipAddr, "ip-limit", correlation, ct);
                return new LoginResult(LoginStatus.Throttled);
            }

            var user = await _repo.GetCredentialsAsync(normEmail, ct);

            // Præcis én hash-verifikation uanset om brugeren findes (ens svartid)
            var hashToVerify = user?.PasswordHash ?? await _dummyHash.Value;
            var passwordOk = _hasher.Verify(normalizedPassword, hashToVerify) && user is not null;

            var locked = user?.LockoutEndUtc is { } end && end > DateTime.UtcNow;
            var emailBlocked = throttle.FailedByEmail >= MaxFailedPerEmail;

            if (user is null || !passwordOk || locked || emailBlocked)
            {
                // Forsøg under en aktiv lås tæller ikke mod kontoen (angriber kan ikke forlænge låsen)
                var countsAgainstEmail = !locked && !emailBlocked;
                var nowLocked = await _repo.RecordAttemptAsync(
                    countsAgainstEmail ? emailHash : null, ipAddr, false,
                    countsAgainstEmail ? user?.UserId : null, ct);

                var reason = user is null ? "unknown-user" : locked || emailBlocked ? "locked" : "bad-password";
                await LogAsync("LoginFailed", "Warning", user?.UserId, ipAddr, reason, correlation, ct);
                if (nowLocked)
                {
                    await LogAsync("AccountLocked", "Warning", user?.UserId, ipAddr, "too-many-failures", correlation, ct);
                }

                return new LoginResult(LoginStatus.Failed);   // samme svar i alle tilfælde
            }

            // Admin/SysAdmin SKAL bruge MFA
            if (user.RoleId >= 2 && !user.MfaEnabled)
            {
                await LogAsync("LoginDenied", "Error", user.UserId, ipAddr, "privileged-role-without-mfa", correlation, ct);
                return new LoginResult(LoginStatus.Failed);
            }

            if (user.MfaEnabled)
            {
                var payload = $"{user.UserId:N}|{Convert.ToBase64String(emailHash)}";
                var token = _pendingProtector.Protect(payload, MfaPendingLifetime);
                return new LoginResult(LoginStatus.RequiresMfa, MfaPendingToken: token);
            }

            return await CompleteLoginAsync(user.UserId, emailHash, ipAddr, userAgent, correlation, ct);
        }

        /* ------------------------------ Trin 2: MFA-kode ------------------------------ */

        public async Task<LoginResult> MfaStepAsync(string pendingToken, string code, string? ip, string? userAgent, CancellationToken ct)
        {
            var correlation = Guid.NewGuid();
            var ipAddr = ip ?? "unknown";

            Guid userId;
            byte[] emailHash;
            try
            {
                var parts = _pendingProtector.Unprotect(pendingToken).Split('|');
                userId = Guid.ParseExact(parts[0], "N");
                emailHash = Convert.FromBase64String(parts[1]);
            }
            catch (Exception e) when (e is CryptographicException or FormatException or IndexOutOfRangeException)
            {
                return new LoginResult(LoginStatus.Failed);   // udløbet eller manipuleret token
            }

            var throttle = await _repo.GetThrottleAsync(emailHash, ipAddr, ct);
            if (throttle.FailedByIp >= MaxFailedPerIp)
            {
                await _repo.RecordAttemptAsync(null, ipAddr, false, null, ct);
                return new LoginResult(LoginStatus.Throttled);
            }

            var mfa = await _repo.GetMfaDataAsync(userId, ct);
            var locked = mfa?.LockoutEndUtc is { } end && end > DateTime.UtcNow;
            if (mfa is null || !mfa.MfaEnabled || mfa.SecretEncrypted is null || locked || throttle.FailedByEmail >= MaxFailedPerEmail)
            {
                await _repo.RecordAttemptAsync(null, ipAddr, false, null, ct);
                await LogAsync("MfaFailed", "Warning", userId, ipAddr, "locked-or-not-enrolled", correlation, ct);
                return new LoginResult(LoginStatus.Failed);
            }

            var normalized = code.Replace(" ", "").Replace("-", "").ToUpperInvariant();
            var ok = false;

            if (TotpFormat().IsMatch(normalized))
            {
                var key = _secretProtector.Unprotect(mfa.SecretEncrypted);
                try
                {
                    if (Totp.Validate(key, normalized, DateTimeOffset.UtcNow) is { } step)
                    {
                        ok = await _repo.TryAdvanceMfaStepAsync(userId, step, ct);   // samme kode kan ikke genbruges
                    }
                }
                finally
                {
                    CryptographicOperations.ZeroMemory(key);
                }
            }
            else if (BackupFormat().IsMatch(normalized))
            {
                ok = await _repo.ConsumeBackupCodeAsync(userId, SHA256.HashData(Encoding.UTF8.GetBytes(normalized)), ct);
            }

            if (!ok)
            {
                // MFA-fejl tæller i samme tæller som password-fejl => 6-cifret kode kan ikke brute-forces
                var nowLocked = await _repo.RecordAttemptAsync(emailHash, ipAddr, false, userId, ct);
                await LogAsync("MfaFailed", "Warning", userId, ipAddr, "bad-code", correlation, ct);
                if (nowLocked)
                {
                    await LogAsync("AccountLocked", "Warning", userId, ipAddr, "too-many-failures", correlation, ct);
                }

                return new LoginResult(LoginStatus.Failed);
            }

            return await CompleteLoginAsync(userId, emailHash, ipAddr, userAgent, correlation, ct);
        }

        /* ------------------------------ Fælles ------------------------------ */

        private async Task<LoginResult> CompleteLoginAsync(Guid userId, byte[] emailHash, string ip, string? userAgent, Guid correlation, CancellationToken ct)
        {
            await _repo.RecordAttemptAsync(emailHash, ip, true, userId, ct);   // nulstiller tæller og lås

            // Altid NYT session-id efter login (session fixation)
            var sessionId = SessionIds.New();
            var ua = userAgent is { Length: > 300 } ? userAgent[..300] : userAgent;
            await _repo.CreateSessionAsync(SessionIds.Hash(sessionId), userId, SessionAbsoluteHours, ip, ua, ct);

            await LogAsync("LoginSuccess", "Info", userId, ip, null, correlation, ct);
            return new LoginResult(LoginStatus.Success, SessionId: sessionId);
        }

        public async Task LogoutAsync(string sessionId, Guid? userId, string? ip, CancellationToken ct)
        {
            await _repo.RevokeSessionAsync(SessionIds.Hash(sessionId), ct);
            await LogAsync("Logout", "Info", userId, ip, null, Guid.NewGuid(), ct);
        }

        public Task RevokeAsync(string sessionId, CancellationToken ct) =>
            _repo.RevokeSessionAsync(SessionIds.Hash(sessionId), ct);

        // Skal være identisk med normaliseringen ved oprettelse (US1), ellers rammer rate-limit-hashen forbi
        public static string NormalizeEmail(string email) =>
            email.Normalize(NormalizationForm.FormKC).Trim().ToLowerInvariant();

        private Task LogAsync(string type, string severity, Guid? userId, string? ip, string? details, Guid correlation, CancellationToken ct) =>
            _repo.LogSecurityEventAsync(type, severity, userId, ip, "/Account/Login", Sanitize(details), correlation, ct);

        // Aldrig passwords, tokens eller session-id i loggen; kontroltegn fjernes mod log injection
        private static string? Sanitize(string? s)
        {
            if (s is null) return null;
            var clean = new string(s.Select(c => char.IsControl(c) ? ' ' : c).ToArray());
            return clean.Length > 1000 ? clean[..1000] : clean;
        }
    }
}
