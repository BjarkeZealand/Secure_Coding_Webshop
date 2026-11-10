using System.Security.Cryptography;
using System.Text;
using Microsoft.AspNetCore.DataProtection;
using Secure_Coding_Webshop.Models;
using Secure_Coding_Webshop.Repo.Interfaces;
using Secure_Coding_Webshop.Services.Interfaces;

namespace Secure_Coding_Webshop.Services
{
    public enum PasswordChangeStatus { Changed, WrongCurrentPassword, PolicyViolation, Stale }

    public sealed record PasswordChangeOutcome(PasswordChangeStatus Status, IReadOnlyList<string> Errors);

    public sealed record MfaEnrollment(string SecretBase32, string OtpAuthUri);

    public interface IAccountService
    {
        Task<PasswordChangeOutcome> ChangePasswordAsync(byte[] sessionHash, string currentPassword, string newPassword, string? ip, CancellationToken ct);

        /// <summary>Svarer ALTID ens udadtil. Mailen lægges i baggrundskøen, så svartiden ikke afslører om kontoen findes.</summary>
        Task RequestResetAsync(string email, string? ip, CancellationToken ct);
        Task<ResetTokenInfo?> ValidateResetTokenAsync(string token, CancellationToken ct);
        Task<(ResetCompleteResult Result, IReadOnlyList<string> Errors)> CompleteResetAsync(string token, string newPassword, string? mfaCode, string? ip, CancellationToken ct);

        /// <summary>Bekræfter adgangskode (og MFA-kode hvis aktiv) igen og stempler sessionen. Følsomme handlinger kræver det.</summary>
        Task<bool> ReauthenticateAsync(byte[] sessionHash, string password, string? mfaCode, string? ip, CancellationToken ct);

        Task<MfaEnrollment?> BeginMfaEnrollAsync(byte[] sessionHash, string accountEmail, string? ip, CancellationToken ct);
        /// <summary>Returnerer de 10 backupkoder i klartekst (vises ÉN gang), eller null hvis koden var forkert.</summary>
        Task<IReadOnlyList<string>?> ActivateMfaAsync(byte[] sessionHash, string code, string? ip, CancellationToken ct);
        Task<IReadOnlyList<string>?> RegenerateBackupCodesAsync(byte[] sessionHash, string? ip, CancellationToken ct);
    }

    public sealed class AccountService : IAccountService
    {
        private const string Issuer = "Secure Coding Webshop";
        private static readonly string Base32Alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
        private static readonly string BackupAlphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";   // uden forvekslelige tegn

        private readonly IAccountRepository _repo;
        private readonly ILoginRepository _login;
        private readonly IPasswordHashService _hasher;
        private readonly IPasswordPolicy _policy;
        private readonly IDataProtector _secretProtector;
        private readonly IEmailQueue _mail;
        private readonly AppSettings _settings;
        private readonly IBreachedPasswordChecker _breached;

        public AccountService(IAccountRepository repo, ILoginRepository login, IPasswordHashService hasher, IPasswordPolicy policy,
            IDataProtectionProvider dataProtection, IEmailQueue mail, AppSettings settings, IBreachedPasswordChecker breached)
        {
            _repo = repo;
            _login = login;
            _hasher = hasher;
            _policy = policy;
            _mail = mail;
            _settings = settings;
            _breached = breached;
            // SAMME purpose som LoginService, ellers kan login ikke dekryptere hemmeligheden
            _secretProtector = dataProtection.CreateProtector("Secure_Coding_Webshop.MfaSecret.v1");
        }

        // Ud over IPasswordPolicy: admin-minimum, mønstre og kendte læk
        private async Task<List<string>> ExtraPasswordErrorsAsync(string normalized, byte roleId, CancellationToken ct)
        {
            var errors = PasswordPatterns.Check(normalized).ToList();
            if (roleId >= 2 && normalized.Length < 16) errors.Add("Administratorer skal bruge mindst 16 tegn.");
            if (await _breached.IsBreachedAsync(normalized, ct)) errors.Add("Adgangskoden findes i kendte datalæk. Vælg en anden.");
            return errors;
        }

        private static string Normalize(string s) => s.Normalize(NormalizationForm.FormKC);

        // ---------- US6: skift adgangskode ----------
        public async Task<PasswordChangeOutcome> ChangePasswordAsync(
            byte[] sessionHash, string currentPassword, string newPassword, string? ip, CancellationToken ct)
        {
            var data = await _repo.GetPasswordDataAsync(sessionHash, ip, ct)
                ?? throw new DbRuleException(DbRuleException.Unauthenticated, "app.usp_Password_GetForChange");

            // Verify er dyrt (Argon2id); kør den også, selv hvis politikken fejler senere, så tiden ikke afslører noget
            if (!_hasher.Verify(Normalize(currentPassword), data.PasswordHash))
                return new PasswordChangeOutcome(PasswordChangeStatus.WrongCurrentPassword, []);

            var normalizedNew = Normalize(newPassword);
            var profile = await _repo.GetProfileAsync(sessionHash, ip, ct);
            var errors = _policy.Validate(normalizedNew, data.Email, profile?.DisplayName ?? "").ToList();
            if (_hasher.Verify(normalizedNew, data.PasswordHash))
                errors.Add("Den nye adgangskode må ikke være den samme som den nuværende.");
            errors.AddRange(await ExtraPasswordErrorsAsync(normalizedNew, data.RoleId, ct));
            if (errors.Count > 0) return new PasswordChangeOutcome(PasswordChangeStatus.PolicyViolation, errors);

            var newHash = await _hasher.HashAsync(normalizedNew, ct);
            var result = await _repo.ChangePasswordAsync(sessionHash, data.PasswordHash, newHash, ip, ct);
            if (result.Result != 0) return new PasswordChangeOutcome(PasswordChangeStatus.Stale, []);

            if (result.Email is not null)
                _mail.TryEnqueue(new EmailMessage(result.Email, "Din adgangskode er ændret",
                    $"Hej {result.DisplayName},\n\nDin adgangskode blev lige ændret. Alle andre enheder er logget ud.\n" +
                    "Var det ikke dig, så nulstil adgangskoden med det samme og kontakt os."));
            return new PasswordChangeOutcome(PasswordChangeStatus.Changed, []);
        }

        // ---------- US6: glemt adgangskode ----------
        public async Task RequestResetAsync(string email, string? ip, CancellationToken ct)
        {
            var normalizedEmail = LoginService.NormalizeEmail(email);
            var token = Base64Url(RandomNumberGenerator.GetBytes(32));            // 256 bit
            var result = await _repo.RequestPasswordResetAsync(normalizedEmail, Sha256(token), ip, ct);
            if (!result.Created) return;

            var link = $"{_settings.PublicBaseUrl.TrimEnd('/')}/Account/ResetPassword?token={Uri.EscapeDataString(token)}";
            _mail.TryEnqueue(new EmailMessage(normalizedEmail, "Nulstil din adgangskode",
                $"Hej {result.DisplayName},\n\nKlik her for at vælge en ny adgangskode (linket virker i 30 minutter og kun én gang):\n{link}\n\n" +
                "Hvis du ikke har bedt om det, kan du ignorere denne mail."));
        }

        public Task<ResetTokenInfo?> ValidateResetTokenAsync(string token, CancellationToken ct) =>
            token.Length is 0 or > 100 ? Task.FromResult<ResetTokenInfo?>(null) : _repo.ValidateResetTokenAsync(Sha256(token), ct);

        public async Task<(ResetCompleteResult Result, IReadOnlyList<string> Errors)> CompleteResetAsync(
            string token, string newPassword, string? mfaCode, string? ip, CancellationToken ct)
        {
            var invalid = new ResetCompleteResult(1, null, null);
            var info = await ValidateResetTokenAsync(token, ct);
            if (info is null) return (invalid, []);

            // Admin/SysAdmin: kontoen kræver MFA-kode for at nulstille (recovery må ikke omgå MFA)
            var mfaVerified = false;
            if (info.RoleId >= 2 || info.MfaEnabled)
            {
                if (string.IsNullOrWhiteSpace(mfaCode) || !await VerifyMfaForUserAsync(info.UserId, Normalize(mfaCode).Trim().ToUpperInvariant(), ct))
                    return (new ResetCompleteResult(2, null, null), []);
                mfaVerified = true;
            }

            var normalizedNew = Normalize(newPassword);
            var errors = _policy.Validate(normalizedNew, "", "").ToList();
            errors.AddRange(await ExtraPasswordErrorsAsync(normalizedNew, info.RoleId, ct));
            if (errors.Count > 0) return (new ResetCompleteResult(3, null, null), errors);

            var hash = await _hasher.HashAsync(normalizedNew, ct);
            var result = await _repo.CompletePasswordResetAsync(Sha256(token), hash, mfaVerified, ip, ct);
            if (result.Result == 0 && result.Email is not null)
                _mail.TryEnqueue(new EmailMessage(result.Email, "Din adgangskode er nulstillet",
                    $"Hej {result.DisplayName},\n\nDin adgangskode er lige blevet nulstillet, og alle sessioner er afsluttet.\n" +
                    "Var det ikke dig, så kontakt os med det samme."));
            return (result, errors);
        }

        // ---------- Re-authentication ----------
        public async Task<bool> ReauthenticateAsync(byte[] sessionHash, string password, string? mfaCode, string? ip, CancellationToken ct)
        {
            var data = await _repo.GetPasswordDataAsync(sessionHash, ip, ct);
            if (data is null || !_hasher.Verify(Normalize(password), data.PasswordHash)) return false;

            if (data.MfaEnabled)
            {
                if (string.IsNullOrWhiteSpace(mfaCode)) return false;
                if (!await VerifyMfaForUserAsync(data.UserId, Normalize(mfaCode).Trim().ToUpperInvariant(), ct)) return false;
            }
            await _repo.MarkReauthAsync(sessionHash, ip, ct);
            return true;
        }

        // ---------- MFA ----------
        public async Task<MfaEnrollment?> BeginMfaEnrollAsync(byte[] sessionHash, string accountEmail, string? ip, CancellationToken ct)
        {
            var secret = RandomNumberGenerator.GetBytes(20);                     // 160 bit, RFC 4226 anbefaling
            var encrypted = _secretProtector.Protect(secret);
            if (!await _repo.BeginMfaEnrollAsync(sessionHash, encrypted, ip, ct)) return null;   // MFA er allerede aktiv

            var b32 = ToBase32(secret);
            var uri = $"otpauth://totp/{Uri.EscapeDataString(Issuer)}:{Uri.EscapeDataString(accountEmail)}" +
                      $"?secret={b32}&issuer={Uri.EscapeDataString(Issuer)}&algorithm=SHA1&digits=6&period=30";
            return new MfaEnrollment(b32, uri);
        }

        public async Task<IReadOnlyList<string>?> ActivateMfaAsync(byte[] sessionHash, string code, string? ip, CancellationToken ct)
        {
            var info = await _repo.GetMfaSecretAsync(sessionHash, ip, ct);
            if (info is null || info.MfaEnabled || info.SecretEncrypted is null) return null;

            byte[] key;
            try { key = _secretProtector.Unprotect(info.SecretEncrypted); }
            catch (CryptographicException) { return null; }

            if (Totp.Validate(key, code.Trim(), DateTimeOffset.UtcNow) is not { } step) return null;

            var (plain, hashes) = NewBackupCodes();
            return await _repo.ActivateMfaAsync(sessionHash, step, hashes, ip, ct) ? plain : null;
        }

        public async Task<IReadOnlyList<string>?> RegenerateBackupCodesAsync(byte[] sessionHash, string? ip, CancellationToken ct)
        {
            var (plain, hashes) = NewBackupCodes();
            // Kræver nylig re-authentication i databasen (50402 hvis ikke)
            return await _repo.ReplaceBackupCodesAsync(sessionHash, hashes, ip, ct) ? plain : null;
        }

        // ---------- Hjælpere ----------
        private async Task<bool> VerifyMfaForUserAsync(Guid userId, string normalizedCode, CancellationToken ct)
        {
            var mfa = await _login.GetMfaDataAsync(userId, ct);
            if (mfa is null || !mfa.MfaEnabled || mfa.SecretEncrypted is null) return false;

            if (normalizedCode.Length == 6 && normalizedCode.All(char.IsAsciiDigit))
            {
                byte[] key;
                try { key = _secretProtector.Unprotect(mfa.SecretEncrypted); }
                catch (CryptographicException) { return false; }
                return Totp.Validate(key, normalizedCode, DateTimeOffset.UtcNow) is { } step
                       && await _login.TryAdvanceMfaStepAsync(userId, step, ct);
            }
            if (normalizedCode.Length == 10)
                return await _login.ConsumeBackupCodeAsync(userId, Sha256(normalizedCode), ct);
            return false;
        }

        private static (IReadOnlyList<string> Plain, IReadOnlyList<byte[]> Hashes) NewBackupCodes()
        {
            var plain = new List<string>(10);
            var hashes = new List<byte[]>(10);
            for (var i = 0; i < 10; i++)
            {
                var chars = new char[10];
                for (var c = 0; c < chars.Length; c++) chars[c] = BackupAlphabet[RandomNumberGenerator.GetInt32(BackupAlphabet.Length)];
                var code = new string(chars);
                plain.Add(code);
                hashes.Add(Sha256(code));
            }
            return (plain, hashes);
        }

        private static byte[] Sha256(string value) => SHA256.HashData(Encoding.UTF8.GetBytes(value));

        private static string Base64Url(byte[] bytes) =>
            Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');

        private static string ToBase32(byte[] data)
        {
            var sb = new StringBuilder((data.Length * 8 + 4) / 5);
            int buffer = 0, bits = 0;
            foreach (var b in data)
            {
                buffer = (buffer << 8) | b;
                bits += 8;
                while (bits >= 5) { sb.Append(Base32Alphabet[(buffer >> (bits - 5)) & 31]); bits -= 5; }
            }
            if (bits > 0) sb.Append(Base32Alphabet[(buffer << (5 - bits)) & 31]);
            return sb.ToString();
        }
    }
}
