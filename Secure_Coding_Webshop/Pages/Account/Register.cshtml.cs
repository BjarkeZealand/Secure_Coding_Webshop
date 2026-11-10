using System.ComponentModel.DataAnnotations;
using System.Text;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.AspNetCore.RateLimiting;
using Secure_Coding_Webshop.Models;
using Secure_Coding_Webshop.Repo.Interfaces;
using Secure_Coding_Webshop.Services;
using Secure_Coding_Webshop.Services.Interfaces;

namespace Secure_Coding_Webshop.Pages.Account
{
    [AllowAnonymous]
    [EnableRateLimiting("register")]
    public sealed class RegisterModel : PageModel
    {
        private readonly IUserRepository _users;
        private readonly IPasswordHashService _hasher;
        private readonly IPasswordPolicy _policy;
        private readonly IBreachedPasswordChecker _breached;
        private readonly IEmailQueue _mail;
        private readonly AppSettings _settings;

        public RegisterModel(IUserRepository users, IPasswordHashService hasher, IPasswordPolicy policy,
            IBreachedPasswordChecker breached, IEmailQueue mail, AppSettings settings)
        {
            _users = users;
            _hasher = hasher;
            _policy = policy;
            _breached = breached;
            _mail = mail;
            _settings = settings;
        }

        public sealed class RegisterInput
        {
            [Required(ErrorMessage = "Skriv din e-mail"), EmailAddress(ErrorMessage = "Ugyldig e-mail"), StringLength(254)]
            public string Email { get; set; } = "";

            [Required(ErrorMessage = "Skriv dit navn"), StringLength(100, MinimumLength = 1)]
            public string DisplayName { get; set; } = "";

            [Required(ErrorMessage = "Vælg en adgangskode"), StringLength(128, MinimumLength = 12, ErrorMessage = "Adgangskoden skal være mellem 12 og 128 tegn"), DataType(DataType.Password)]
            public string Password { get; set; } = "";

            [Required(ErrorMessage = "Gentag adgangskoden"), Compare(nameof(Password), ErrorMessage = "De to adgangskoder er ikke ens"), DataType(DataType.Password)]
            public string ConfirmPassword { get; set; } = "";

            [Range(typeof(bool), "true", "true", ErrorMessage = "Du skal acceptere privatlivspolitikken")]
            public bool AcceptPrivacy { get; set; }
        }

        [BindProperty] public RegisterInput Input { get; set; } = new();
        public bool Submitted { get; private set; }
        public string PrivacyVersion => _settings.PrivacyPolicyVersion;

        public void OnGet() { }

        public async Task<IActionResult> OnPostAsync(CancellationToken ct)
        {
            if (!ModelState.IsValid) return Page();

            // Samme normalisering som ved login (NFKC), ellers kan password aldrig matche igen
            var email = LoginService.NormalizeEmail(Input.Email);
            var displayName = Input.DisplayName.Trim();
            var password = Input.Password.Normalize(NormalizationForm.FormKC);

            var errors = _policy.Validate(password, email, displayName).ToList();
            errors.AddRange(PasswordPatterns.Check(password));
            if (errors.Count == 0 && await _breached.IsBreachedAsync(password, ct))
                errors.Add("Adgangskoden findes i kendte datalæk. Vælg en anden.");
            if (errors.Count > 0)
            {
                foreach (var e in errors) ModelState.AddModelError(string.Empty, e);
                return Page();
            }

            // Hashing sker FØR databasekaldet, så svartiden er den samme for nye og eksisterende e-mails
            var hash = await _hasher.HashAsync(password, ct);
            var (token, tokenHash) = ConfirmationToken.Create();

            var created = await _users.RegisterAsync(
                new NewUser(email, displayName, hash, _settings.PrivacyPolicyVersion, tokenHash),
                HttpContext.ClientIp(), ct);

            if (created)
            {
                var link = $"{_settings.PublicBaseUrl.TrimEnd('/')}/Account/ConfirmEmail?token={token}";
                _mail.TryEnqueue(new EmailMessage(email, "Bekræft din konto",
                    $"Hej {displayName},\n\nBekræft din e-mail ved at åbne dette link (gyldigt i 24 timer):\n{link}\n\n" +
                    "Hvis du ikke har oprettet en konto, kan du ignorere denne mail."));
            }
            // Eksisterende e-mail: samme svar. (Valgfrit: send "nogen forsøgte at oprette en konto med din e-mail"-mail her.)

            Submitted = true;
            return Page();
        }
    }
}
