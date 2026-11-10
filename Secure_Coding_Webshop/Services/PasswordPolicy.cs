using Secure_Coding_Webshop.Services.Interfaces;

namespace Secure_Coding_Webshop.Services
{
    /// <summary>Kundepolicy: min. 12 / maks. 128 tegn, ingen kompositionsregler, ingen kendte/oplagte passwords.</summary>
    public sealed class PasswordPolicy : IPasswordPolicy
    {
        public const int MinLength = 12;
        public const int MaxLength = 128;
        private const string ShopName = "webshop";

        private readonly HashSet<string> _common;

        public PasswordPolicy(IWebHostEnvironment env)
        {
            // Læg fx top 100.000 fra SecLists i Resources/common-passwords.txt (ét password pr. linje)
            var path = Path.Combine(env.ContentRootPath, "Resources", "common-passwords.txt");
            _common = File.Exists(path)
                ? new HashSet<string>(File.ReadLines(path).Select(l => l.Trim().ToLowerInvariant()).Where(l => l.Length > 0))
                : new HashSet<string>();
        }

        public IReadOnlyList<string> Validate(string password, string email, string displayName)
        {
            var errors = new List<string>();

            if (password.Length < MinLength) errors.Add($"Passwordet skal være mindst {MinLength} tegn.");
            if (password.Length > MaxLength) errors.Add($"Passwordet må højst være {MaxLength} tegn.");
            if (errors.Count > 0) return errors; // spar resten (og CPU) når længden er forkert

            var lower = password.ToLowerInvariant();

            if (_common.Contains(lower))
                errors.Add("Dette password er for almindeligt eller kendt fra datalæk. Prøv en længere sætning.");

            if (password.Distinct().Count() <= 2)
                errors.Add("Passwordet består af for få forskellige tegn.");

            var local = email.Split('@')[0].ToLowerInvariant();
            var nameParts = displayName.ToLowerInvariant().Split(' ', StringSplitOptions.RemoveEmptyEntries);
            if (lower.Contains(email.ToLowerInvariant())
                || (local.Length >= 3 && lower.Contains(local))
                || lower.Contains(displayName.ToLowerInvariant())
                || nameParts.Any(n => n.Length >= 3 && lower.Contains(n))
                || lower.Contains(ShopName))
                errors.Add("Passwordet må ikke indeholde din e-mail, dit navn eller webshoppens navn.");

            return errors;
        }
    }
}
