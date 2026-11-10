using System.ComponentModel.DataAnnotations;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.AspNetCore.RateLimiting;
using Secure_Coding_Webshop.Services;

namespace Secure_Coding_Webshop.Pages.Account
{
    [EnableRateLimiting("login")]
    public sealed class ResetPasswordModel : PageModel
    {
        private readonly IAccountService _accounts;

        public ResetPasswordModel(IAccountService accounts) => _accounts = accounts;

        [BindProperty(SupportsGet = true), StringLength(100)] public string Token { get; set; } = "";
        [BindProperty, Required, StringLength(128, MinimumLength = 12)] public string NewPassword { get; set; } = "";
        [BindProperty, Required, Compare(nameof(NewPassword), ErrorMessage = "De to adgangskoder er ikke ens.")] public string Confirm { get; set; } = "";
        [BindProperty, StringLength(10)] public string? MfaCode { get; set; }

        public bool TokenValid { get; private set; }
        public bool NeedsMfa { get; private set; }
        public bool Done { get; private set; }

        public async Task OnGetAsync(CancellationToken ct) => await LoadAsync(ct);

        public async Task<IActionResult> OnPostAsync(CancellationToken ct)
        {
            await LoadAsync(ct);
            if (!TokenValid || !ModelState.IsValid) return Page();

            var (result, errors) = await _accounts.CompleteResetAsync(Token, NewPassword, MfaCode, HttpContext.ClientIp(), ct);
            switch (result.Result)
            {
                case 0: Done = true; break;
                case 2: ModelState.AddModelError(string.Empty, "Koden er forkert."); break;
                case 3:
                    foreach (var e in errors) ModelState.AddModelError(string.Empty, e);
                    break;
                default: TokenValid = false; break;
            }
            return Page();
        }

        private async Task LoadAsync(CancellationToken ct)
        {
            var info = await _accounts.ValidateResetTokenAsync(Token, ct);
            TokenValid = info is not null;
            NeedsMfa = info is { MfaEnabled: true } || info is { RoleId: >= 2 };
        }
    }
}
