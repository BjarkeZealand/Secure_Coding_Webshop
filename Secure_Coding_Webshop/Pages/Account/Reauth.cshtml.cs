using System.ComponentModel.DataAnnotations;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;
using Secure_Coding_Webshop.Repo.Interfaces;
using Secure_Coding_Webshop.Services;

namespace Secure_Coding_Webshop.Pages.Account
{
    [Authorize]
    [EnableRateLimiting("login")]
    public sealed class ReauthModel : ShopPageModel
    {
        private readonly IAccountService _accounts;
        private readonly IAccountRepository _repo;

        public ReauthModel(IAccountService accounts, IAccountRepository repo)
        {
            _accounts = accounts;
            _repo = repo;
        }

        [BindProperty(SupportsGet = true)] public string? ReturnUrl { get; set; }
        [BindProperty, Required, StringLength(128)] public string Password { get; set; } = "";
        [BindProperty, StringLength(10)] public string? MfaCode { get; set; }
        public bool NeedsMfa { get; private set; }

        public async Task OnGetAsync() => await LoadAsync();

        public async Task<IActionResult> OnPostAsync()
        {
            await LoadAsync();
            if (!ModelState.IsValid) return Page();

            if (!await _accounts.ReauthenticateAsync(SessionHash, Password, MfaCode, Ip, Ct))
            {
                ModelState.AddModelError(string.Empty, "Adgangskoden eller koden er forkert.");
                return Page();
            }
            return LocalRedirect(SafeReturnUrl(ReturnUrl));
        }

        private async Task LoadAsync() =>
            NeedsMfa = (await _repo.GetProfileAsync(SessionHash, Ip, Ct))?.MfaEnabled == true;
    }
}
