using System.ComponentModel.DataAnnotations;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Secure_Coding_Webshop.Services;

namespace Secure_Coding_Webshop.Pages.Account
{
    [Authorize]
    public sealed class ChangePasswordModel : ShopPageModel
    {
        private readonly IAccountService _accounts;

        public ChangePasswordModel(IAccountService accounts) => _accounts = accounts;

        public sealed class PasswordInput
        {
            [Required, StringLength(128)] public string Current { get; set; } = "";
            [Required, StringLength(128, MinimumLength = 12)] public string New { get; set; } = "";
            [Required, Compare(nameof(New), ErrorMessage = "De to nye adgangskoder er ikke ens.")] public string Confirm { get; set; } = "";
        }

        [BindProperty] public PasswordInput Input { get; set; } = new();
        public bool Done { get; private set; }

        public void OnGet() { }

        public Task<IActionResult> OnPostAsync() => GuardAsync(async () =>
        {
            if (!ModelState.IsValid) return Page();

            var outcome = await _accounts.ChangePasswordAsync(SessionHash, Input.Current, Input.New, Ip, Ct);
            switch (outcome.Status)
            {
                case PasswordChangeStatus.Changed:
                    Done = true;
                    break;
                case PasswordChangeStatus.WrongCurrentPassword:
                    ModelState.AddModelError(string.Empty, "Den nuværende adgangskode er forkert.");
                    break;
                case PasswordChangeStatus.PolicyViolation:
                    foreach (var e in outcome.Errors) ModelState.AddModelError(string.Empty, e);
                    break;
                default:
                    ModelState.AddModelError(string.Empty, "Noget ændrede sig undervejs. Prøv igen.");
                    break;
            }
            return Page();
        });
    }
}
