using System.ComponentModel.DataAnnotations;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Secure_Coding_Webshop.Models;
using Secure_Coding_Webshop.Repo.Interfaces;
using Secure_Coding_Webshop.Services;

namespace Secure_Coding_Webshop.Pages.Account
{
    [Authorize]
    public sealed class MfaSetupModel : ShopPageModel
    {
        private readonly IAccountService _accounts;
        private readonly IAccountRepository _repo;

        public MfaSetupModel(IAccountService accounts, IAccountRepository repo)
        {
            _accounts = accounts;
            _repo = repo;
        }

        [BindProperty, RegularExpression(@"^\d{6}$", ErrorMessage = "Koden består af 6 cifre.")] public string Code { get; set; } = "";
        public AccountProfile? Profile { get; private set; }
        public MfaEnrollment? Enrollment { get; private set; }
        public IReadOnlyList<string>? BackupCodes { get; private set; }

        public async Task<IActionResult> OnGetAsync()
        {
            Profile = await _repo.GetProfileAsync(SessionHash, Ip, Ct);
            return Page();
        }

        public Task<IActionResult> OnPostStartAsync() => GuardAsync(async () =>
        {
            Profile = await _repo.GetProfileAsync(SessionHash, Ip, Ct);
            if (Profile is null) return Challenge();
            Enrollment = await _accounts.BeginMfaEnrollAsync(SessionHash, Profile.Email, Ip, Ct);
            return Page();
        });

        public Task<IActionResult> OnPostActivateAsync() => GuardAsync(async () =>
        {
            Profile = await _repo.GetProfileAsync(SessionHash, Ip, Ct);
            if (Profile is null) return Challenge();
            if (!ModelState.IsValid) { Enrollment = await ReloadEnrollmentAsync(); return Page(); }

            BackupCodes = await _accounts.ActivateMfaAsync(SessionHash, Code, Ip, Ct);
            if (BackupCodes is null)
            {
                ModelState.AddModelError(string.Empty, "Koden er forkert. Der er lavet en NY nøgle: scan eller indtast den igen, og brug en frisk kode.");
                Enrollment = await ReloadEnrollmentAsync();
            }
            return Page();
        });

        // Databasen kræver nylig re-authentication (5 min) til de to følgende; GuardAsync sender videre til /Account/Reauth
        public Task<IActionResult> OnPostNewCodesAsync() => GuardAsync(async () =>
        {
            BackupCodes = await _accounts.RegenerateBackupCodesAsync(SessionHash, Ip, Ct);
            Profile = await _repo.GetProfileAsync(SessionHash, Ip, Ct);
            return Page();
        });

        public Task<IActionResult> OnPostDisableAsync() => GuardAsync(async () =>
        {
            await _repo.DisableMfaAsync(SessionHash, Ip, Ct);
            return RedirectToPage();
        });

        private async Task<MfaEnrollment?> ReloadEnrollmentAsync() =>
            // Hemmeligheden er allerede gemt; en ny Start overskriver den, så brugeren får en frisk QR-kode
            Profile is null ? null : await _accounts.BeginMfaEnrollAsync(SessionHash, Profile.Email, Ip, Ct);
    }
}
