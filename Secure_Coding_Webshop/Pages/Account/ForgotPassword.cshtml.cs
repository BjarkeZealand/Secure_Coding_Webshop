using System.ComponentModel.DataAnnotations;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.AspNetCore.RateLimiting;
using Secure_Coding_Webshop.Services;

namespace Secure_Coding_Webshop.Pages.Account
{
    [EnableRateLimiting("login")]
    public sealed class ForgotPasswordModel : PageModel
    {
        private readonly IAccountService _accounts;

        public ForgotPasswordModel(IAccountService accounts) => _accounts = accounts;

        [BindProperty, Required, EmailAddress, StringLength(254)] public string Email { get; set; } = "";
        public bool Sent { get; private set; }

        public void OnGet() { }

        public async Task<IActionResult> OnPostAsync(CancellationToken ct)
        {
            if (!ModelState.IsValid) return Page();
            await _accounts.RequestResetAsync(Email, HttpContext.ClientIp(), ct);
            Sent = true;
            return Page();
        }
    }
}
