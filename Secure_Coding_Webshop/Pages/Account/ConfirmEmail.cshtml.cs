using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.AspNetCore.RateLimiting;
using Secure_Coding_Webshop.Repo.Interfaces;
using Secure_Coding_Webshop.Services;

namespace Secure_Coding_Webshop.Pages.Account
{
    public enum ConfirmState { Ready, Done, Invalid }

    [AllowAnonymous]
    [EnableRateLimiting("login")]
    public sealed class ConfirmEmailModel : PageModel
    {
        private readonly IUserRepository _users;

        public ConfirmEmailModel(IUserRepository users) => _users = users;

        [BindProperty(SupportsGet = true)] public string? Token { get; set; }
        public ConfirmState State { get; private set; } = ConfirmState.Invalid;

        public void OnGet() =>
            State = ConfirmationToken.TryHash(Token, out _) ? ConfirmState.Ready : ConfirmState.Invalid;

        public async Task<IActionResult> OnPostAsync(CancellationToken ct)
        {
            if (!ConfirmationToken.TryHash(Token, out var hash)) return Page();
            State = await _users.ConfirmEmailAsync(hash, HttpContext.ClientIp(), ct) ? ConfirmState.Done : ConfirmState.Invalid;
            return Page();
        }
    }
}
