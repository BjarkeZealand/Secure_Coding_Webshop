using System.Security.Claims;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Secure_Coding_Webshop.Services;

namespace Secure_Coding_Webshop.Pages.Account
{
    [AllowAnonymous]
    public sealed class LogoutModel : PageModel
    {
        private readonly ILoginService _login;

        public LogoutModel(ILoginService login) => _login = login;

        public void OnGet() { }

        public async Task<IActionResult> OnPostAsync(CancellationToken ct)
        {
            if (Request.Cookies.TryGetValue(SessionCookie.Name, out var sessionId) && !string.IsNullOrEmpty(sessionId))
            {
                Guid? userId = Guid.TryParse(User.FindFirstValue(ClaimTypes.NameIdentifier), out var g) ? g : null;
                await _login.LogoutAsync(sessionId, userId, HttpContext.ClientIp(), ct);   // sessionen dør på serveren
            }
            SessionCookie.Clear(Response);
            CartCookie.Clear(HttpContext);
            return RedirectToPage("/Index");
        }
    }
}
