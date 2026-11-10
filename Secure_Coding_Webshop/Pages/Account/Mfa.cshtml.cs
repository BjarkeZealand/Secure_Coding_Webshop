using System.ComponentModel.DataAnnotations;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.AspNetCore.RateLimiting;
using Secure_Coding_Webshop.Services;

namespace Secure_Coding_Webshop.Pages.Account
{
    /// <summary>Trin 2 af login. (Aktivering af MFA ligger i MfaSetup.)</summary>
    [AllowAnonymous]
    [EnableRateLimiting("login")]
    public sealed class MfaModel : PageModel
    {
        private readonly ILoginService _login;
        private readonly IPostLoginService _postLogin;

        public MfaModel(ILoginService login, IPostLoginService postLogin)
        {
            _login = login;
            _postLogin = postLogin;
        }

        [BindProperty(SupportsGet = true)] public string? ReturnUrl { get; set; }

        [BindProperty, Required(ErrorMessage = "Skriv koden"), StringLength(16, MinimumLength = 6), DataType(DataType.Text)]
        public string Code { get; set; } = "";

        public IActionResult OnGet() =>
            Request.Cookies.ContainsKey(SessionCookie.MfaPendingName) ? Page() : RedirectToPage("Login");

        public async Task<IActionResult> OnPostAsync(CancellationToken ct)
        {
            if (!Request.Cookies.TryGetValue(SessionCookie.MfaPendingName, out var pending) || string.IsNullOrEmpty(pending))
                return RedirectToPage("Login");
            if (!ModelState.IsValid) return Page();

            var result = await _login.MfaStepAsync(pending, Code, HttpContext.ClientIp(), Request.Headers.UserAgent.ToString(), ct);

            switch (result.Status)
            {
                case LoginStatus.Success:
                    Response.Cookies.Delete(SessionCookie.MfaPendingName, SessionCookie.PendingOptions());
                    await SessionCookie.StartAsync(HttpContext, _login, result.SessionId!, ct);
                    await _postLogin.RunAsync(HttpContext, result.SessionId!, ct);
                    return !string.IsNullOrEmpty(ReturnUrl) && Url.IsLocalUrl(ReturnUrl) ? LocalRedirect(ReturnUrl) : LocalRedirect("/");

                case LoginStatus.Throttled:
                    Response.StatusCode = StatusCodes.Status429TooManyRequests;
                    ModelState.AddModelError(string.Empty, "For mange forsøg. Prøv igen om lidt.");
                    return Page();

                default:
                    ModelState.AddModelError(string.Empty, "Ugyldig kode");
                    return Page();
            }
        }
    }
}
