using System.ComponentModel.DataAnnotations;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.AspNetCore.RateLimiting;
using Secure_Coding_Webshop.Services;

namespace Secure_Coding_Webshop.Pages.Account
{
    [AllowAnonymous]
    [EnableRateLimiting("login")]
    public sealed class LoginModel : PageModel
    {
        private readonly ILoginService _login;
        private readonly IPostLoginService _postLogin;

        public LoginModel(ILoginService login, IPostLoginService postLogin)
        {
            _login = login;
            _postLogin = postLogin;
        }

        public sealed class InputModel
        {
            [Required(ErrorMessage = "Skriv din e-mail"), EmailAddress(ErrorMessage = "Ugyldig e-mail"), StringLength(254)]
            public string Email { get; set; } = "";

            // Loftet forhindrer enorme inputs i hash-funktionen
            [Required(ErrorMessage = "Skriv din adgangskode"), StringLength(128), DataType(DataType.Password)]
            public string Password { get; set; } = "";
        }

        [BindProperty] public InputModel Input { get; set; } = new();
        [BindProperty(SupportsGet = true)] public string? ReturnUrl { get; set; }

        public IActionResult OnGet() =>
            User.Identity?.IsAuthenticated == true ? LocalRedirect("/") : Page();

        public async Task<IActionResult> OnPostAsync(CancellationToken ct)
        {
            if (!ModelState.IsValid) return Page();

            var result = await _login.PasswordStepAsync(
                Input.Email, Input.Password, HttpContext.ClientIp(), Request.Headers.UserAgent.ToString(), ct);

            switch (result.Status)
            {
                case LoginStatus.Success:
                    // Ny session erstatter en evt. gammel (beskytter mod session fixation)
                    await SessionCookie.StartAsync(HttpContext, _login, result.SessionId!, ct);
                    await _postLogin.RunAsync(HttpContext, result.SessionId!, ct);
                    return SafeRedirect();

                case LoginStatus.RequiresMfa:
                    Response.Cookies.Append(SessionCookie.MfaPendingName, result.MfaPendingToken!, SessionCookie.PendingOptions());
                    return RedirectToPage("Mfa", new { returnUrl = ReturnUrl });

                case LoginStatus.Throttled:
                    Response.StatusCode = StatusCodes.Status429TooManyRequests;
                    ModelState.AddModelError(string.Empty, "For mange forsøg. Prøv igen om lidt.");
                    return Page();

                default:
                    // Samme besked uanset om e-mailen findes, adgangskoden er forkert eller kontoen er låst
                    ModelState.AddModelError(string.Empty, "Forkert e-mail eller adgangskode");
                    return Page();
            }
        }

        // Open redirect-beskyttelse: kun lokale stier
        private IActionResult SafeRedirect() =>
            !string.IsNullOrEmpty(ReturnUrl) && Url.IsLocalUrl(ReturnUrl) ? LocalRedirect(ReturnUrl) : LocalRedirect("/");
    }
}
