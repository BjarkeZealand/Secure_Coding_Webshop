using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Secure_Coding_Webshop.Models;
using Secure_Coding_Webshop.Services;

namespace Secure_Coding_Webshop.Pages
{
    /// <summary>Fælles hjælpere: sessionens hash, klient-IP og ensartet håndtering af databasens afvisninger.</summary>
    public abstract class ShopPageModel : PageModel
    {
        protected byte[] SessionHash => User.GetSessionHash();
        protected string? Ip => HttpContext.ClientIp();
        protected CancellationToken Ct => HttpContext.RequestAborted;

        /// <summary>
        /// Kører handleren og oversætter databasens regler til svar:
        /// 50402 -> re-login-side, 50403 -> 403, 50401 -> login, 50409 -> besked om samtidig ændring.
        /// </summary>
        protected async Task<IActionResult> GuardAsync(Func<Task<IActionResult>> action)
        {
            try
            {
                return await action();
            }
            catch (DbRuleException ex) when (ex.Code == DbRuleException.ReauthRequired)
            {
                return RedirectToPage("/Account/Reauth", new { returnUrl = Request.Path + Request.QueryString });
            }
            catch (DbRuleException ex) when (ex.Code == DbRuleException.Forbidden)
            {
                return Forbid();
            }
            catch (DbRuleException ex) when (ex.Code == DbRuleException.Unauthenticated)
            {
                return Challenge();
            }
            catch (DbRuleException ex) when (ex.Code == DbRuleException.Validation)
            {
                ModelState.AddModelError(string.Empty, "Ugyldige data. Tjek felterne og prøv igen.");
                return Page();
            }
            catch (DbRuleException ex) when (ex.Code == DbRuleException.Conflict)
            {
                ModelState.AddModelError(string.Empty, "Posten blev ændret af en anden imens du redigerede. Indlæs siden igen.");
                return Page();
            }
        }

        /// <summary>Kun lokale returUrl'er (åbne redirects er en klassiker).</summary>
        protected string SafeReturnUrl(string? returnUrl, string fallback = "/") =>
            !string.IsNullOrEmpty(returnUrl) && Url.IsLocalUrl(returnUrl) ? returnUrl : fallback;
    }
}
