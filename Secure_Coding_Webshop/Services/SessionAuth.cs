using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Text.Encodings.Web;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Options;
using Secure_Coding_Webshop.Repo.Interfaces;

namespace Secure_Coding_Webshop.Services;

public static class RoleNames
{
    public const string Customer = "Customer";
    public const string Admin = "Admin";
    public const string SysAdmin = "SysAdmin";

    // Matcher dbo.Roles (1, 2, 3). Rollen læses KUN fra databasen via sessionen, aldrig fra requesten.
    public static string Name(byte roleId) => roleId switch
    {
        2 => Admin,
        3 => SysAdmin,
        _ => Customer
    };
}

public static class SessionIds
{
    /// <summary>256 bit kryptografisk tilfældigt id (krav: mindst 128 bit). Kun hashen gemmes i databasen.</summary>
    public static string New() => Base64UrlEncode(RandomNumberGenerator.GetBytes(32));

    public static byte[] Hash(string sessionId) => SHA256.HashData(Encoding.UTF8.GetBytes(sessionId));

    private static string Base64UrlEncode(byte[] bytes) =>
        Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');
}

public static class SessionClaims
{
    public const string SessionHash = "session_hash";

    /// <summary>
    /// SHA-256 af session-id'et (aldrig selve id'et). Sendes som første parameter til admin-procedurerne,
    /// som selv slår rollen op i databasen.
    /// </summary>
    public static byte[] GetSessionHash(this ClaimsPrincipal user)
    {
        var value = user.FindFirstValue(SessionHash)
            ?? throw new InvalidOperationException("Brugeren har ingen session");
        return Convert.FromBase64String(value);
    }
}

public static class SessionCookie
{
    // __Host-: kræver Secure, Path=/ og intet Domain => kan ikke overskrives af subdomæner
    public const string Name = "__Host-session";
    public const string MfaPendingName = "__Host-mfa-pending";

    // Ingen Expires/MaxAge => session-cookie. Den rigtige udløbstid håndhæves på serveren.
    public static CookieOptions Options() => new()
    {
        HttpOnly = true,
        Secure = true,
        SameSite = SameSiteMode.Lax,
        Path = "/",
        IsEssential = true
    };

    // Kortlivet cookie mellem password-trin og MFA-trin (indholdet er krypteret og udløber efter 5 min)
    public static CookieOptions PendingOptions() => new()
    {
        HttpOnly = true,
        Secure = true,
        SameSite = SameSiteMode.Lax,
        Path = "/",
        IsEssential = true,
        MaxAge = TimeSpan.FromMinutes(5)
    };

    public static void Set(HttpResponse response, string sessionId) =>
        response.Cookies.Append(Name, sessionId, Options());

    public static void Clear(HttpResponse response) =>
        response.Cookies.Delete(Name, Options());

    /// <summary>Starter ny session og tilbagekalder en evt. gammel (nyt session-id efter login).</summary>
    public static async Task StartAsync(HttpContext ctx, ILoginService login, string newSessionId, CancellationToken ct)
    {
        if (ctx.Request.Cookies.TryGetValue(Name, out var old) && !string.IsNullOrEmpty(old))
            await login.RevokeAsync(old, ct);
        Set(ctx.Response, newSessionId);
    }
}

/// <summary>
/// Autentificering mod server-side sessioner: cookien indeholder kun et tilfældigt id.
/// Rolle, udløb (idle 20 min / absolut 8 t) og tilbagekaldelse tjekkes i databasen ved hver request.
/// </summary>
public sealed class SessionAuthHandler(
    IOptionsMonitor<AuthenticationSchemeOptions> options,
    ILoggerFactory logger,
    UrlEncoder encoder,
    ILoginRepository repo)
    : AuthenticationHandler<AuthenticationSchemeOptions>(options, logger, encoder)
{
    public const string Scheme = "ServerSession";

    protected override async Task<AuthenticateResult> HandleAuthenticateAsync()
    {
        if (!Request.Cookies.TryGetValue(SessionCookie.Name, out var sessionId)
            || string.IsNullOrEmpty(sessionId) || sessionId.Length > 128)
            return AuthenticateResult.NoResult();

        var sessionHash = SessionIds.Hash(sessionId);
        var info = await repo.ValidateSessionAsync(sessionHash, Context.RequestAborted);
        if (info is null) return AuthenticateResult.NoResult();   // ukendt, udløbet eller tilbagekaldt

        var identity = new ClaimsIdentity(
        [
            new Claim(ClaimTypes.NameIdentifier, info.UserId.ToString()),
            new Claim(ClaimTypes.Name, info.DisplayName),
            new Claim(ClaimTypes.Role, RoleNames.Name(info.RoleId)),
            new Claim("email_confirmed", info.EmailConfirmed ? "true" : "false"),
            new Claim(SessionClaims.SessionHash, Convert.ToBase64String(sessionHash))
        ], Scheme);

        return AuthenticateResult.Success(new AuthenticationTicket(new ClaimsPrincipal(identity), Scheme));
    }

    protected override Task HandleChallengeAsync(AuthenticationProperties properties)
    {
        var target = "/Account/Login";
        // returnUrl er kun en lokal sti; Login-siden validerer den igen med Url.IsLocalUrl
        if (HttpMethods.IsGet(Request.Method))
            target += "?returnUrl=" + Uri.EscapeDataString(Request.Path + Request.QueryString);
        Response.Redirect(target);
        return Task.CompletedTask;
    }
}
