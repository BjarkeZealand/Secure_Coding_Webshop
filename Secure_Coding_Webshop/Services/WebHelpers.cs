using System.Security.Cryptography;
using System.Text;
using Microsoft.AspNetCore.Mvc.Filters;

namespace Secure_Coding_Webshop.Services
{
    public static class HttpContextExtensions
    {
        /// <summary>Klientens IP som tekst (ForwardedHeaders-middleware sætter den korrekt bag en proxy).</summary>
        public static string? ClientIp(this HttpContext ctx) => ctx.Connection.RemoteIpAddress?.ToString();
    }

    /// <summary>Anonym kurv: tilfældig 128-bit nøgle i en __Host-cookie; databasen gemmer kun SHA-256 af den.</summary>
    public static class CartCookie
    {
        public const string Name = "__Host-cart";

        public static byte[]? ReadHash(HttpContext ctx) =>
            ctx.Request.Cookies.TryGetValue(Name, out var v) && v.Length is >= 16 and <= 64
                ? SHA256.HashData(Encoding.UTF8.GetBytes(v)) : null;

        public static byte[] EnsureHash(HttpContext ctx)
        {
            if (ReadHash(ctx) is { } existing) return existing;
            var key = Convert.ToHexString(RandomNumberGenerator.GetBytes(16));
            ctx.Response.Cookies.Append(Name, key, new CookieOptions
            {
                HttpOnly = true, Secure = true, SameSite = SameSiteMode.Lax, Path = "/", IsEssential = true,
                MaxAge = TimeSpan.FromDays(30)
            });
            return SHA256.HashData(Encoding.UTF8.GetBytes(key));
        }

        public static void Clear(HttpContext ctx) => ctx.Response.Cookies.Delete(Name, new CookieOptions { Secure = true, Path = "/" });
    }

    /// <summary>Sider med personlige data (konto, ordrer, admin) må ikke cache'es af browser eller proxy.</summary>
    public sealed class NoStorePageFilter : IAsyncPageFilter
    {
        public Task OnPageHandlerSelectionAsync(Microsoft.AspNetCore.Mvc.Filters.PageHandlerSelectedContext context) => Task.CompletedTask;

        public async Task OnPageHandlerExecutionAsync(PageHandlerExecutingContext context, PageHandlerExecutionDelegate next)
        {
            var headers = context.HttpContext.Response.Headers;
            headers.CacheControl = "no-store";
            headers.Pragma = "no-cache";
            await next();
        }
    }

    public static class SecurityHeaders
    {
        /// <summary>CSP uden inline script/style (scripts ligger i wwwroot/js), så XSS ikke kan køre kode.</summary>
        public static IApplicationBuilder UseSecurityHeaders(this IApplicationBuilder app) =>
            app.Use(async (ctx, next) =>
            {
                var h = ctx.Response.Headers;
                h["Content-Security-Policy"] =
                    "default-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'; " +
                    "object-src 'none'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'";
                h["X-Content-Type-Options"] = "nosniff";
                h["Referrer-Policy"] = "no-referrer";
                h["X-Frame-Options"] = "DENY";
                h["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()";
                await next();
            });
    }
}
