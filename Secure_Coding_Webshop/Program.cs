using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Mvc.ApplicationModels;
using Microsoft.AspNetCore.RateLimiting;
using Secure_Coding_Webshop.Models;
using Secure_Coding_Webshop.Repo;
using Secure_Coding_Webshop.Repo.Interfaces;
using Secure_Coding_Webshop.Repo.Shared.Factories;
using Secure_Coding_Webshop.Repo.Shared.Factories.Interfaces;
using Secure_Coding_Webshop.Services;
using Secure_Coding_Webshop.Services.Development;
using Secure_Coding_Webshop.Services.Interfaces;
using System.Threading.RateLimiting;
using Microsoft.AspNetCore.DataProtection;

namespace Secure_Coding_Webshop
{
    public class Program
    {
        public static void Main(string[] args)
        {

            var builder = WebApplication.CreateBuilder(args);

            builder.WebHost.ConfigureKestrel(o => o.AddServerHeader = false);
            // --- Konfiguration (connection string ligger i User Secrets) ---
            var appSection = builder.Configuration.GetSection("App");
            builder.Services.AddSingleton(new AppSettings(
                appSection["PublicBaseUrl"] ?? throw new InvalidOperationException("App:PublicBaseUrl mangler"),
                appSection["PrivacyPolicyVersion"] ?? throw new InvalidOperationException("App:PrivacyPolicyVersion mangler")));
            // Add services to the container.
            // US2: /Admin og /SysAdmin kræver login med den rette rolle (sættes server-side via sessionen)
            builder.Services.AddRazorPages(o =>
            {
                o.Conventions.AuthorizeFolder("/Admin", "AdminOnly");
                o.Conventions.AuthorizeFolder("/SysAdmin", "SysAdminOnly");
                o.Conventions.AuthorizeFolder("/Account");
                o.Conventions.AllowAnonymousToPage("/Account/Login");
                o.Conventions.AllowAnonymousToPage("/Account/Mfa");
                o.Conventions.AllowAnonymousToPage("/Account/ForgotPassword");
                o.Conventions.AllowAnonymousToPage("/Account/ResetPassword");
                o.Conventions.AllowAnonymousToPage("/Account/Register");
                o.Conventions.AllowAnonymousToPage("/Account/ConfirmEmail");
                o.Conventions.AllowAnonymousToPage("/Account/Logout");

                // Sider med personlige data må ikke ligge i browserens eller en proxys cache
                foreach (var folder in new[] { "/Account", "/Orders", "/Cart", "/Checkout", "/Payment", "/Admin", "/SysAdmin" })
                    o.Conventions.AddFolderApplicationModelConvention(folder, m => m.Filters.Add(new NoStorePageFilter()));
            });
            builder.Services.AddAntiforgery(o =>
            {
                o.Cookie.Name = "__Host-af";
                o.Cookie.HttpOnly = true;
                o.Cookie.SecurePolicy = CookieSecurePolicy.Always;
                o.Cookie.SameSite = SameSiteMode.Strict;
            });
            // --- Data-lag: factory + repository + decorator ---
            builder.Services.AddSingleton<ISqlConnectionFactory, SqlConnectionFactory>();
            builder.Services.AddSingleton<UserRepo>();
            builder.Services.AddSingleton<IUserRepository>(sp => new LoggingUserRepo(
                sp.GetRequiredService<UserRepo>(),
                sp.GetRequiredService<ILogger<LoggingUserRepo>>()));

            // --- US3-US11: repos (kun stored procedures) ---
            builder.Services.AddSingleton<IProductRepository, ProductRepo>();
            builder.Services.AddSingleton<ICartRepository, CartRepo>();
            builder.Services.AddSingleton<IOrderRepository, OrderRepo>();
            builder.Services.AddSingleton<IAccountRepository, AccountRepo>();
            builder.Services.AddSingleton<IAdminRepository, AdminRepo>();
            builder.Services.AddSingleton<ISysAdminRepository, SysAdminRepo>();

            // --- US3-US11: services ---
            builder.Services.AddSingleton<IAccountService, AccountService>();
            builder.Services.AddSingleton<IPostLoginService, PostLoginService>();   // kurv-merge + ny-enhed-mail efter login
            builder.Services.AddSingleton<IImageStorage, ImageStorage>();
            builder.Services.AddHttpClient<IBreachedPasswordChecker, HibpPasswordChecker>(c =>
            {
                c.BaseAddress = new Uri("https://api.pwnedpasswords.com/");
                c.Timeout = TimeSpan.FromSeconds(3);
            });
            builder.Services.AddSingleton<IPaymentGateway, MockPaymentGateway>();       // skiftes ud med rigtig udbyder
            builder.Services.AddSingleton<IPaymentWebhookService, PaymentWebhookService>();   // kræver Payment:WebhookSecret (user-secrets)

            // Maks. 2 MB billede + formularfelter
            builder.Services.Configure<Microsoft.AspNetCore.Http.Features.FormOptions>(o => o.MultipartBodyLengthLimit = 3 * 1024 * 1024);

            // --- Sikkerhed ---
            builder.Services.AddSingleton<IPasswordHashService, Argon2PasswordHashService>();
            builder.Services.AddSingleton<IPasswordPolicy, PasswordPolicy>();

            // --- US2: login, server-side sessioner og MFA ---
            // Login-repoet bruger din ISqlConnectionFactory (ConnectionStrings:Webshop, login webshop_app med EXECUTE på schema app)
            builder.Services.AddSingleton<ILoginRepository, LoginRepo>();
            builder.Services.AddSingleton<ILoginService, LoginService>();

            // Data Protection krypterer MFA-secrets og "MFA pending"-token. Nøglerne ligger uden for webroot og uden for Git.
            builder.Services.AddDataProtection()
                .SetApplicationName("Secure_Coding_Webshop")
                .PersistKeysToFileSystem(new DirectoryInfo(
                    builder.Configuration["DataProtection:KeyPath"]
                    ?? throw new InvalidOperationException("DataProtection:KeyPath mangler")));

            builder.Services
                .AddAuthentication(SessionAuthHandler.Scheme)
                .AddScheme<AuthenticationSchemeOptions, SessionAuthHandler>(SessionAuthHandler.Scheme, _ => { });

            builder.Services.AddAuthorizationBuilder()
                .AddPolicy("AdminOnly", p => p.RequireRole(RoleNames.Admin))
                .AddPolicy("SysAdminOnly", p => p.RequireRole(RoleNames.SysAdmin));

            // --- E-mail (sendes i baggrunden, så svartiden ikke afslører om e-mailen var ny) ---
            builder.Services.AddSingleton<EmailQueue>();
            builder.Services.AddSingleton<IEmailQueue>(sp => sp.GetRequiredService<EmailQueue>());
            builder.Services.AddHostedService<EmailBackgroundService>();
            if (builder.Environment.IsDevelopment())
                builder.Services.AddSingleton<IEmailSender, ConsoleEmailSender>();
            // Uden for udvikling mangler en IEmailSender (fx SMTP) med vilje: appen starter ikke uden en rigtig afsender.

            // --- Rate limiting: 5 registreringsforsøg (POST) pr. IP pr. time + grov flood-beskyttelse på login ---
            builder.Services.AddRateLimiter(o =>
            {
                o.RejectionStatusCode = StatusCodes.Status429TooManyRequests;
                o.AddPolicy("register", ctx =>
                    HttpMethods.IsPost(ctx.Request.Method)
                        ? RateLimitPartition.GetFixedWindowLimiter(
                            ctx.Connection.RemoteIpAddress?.ToString() ?? "unknown",
                            _ => new FixedWindowRateLimiterOptions
                            {
                                PermitLimit = 5,
                                Window = TimeSpan.FromHours(1),
                                QueueLimit = 0
                            })
                        : RateLimitPartition.GetNoLimiter("get"));

                // Den præcise tælling af mislykkede forsøg (5 pr. konto, 20 pr. IP pr. 15 min) sker i databasen
                o.AddPolicy("login", ctx =>
                    HttpMethods.IsPost(ctx.Request.Method)
                        ? RateLimitPartition.GetFixedWindowLimiter(
                            ctx.Connection.RemoteIpAddress?.ToString() ?? "unknown",
                            _ => new FixedWindowRateLimiterOptions
                            {
                                PermitLimit = 30,
                                Window = TimeSpan.FromMinutes(1),
                                QueueLimit = 0
                            })
                        : RateLimitPartition.GetNoLimiter("get"));
            });
            var app = builder.Build();

            app.UseExceptionHandler(errorApp => errorApp.Run(async ctx =>
            {
                ctx.Response.StatusCode = StatusCodes.Status500InternalServerError;
                await ctx.Response.WriteAsync("Der skete en fejl. Prøv igen senere.");
            }));
            if (!app.Environment.IsDevelopment()) app.UseHsts();
            app.UseHttpsRedirection();

            app.UseSecurityHeaders();
            // Configure the HTTP request pipeline.
            if (!app.Environment.IsDevelopment())
            {
                app.UseExceptionHandler("/Error");
                // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
                app.UseHsts();
            }

            app.UseHttpsRedirection();
            app.UseStaticFiles();

            app.UseRouting();

            // Rækkefølgen er vigtig: rate limiter -> authentication -> authorization.
            // UseRateLimiter manglede før, så [EnableRateLimiting("register")] blev ikke håndhævet.
            app.UseRateLimiter();
            app.UseAuthentication();
            app.UseAuthorization();

            // Admin og SysAdmin SKAL have MFA: uden aktiv MFA sendes de til tilmelding, før de kommer ind
            app.Use(async (ctx, next) =>
            {
                var path = ctx.Request.Path;
                if (ctx.User.Identity?.IsAuthenticated == true
                    && (path.StartsWithSegments("/Admin") || path.StartsWithSegments("/SysAdmin")))
                {
                    var repo = ctx.RequestServices.GetRequiredService<IAccountRepository>();
                    var profile = await repo.GetProfileAsync(ctx.User.GetSessionHash(), ctx.ClientIp(), ctx.RequestAborted);
                    if (profile is { MfaEnabled: false })
                    {
                        ctx.Response.Redirect("/Account/MfaSetup");
                        return;
                    }
                }
                await next();
            });

            app.MapRazorPages();

            // Betalingsudbyderens webhook: ingen cookie-login, i stedet HMAC-signatur + tidsstempel (se WebhookSignature)
            app.MapPost("/api/payments/webhook", async (HttpRequest req, IPaymentWebhookService webhook, CancellationToken ct) =>
            {
                if (req.ContentLength is null or > 16 * 1024) return Results.StatusCode(StatusCodes.Status413PayloadTooLarge);
                using var reader = new StreamReader(req.Body);
                var body = await reader.ReadToEndAsync(ct);
                return Results.StatusCode(await webhook.HandleAsync(body, req.Headers["X-Signature"].ToString(), ct));
            });

            // Produktbilleder ligger uden for wwwroot og serveres kun under genererede navne
            app.MapGet("/img/{name}", (string name, IImageStorage images) =>
            {
                var stream = images.Open(name, out var contentType);
                return stream is null ? Results.NotFound() : Results.File(stream, contentType);
            });

            app.Run();
        }
    }
}
