using Secure_Coding_Webshop.Models;
using Secure_Coding_Webshop.Services.Interfaces;

namespace Secure_Coding_Webshop.Services.Development
{
    /// <summary>KUN til udvikling: skriver mailen i konsollen, så du kan klikke på bekræftelseslinket.</summary>
    public sealed class ConsoleEmailSender : IEmailSender
    {
        private readonly ILogger<ConsoleEmailSender> _log;
        public ConsoleEmailSender(ILogger<ConsoleEmailSender> log) => _log = log;

        public Task SendAsync(EmailMessage message, CancellationToken ct)
        {
            _log.LogInformation("DEV-MAIL til {To} | {Subject}{NewLine}{Body}", message.To, message.Subject, Environment.NewLine, message.Body);
            return Task.CompletedTask;
        }
    }
}
