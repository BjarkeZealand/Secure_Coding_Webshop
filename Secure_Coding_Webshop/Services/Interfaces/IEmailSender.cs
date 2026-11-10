using Secure_Coding_Webshop.Models;

namespace Secure_Coding_Webshop.Services.Interfaces
{
    public interface IEmailSender { Task SendAsync(EmailMessage message, CancellationToken ct); }
}
