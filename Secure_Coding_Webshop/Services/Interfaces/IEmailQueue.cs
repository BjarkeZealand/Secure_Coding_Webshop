using Secure_Coding_Webshop.Models;

namespace Secure_Coding_Webshop.Services.Interfaces
{
    public interface IEmailQueue { bool TryEnqueue(EmailMessage message); }
}
