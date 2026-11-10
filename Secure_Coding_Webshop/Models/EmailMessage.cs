namespace Secure_Coding_Webshop.Models
{
    public sealed record EmailMessage(string To, string Subject, string Body)
    {
    }
}
