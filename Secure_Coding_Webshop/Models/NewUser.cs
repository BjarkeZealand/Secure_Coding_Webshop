namespace Secure_Coding_Webshop.Models
{
    public sealed record NewUser(
        string Email,
        string DisplayName,
        string PasswordHash,
        string PrivacyConsentVersion,
        byte[] ConfirmTokenHash)
    {
    }
}
