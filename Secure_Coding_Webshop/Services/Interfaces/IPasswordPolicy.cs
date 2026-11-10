namespace Secure_Coding_Webshop.Services.Interfaces
{
    public interface IPasswordPolicy
    {
        /// <summary>Returnerer fejlbeskeder (tom liste = godkendt). Forventer NFKC-normaliseret password.</summary>
        IReadOnlyList<string> Validate(string password, string email, string displayName);
    }
}
