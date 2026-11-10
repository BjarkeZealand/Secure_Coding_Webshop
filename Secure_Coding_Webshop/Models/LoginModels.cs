namespace Secure_Coding_Webshop.Models
{
    public sealed record CredentialRow(Guid UserId, string PasswordHash, byte RoleId, bool EmailConfirmed, bool MfaEnabled, DateTime? LockoutEndUtc);

    public sealed record MfaRow(Guid UserId, byte RoleId, bool MfaEnabled, byte[]? SecretEncrypted, DateTime? LockoutEndUtc);

    public sealed record ThrottleRow(int FailedByEmail, int FailedByIp);

    public sealed record SessionInfo(Guid UserId, byte RoleId, string DisplayName, bool EmailConfirmed);
}
