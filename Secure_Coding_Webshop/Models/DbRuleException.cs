namespace Secure_Coding_Webshop.Models
{
    /// <summary>
    /// Kastes af repoerne, når en stored procedure afviser kaldet med en af de aftalte fejlkoder (50400-50409).
    /// Erstatter ForbiddenException. Beskeden er kun til logs og må aldrig vises for brugeren.
    /// </summary>
    public sealed class DbRuleException : Exception
    {
        public const int Validation = 50400;       // ugyldigt input
        public const int Unauthenticated = 50401;  // ingen/udløbet session
        public const int ReauthRequired = 50402;   // kræver nyligt login (adgangskode igen)
        public const int Forbidden = 50403;        // forkert rolle / e-mail ikke bekræftet
        public const int Conflict = 50409;         // RowVersion er ændret af en anden

        public DbRuleException(int code, string procedure) : base($"{procedure} afviste kaldet ({code})")
        {
            Code = code;
            Procedure = procedure;
        }

        public int Code { get; }
        public string Procedure { get; }

        public static bool IsRuleError(int sqlErrorNumber) => sqlErrorNumber is >= 50400 and <= 50409;
    }
}
