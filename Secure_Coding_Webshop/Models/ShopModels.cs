namespace Secure_Coding_Webshop.Models
{
    // ---------- Fælles ----------
    public sealed record PagedResult<T>(IReadOnlyList<T> Items, int Total, int Page, int PageSize)
    {
        public int TotalPages => PageSize <= 0 ? 0 : (int)Math.Ceiling(Total / (double)PageSize);
    }

    // ---------- Produkter (US3, US7) ----------
    public sealed record CategoryRow(int CategoryId, string Name);

    public sealed record ProductListItem(
        int ProductId, int CategoryId, string CategoryName, string Name, string ShortDescription,
        decimal Price, int StockQuantity, string? ImageFileName);

    public sealed record ProductDetail(
        int ProductId, int CategoryId, string CategoryName, string Name, string Description,
        decimal Price, int StockQuantity, string? ImageFileName);

    // ---------- Kurv (US4) ----------
    /// <summary>Resultatkode fra kurv-procedurerne (0 ok, 1 produkt utilgængeligt, 2 for lidt lager, 3 ugyldigt antal).</summary>
    public enum CartResult { Ok = 0, Unavailable = 1, NotEnoughStock = 2, InvalidQuantity = 3 }

    public sealed record CartLine(
        int ProductId, string Name, decimal UnitPrice, int Quantity, decimal LineTotal,
        int StockQuantity, bool IsActive, string? ImageFileName);

    // ---------- Ordrer (US5, US8) ----------
    /// <summary>0 oprettet, 1 tom kurv, 2 vare utilgængelig/udsolgt, 3 for mange ubetalte ordrer, 5 gentagelse (samme nøgle).</summary>
    public enum OrderCreateStatus { Created = 0, EmptyCart = 1, Unavailable = 2, TooManyPending = 3, Replay = 5 }

    public sealed record OrderCreateResult(OrderCreateStatus Status, Guid? OrderId, decimal? TotalAmount);

    public sealed record ShippingAddress(string Name, string AddressLine, string PostalCode, string City, string Country);

    public sealed record OrderSummary(Guid OrderId, DateTime CreatedAtUtc, string Status, decimal TotalAmount, string Currency);

    public sealed record OrderLine(int ProductId, string ProductName, decimal UnitPrice, int Quantity);

    public sealed record OrderDetail(
        Guid OrderId, string? CustomerName, DateTime CreatedAtUtc, string Status, DateTime? PaidAtUtc,
        decimal TotalAmount, string Currency, ShippingAddress Shipping, IReadOnlyList<OrderLine> Lines);

    /// <summary>0 ok, 1 dublet, 2 ukendt ordre/reference, 3 forkert beløb, 4 betaling til lukket ordre.</summary>
    public enum PaymentApplyStatus { Applied = 0, Duplicate = 1, UnknownOrder = 2, AmountMismatch = 3, ClosedOrder = 4 }

    public sealed record PaymentApplyResult(
        PaymentApplyStatus Status, bool Transitioned, string? OrderStatus, Guid OrderId,
        string? UserEmail, string? DisplayName, decimal? TotalAmount);

    // ---------- Konto (US6, US2, US11) ----------
    public sealed record PasswordChangeData(Guid UserId, string Email, string PasswordHash, bool MfaEnabled, byte RoleId);

    /// <summary>Result 0 = ændret, 1 = forældet (prøv igen).</summary>
    public sealed record PasswordChangeResult(int Result, string? Email, string? DisplayName);

    public sealed record ResetRequestResult(bool Created, string? DisplayName);

    public sealed record ResetTokenInfo(Guid UserId, byte RoleId, bool MfaEnabled);

    /// <summary>Result 0 = gennemført, 1 = ugyldigt/brugt/udløbet link, 2 = kræver ekstra verifikation (admin).</summary>
    public sealed record ResetCompleteResult(int Result, string? Email, string? DisplayName);

    public sealed record AccountProfile(string DisplayName, string Email, byte RoleId, bool EmailConfirmed, bool MfaEnabled, int UnusedBackupCodes);

    public sealed record MfaSecretInfo(bool MfaEnabled, byte[]? SecretEncrypted);

    public sealed record DeviceInfo(bool IsNew, bool HadPreviousDevices, string Email, string DisplayName);

    // ---------- Admin (US9) ----------
    public sealed record AdminProductItem(
        int ProductId, int CategoryId, string CategoryName, string Name, decimal Price,
        int StockQuantity, bool IsActive, DateTime? UpdatedAtUtc);

    public sealed record AdminProductDetail(
        int ProductId, int CategoryId, string Name, string Description, decimal Price,
        int StockQuantity, string? ImageFileName, bool IsActive, byte[] RowVersion);

    public sealed record ProductInput(
        int CategoryId, string Name, string Description, decimal Price, int StockQuantity, string? ImageFileName);

    // ---------- SysAdmin (US10) ----------
    public sealed record SecurityEventRow(
        long EventId, DateTime OccurredAtUtc, string EventType, string Severity, Guid? UserId,
        string? IpAddress, string? Resource, string? Details, Guid? CorrelationId);

    public sealed record AuditRow(
        long AuditId, DateTime OccurredAtUtc, Guid? ActorUserId, string Action, string EntityType,
        string? EntityId, string? OldValueJson, string? NewValueJson, string? IpAddress);

    public sealed record SecurityEventFilter(
        DateTime? FromUtc, DateTime? ToUtc, string? EventType, string? Severity, Guid? UserId, string? Ip);

    public sealed record AuditFilter(DateTime? FromUtc, DateTime? ToUtc, string? Action, string? EntityType, Guid? ActorUserId);

    public sealed record AlertRow(string AlertType, string Subject, int EventCount, DateTime FirstAtUtc, DateTime LastAtUtc);

    public sealed record ChainResult(string LogName, long RowsChecked, long BrokenRows, long? FirstBrokenId);
}
