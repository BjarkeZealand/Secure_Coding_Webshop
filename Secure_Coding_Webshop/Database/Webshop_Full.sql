/* =====================================================================
   WEBSHOP - COMPLETE DATABASE SCRIPT (user stories 1-11)
   Target: SQL Server 2017+ (uses TRANSLATE, STRING_SPLIT, THROW, CREATE OR ALTER)

   HOW TO RUN
   ----------
   Run the whole file once as a sysadmin/dbo-level login (e.g. sa locally) in SSMS.
   The script is RE-RUNNABLE:
     * tables/indexes are created only if missing, new columns are added with
       guarded ALTERs (so a database created by the earlier US1/US2 scripts is upgraded in place),
     * procedures/functions/triggers use CREATE OR ALTER,
     * logins/users are created only if missing, permissions are re-applied.
   To start over from scratch (development only):  DROP DATABASE Webshop;  then run again.

   ARCHITECTURE IN ONE PAGE
   ------------------------
   1. NO direct table access for the application.
      The web app logs in as [webshop_app]. That login has EXECUTE on the schemas
      [app], [admin] and [sysadmin] and is explicitly DENIED everything on schema [dbo]
      (where the tables live). Procedures work anyway because of OWNERSHIP CHAINING:
      all schemas are owned by dbo, so a procedure owned by dbo may touch dbo tables
      without the caller having table permissions. Consequence: even a complete
      SQL-injection or a stolen connection string can only call procedures; it cannot
      run SELECT * FROM Users, UPDATE, DROP, etc.
      RULE: never use dynamic SQL (EXEC(@sql)/sp_executesql) inside these procedures,
      because dynamic SQL breaks the ownership chain.

   2. Schemas = trust zones
        app       customer + public functions   (anonymous or any logged-in role)
        admin     Admin-only functions          (product management, order support lookups)
        sysadmin  SysAdmin-only functions       (log viewing, alerts, log integrity check)
        maint     operations (purge, seeding)   (NOT granted to the web app; own login)
        dbo       tables + internal helpers     (DENIED for the web app)

   3. AUTHORISATION INSIDE THE DATABASE (defence in depth)
      Every procedure that needs an identity takes @SessionIdHash (SHA-256 of the
      session cookie value; the raw session id never reaches the database) and calls
      dbo.usp_Internal_ResolveSession, which:
        - validates the server-side session (not revoked, absolute + idle timeout,
          user not deleted; idle timeout is 10 min for Admin/SysAdmin, 20 min for customers),
        - checks the role against a CONSTANT list written in the procedure ('2' = Admin ...),
        - optionally requires a confirmed e-mail and/or a recent re-authentication,
        - derives the acting user id from the session. The caller can NEVER pass a user id
          or an actor id, so IDOR/BOLA and audit-log forgery are impossible by construction.
      The ASP.NET authorisation policies stay in place for good UX (403 pages), the database
      is the backstop if somebody forgets an attribute.
      Keep the role lists in sync with the policies in Program.cs and the RBAC matrix:
        Customer=1, Admin=2, SysAdmin=3.

   4. ERROR CONTRACT (THROW numbers, mapped to exceptions in BaseRepo.cs)
        50400  validation failed        (message = short reason, never user data)
        50401  unauthenticated          (no valid session)
        50402  re-authentication needed (sensitive action, session too old)
        50403  forbidden                (wrong role / e-mail not confirmed). Message
                                         is 'Forbidden' or 'EmailNotConfirmed'
        50409  concurrency conflict     (optimistic locking on products)
      Business outcomes that are normal (cart full, out of stock, duplicate e-mail ...)
      are returned as a Result code, not as an exception.

   5. LOGGING WITH A HASH CHAIN (user story 10)
      dbo.SecurityEvents and dbo.AuditLog are written ONLY through
      dbo.usp_Internal_LogSecurityEvent / usp_Internal_LogAudit. Each row stores
      PrevHash and RowHash = SHA-256(fields + PrevHash). Editing or deleting a row in
      the middle breaks the chain; sysadmin.usp_Log_VerifyChain detects it.
      Control characters are stripped from free text (log injection).
      Chain writes are serialised with an application lock, so logging is deliberately
      "slow but tamper-evident". Truncating the END of the log cannot be detected by the
      chain alone: periodically copy the newest RowHash somewhere else (see notes in
      sysadmin.usp_Log_VerifyChain).
      Retention: 90 days security log, 2 years audit log (maint.usp_Purge_All). Purges
      store an anchor hash in dbo.LogAnchors so the chain stays verifiable afterwards.

   6. STOCK RESERVATION MODEL (user story 5)
      Stock is reduced when the order is CREATED (status Pending) using a conditional
      UPDATE ... WHERE StockQuantity >= qty inside the same transaction as the order
      insert. That is what makes "two buyers, one last item -> exactly one wins" true.
      Stock is given back when an order fails/cancels/expires (60 min). A payment
      confirmation that arrives for an already-closed order is NOT applied; it is logged
      as Critical (PaymentOnClosedOrder) so a human can refund it.

   7. OTHER DESIGN DECISIONS
      - Email column uses collation Latin1_General_100_CI_AS (the Danish collation treats
        'aa' = 'a-ring', which could make two different addresses collide).
      - Product descriptions are PLAIN TEXT only (output is HTML-encoded by Razor); no HTML is
        stored, so no sanitiser is needed.
      - Search/list: one procedure, ORDER BY is a fixed CASE whitelist (no dynamic SQL),
        LIKE wildcards are escaped inside the procedure.
   ===================================================================== */
SET NOCOUNT ON;
GO

IF DB_ID(N'Webshop') IS NULL
    CREATE DATABASE Webshop COLLATE Danish_Norwegian_CI_AS;
GO
USE Webshop;
GO

/* ---------------------------------------------------------------------
   0. Schemas
   --------------------------------------------------------------------- */
IF SCHEMA_ID(N'app')      IS NULL EXEC (N'CREATE SCHEMA app      AUTHORIZATION dbo');
IF SCHEMA_ID(N'admin')    IS NULL EXEC (N'CREATE SCHEMA [admin]  AUTHORIZATION dbo');
IF SCHEMA_ID(N'sysadmin') IS NULL EXEC (N'CREATE SCHEMA sysadmin AUTHORIZATION dbo');
IF SCHEMA_ID(N'maint')    IS NULL EXEC (N'CREATE SCHEMA maint    AUTHORIZATION dbo');
GO

/* ---------------------------------------------------------------------
   1. RBAC roles. Role changes are NOT possible through the application:
      only a DBA can UPDATE dbo.Users.RoleId, and a trigger logs it (section 6).
   --------------------------------------------------------------------- */
IF OBJECT_ID(N'dbo.Roles', N'U') IS NULL
BEGIN
    CREATE TABLE dbo.Roles (
        RoleId TINYINT      NOT NULL CONSTRAINT PK_Roles PRIMARY KEY,
        Name   NVARCHAR(30) NOT NULL CONSTRAINT UQ_Roles_Name UNIQUE
    );
    INSERT INTO dbo.Roles (RoleId, Name) VALUES (1, N'Customer'), (2, N'Admin'), (3, N'SysAdmin');
END
GO

/* ---------------------------------------------------------------------
   2. Users (US1, US2, US6, US11)
      PasswordHash      : Argon2id string incl. salt + parameters. Never plaintext.
      MfaSecretEncrypted: encrypted by the application (ASP.NET Data Protection).
      MfaLastUsedStep   : last accepted 30-second TOTP step -> a code cannot be replayed.
      IsDeleted         : GDPR anonymisation flag (row kept for order bookkeeping).
   --------------------------------------------------------------------- */
IF OBJECT_ID(N'dbo.Users', N'U') IS NULL
BEGIN
    CREATE TABLE dbo.Users (
        UserId                 UNIQUEIDENTIFIER NOT NULL CONSTRAINT DF_Users_Id DEFAULT NEWSEQUENTIALID() CONSTRAINT PK_Users PRIMARY KEY,
        Email                  NVARCHAR(254)    COLLATE Latin1_General_100_CI_AS NOT NULL,
        DisplayName            NVARCHAR(100)    NOT NULL,
        PasswordHash           NVARCHAR(255)    NOT NULL,
        PasswordChangedAtUtc   DATETIME2(0)     NOT NULL CONSTRAINT DF_Users_PwChanged DEFAULT SYSUTCDATETIME(),
        RoleId                 TINYINT          NOT NULL CONSTRAINT DF_Users_Role DEFAULT 1
                               CONSTRAINT FK_Users_Roles REFERENCES dbo.Roles(RoleId),
        EmailConfirmed         BIT              NOT NULL CONSTRAINT DF_Users_EmailConf DEFAULT 0,
        MfaEnabled             BIT              NOT NULL CONSTRAINT DF_Users_MfaEnabled DEFAULT 0,
        MfaSecretEncrypted     VARBINARY(512)   NULL,
        MfaLastUsedStep        BIGINT           NULL,
        FailedLoginCount       INT              NOT NULL CONSTRAINT DF_Users_Failed DEFAULT 0,
        LockoutEndUtc          DATETIME2(0)     NULL,
        PrivacyConsentVersion  NVARCHAR(20)     NOT NULL,
        PrivacyConsentAtUtc    DATETIME2(0)     NOT NULL,
        CreatedAtUtc           DATETIME2(0)     NOT NULL CONSTRAINT DF_Users_Created DEFAULT SYSUTCDATETIME(),
        IsDeleted              BIT              NOT NULL CONSTRAINT DF_Users_Deleted DEFAULT 0,
        CONSTRAINT CK_Users_Email CHECK (Email LIKE N'%_@_%._%')
    );
    -- Uniqueness is enforced by the database, not only by application code
    CREATE UNIQUE INDEX UX_Users_Email ON dbo.Users (Email);
END
GO

-- Upgrades for databases created by the earlier scripts ----------------------------------
IF COL_LENGTH(N'dbo.Users', N'MfaLastUsedStep') IS NULL
    ALTER TABLE dbo.Users ADD MfaLastUsedStep BIGINT NULL;
GO
IF EXISTS (SELECT 1 FROM sys.columns
           WHERE object_id = OBJECT_ID(N'dbo.Users') AND name = N'Email'
             AND collation_name <> N'Latin1_General_100_CI_AS')
BEGIN
    DROP INDEX UX_Users_Email ON dbo.Users;
    ALTER TABLE dbo.Users DROP CONSTRAINT CK_Users_Email;
    ALTER TABLE dbo.Users ALTER COLUMN Email NVARCHAR(254) COLLATE Latin1_General_100_CI_AS NOT NULL;
    ALTER TABLE dbo.Users ADD CONSTRAINT CK_Users_Email CHECK (Email LIKE N'%_@_%._%');
    CREATE UNIQUE INDEX UX_Users_Email ON dbo.Users (Email);
END
GO

/* One-time tokens for e-mail confirmation and password reset. Only the SHA-256 hash is stored. */
IF OBJECT_ID(N'dbo.UserTokens', N'U') IS NULL
BEGIN
    CREATE TABLE dbo.UserTokens (
        TokenId       BIGINT IDENTITY(1,1) NOT NULL CONSTRAINT PK_UserTokens PRIMARY KEY,
        UserId        UNIQUEIDENTIFIER NOT NULL CONSTRAINT FK_UserTokens_Users REFERENCES dbo.Users(UserId) ON DELETE CASCADE,
        Purpose       VARCHAR(20)      NOT NULL CONSTRAINT CK_UserTokens_Purpose CHECK (Purpose IN ('EmailConfirm','PasswordReset')),
        TokenHash     BINARY(32)       NOT NULL,
        CreatedAtUtc  DATETIME2(0)     NOT NULL CONSTRAINT DF_UserTokens_Created DEFAULT SYSUTCDATETIME(),
        ExpiresAtUtc  DATETIME2(0)     NOT NULL,
        UsedAtUtc     DATETIME2(0)     NULL
    );
    CREATE UNIQUE INDEX UX_UserTokens_Hash ON dbo.UserTokens (TokenHash);
    CREATE INDEX IX_UserTokens_User ON dbo.UserTokens (UserId, Purpose);
END
GO

/* MFA backup codes (hashed, single use) */
IF OBJECT_ID(N'dbo.MfaBackupCodes', N'U') IS NULL
BEGIN
    CREATE TABLE dbo.MfaBackupCodes (
        BackupCodeId BIGINT IDENTITY(1,1) NOT NULL CONSTRAINT PK_MfaBackupCodes PRIMARY KEY,
        UserId       UNIQUEIDENTIFIER NOT NULL CONSTRAINT FK_MfaBackup_Users REFERENCES dbo.Users(UserId) ON DELETE CASCADE,
        CodeHash     BINARY(32)       NOT NULL,
        UsedAtUtc    DATETIME2(0)     NULL
    );
    CREATE INDEX IX_MfaBackupCodes_User ON dbo.MfaBackupCodes (UserId, CodeHash);
END
GO

/* ---------------------------------------------------------------------
   3. Server-side sessions (US2). Revocable. Only SHA-256(session id) is stored.
      ReauthAtUtc = last time the user proved identity again (password [+ MFA]);
      sensitive admin actions (deleting a product, disabling MFA, deleting the account)
      require it to be recent.
   --------------------------------------------------------------------- */
IF OBJECT_ID(N'dbo.Sessions', N'U') IS NULL
BEGIN
    CREATE TABLE dbo.Sessions (
        SessionIdHash     BINARY(32)       NOT NULL CONSTRAINT PK_Sessions PRIMARY KEY,
        UserId            UNIQUEIDENTIFIER NOT NULL CONSTRAINT FK_Sessions_Users REFERENCES dbo.Users(UserId) ON DELETE CASCADE,
        CreatedAtUtc      DATETIME2(0)     NOT NULL CONSTRAINT DF_Sessions_Created DEFAULT SYSUTCDATETIME(),
        LastSeenAtUtc     DATETIME2(0)     NOT NULL CONSTRAINT DF_Sessions_LastSeen DEFAULT SYSUTCDATETIME(),
        AbsoluteExpiryUtc DATETIME2(0)     NOT NULL,
        RevokedAtUtc      DATETIME2(0)     NULL,
        IpAddress         VARCHAR(45)      NULL,
        UserAgent         NVARCHAR(300)    NULL,
        ReauthAtUtc       DATETIME2(0)     NULL
    );
    CREATE INDEX IX_Sessions_User ON dbo.Sessions (UserId);
END
GO
IF COL_LENGTH(N'dbo.Sessions', N'ReauthAtUtc') IS NULL
    ALTER TABLE dbo.Sessions ADD ReauthAtUtc DATETIME2(0) NULL;
GO

/* Login attempts for rate limiting per e-mail hash and per IP */
IF OBJECT_ID(N'dbo.LoginAttempts', N'U') IS NULL
BEGIN
    CREATE TABLE dbo.LoginAttempts (
        AttemptId      BIGINT IDENTITY(1,1) NOT NULL CONSTRAINT PK_LoginAttempts PRIMARY KEY,
        EmailHash      BINARY(32)   NULL,          -- SHA-256 of the normalised e-mail (no plaintext)
        IpAddress      VARCHAR(45)  NOT NULL,
        Succeeded      BIT          NOT NULL,
        AttemptedAtUtc DATETIME2(0) NOT NULL CONSTRAINT DF_LoginAttempts_At DEFAULT SYSUTCDATETIME()
    );
    CREATE INDEX IX_LoginAttempts_Ip    ON dbo.LoginAttempts (IpAddress, AttemptedAtUtc);
    CREATE INDEX IX_LoginAttempts_Email ON dbo.LoginAttempts (EmailHash, AttemptedAtUtc);
END
GO

/* Known devices: used for the optional "login from a new device" notification e-mail (US2 stretch goal).
   DeviceHash = SHA-256(User-Agent). No IP address is stored here. */
IF OBJECT_ID(N'dbo.KnownDevices', N'U') IS NULL
BEGIN
    CREATE TABLE dbo.KnownDevices (
        UserId       UNIQUEIDENTIFIER NOT NULL CONSTRAINT FK_KnownDevices_Users REFERENCES dbo.Users(UserId) ON DELETE CASCADE,
        DeviceHash   BINARY(32)       NOT NULL,
        FirstSeenUtc DATETIME2(0)     NOT NULL CONSTRAINT DF_KnownDevices_First DEFAULT SYSUTCDATETIME(),
        LastSeenUtc  DATETIME2(0)     NOT NULL CONSTRAINT DF_KnownDevices_Last  DEFAULT SYSUTCDATETIME(),
        CONSTRAINT PK_KnownDevices PRIMARY KEY (UserId, DeviceHash)
    );
END
GO

/* ---------------------------------------------------------------------
   4. Catalogue (US3, US7, US9)
   --------------------------------------------------------------------- */
IF OBJECT_ID(N'dbo.Categories', N'U') IS NULL
BEGIN
    CREATE TABLE dbo.Categories (
        CategoryId INT IDENTITY(1,1) NOT NULL CONSTRAINT PK_Categories PRIMARY KEY,
        Name       NVARCHAR(100) NOT NULL CONSTRAINT UQ_Categories_Name UNIQUE
    );
END
GO

IF OBJECT_ID(N'dbo.Products', N'U') IS NULL
BEGIN
    CREATE TABLE dbo.Products (
        ProductId      INT IDENTITY(1,1) NOT NULL CONSTRAINT PK_Products PRIMARY KEY,
        CategoryId     INT            NOT NULL CONSTRAINT FK_Products_Categories REFERENCES dbo.Categories(CategoryId),
        Name           NVARCHAR(150)  NOT NULL,
        Description    NVARCHAR(2000) NOT NULL,                 -- plain text only
        Price          DECIMAL(10,2)  NOT NULL CONSTRAINT CK_Products_Price CHECK (Price > 0 AND Price <= 1000000),
        StockQuantity  INT            NOT NULL CONSTRAINT CK_Products_Stock CHECK (StockQuantity BETWEEN 0 AND 100000),
        ImageFileName  NVARCHAR(100)  NULL,                     -- generated '<32 hex>.jpg|png|webp', file lives outside webroot
        IsActive       BIT            NOT NULL CONSTRAINT DF_Products_Active DEFAULT 1,   -- soft delete
        CreatedAtUtc   DATETIME2(0)   NOT NULL CONSTRAINT DF_Products_Created DEFAULT SYSUTCDATETIME(),
        UpdatedAtUtc   DATETIME2(0)   NULL,
        RowVersion     ROWVERSION                               -- optimistic concurrency
    );
    CREATE INDEX IX_Products_Name     ON dbo.Products (Name) INCLUDE (Price, IsActive);
    CREATE INDEX IX_Products_Category ON dbo.Products (CategoryId, IsActive);
END
GO

/* ---------------------------------------------------------------------
   5. Cart (US4). A cart belongs to EXACTLY one owner: a user, or an anonymous cookie (hash).
      The client never sends a cart id; the owner is derived from the session / cookie.
   --------------------------------------------------------------------- */
IF OBJECT_ID(N'dbo.Carts', N'U') IS NULL
BEGIN
    CREATE TABLE dbo.Carts (
        CartId           UNIQUEIDENTIFIER NOT NULL CONSTRAINT DF_Carts_Id DEFAULT NEWID() CONSTRAINT PK_Carts PRIMARY KEY,
        UserId           UNIQUEIDENTIFIER NULL CONSTRAINT FK_Carts_Users REFERENCES dbo.Users(UserId) ON DELETE CASCADE,
        AnonymousKeyHash BINARY(32)       NULL,   -- SHA-256 of a random 128-bit cookie value
        CreatedAtUtc     DATETIME2(0)     NOT NULL CONSTRAINT DF_Carts_Created DEFAULT SYSUTCDATETIME(),
        UpdatedAtUtc     DATETIME2(0)     NOT NULL CONSTRAINT DF_Carts_Updated DEFAULT SYSUTCDATETIME(),
        CONSTRAINT CK_Carts_Owner CHECK ((UserId IS NOT NULL AND AnonymousKeyHash IS NULL)
                                      OR (UserId IS NULL AND AnonymousKeyHash IS NOT NULL))
    );
    CREATE UNIQUE INDEX UX_Carts_User ON dbo.Carts (UserId) WHERE UserId IS NOT NULL;
    CREATE UNIQUE INDEX UX_Carts_Anon ON dbo.Carts (AnonymousKeyHash) WHERE AnonymousKeyHash IS NOT NULL;
    CREATE INDEX IX_Carts_Updated ON dbo.Carts (UpdatedAtUtc);
END
GO

IF OBJECT_ID(N'dbo.CartItems', N'U') IS NULL
BEGIN
    CREATE TABLE dbo.CartItems (
        CartId     UNIQUEIDENTIFIER NOT NULL CONSTRAINT FK_CartItems_Carts REFERENCES dbo.Carts(CartId) ON DELETE CASCADE,
        ProductId  INT              NOT NULL CONSTRAINT FK_CartItems_Products REFERENCES dbo.Products(ProductId),
        Quantity   INT              NOT NULL CONSTRAINT CK_CartItems_Qty CHECK (Quantity BETWEEN 1 AND 99),
        AddedAtUtc DATETIME2(0)     NOT NULL CONSTRAINT DF_CartItems_Added DEFAULT SYSUTCDATETIME(),
        CONSTRAINT PK_CartItems PRIMARY KEY (CartId, ProductId)
    );
END
GO

/* ---------------------------------------------------------------------
   6. Orders and payments (US5, US8). No card data is ever stored: only the provider reference.
      Status flow: Pending -> Paid -> Shipped, or Pending -> Failed | Cancelled.
   --------------------------------------------------------------------- */
IF OBJECT_ID(N'dbo.Orders', N'U') IS NULL
BEGIN
    CREATE TABLE dbo.Orders (
        OrderId            UNIQUEIDENTIFIER NOT NULL CONSTRAINT DF_Orders_Id DEFAULT NEWID() CONSTRAINT PK_Orders PRIMARY KEY,
        UserId             UNIQUEIDENTIFIER NOT NULL CONSTRAINT FK_Orders_Users REFERENCES dbo.Users(UserId),
        Status             VARCHAR(15)      NOT NULL CONSTRAINT DF_Orders_Status DEFAULT 'Pending'
                           CONSTRAINT CK_Orders_Status CHECK (Status IN ('Pending','Paid','Shipped','Cancelled','Failed')),
        TotalAmount        DECIMAL(12,2)    NOT NULL CONSTRAINT CK_Orders_Total CHECK (TotalAmount >= 0),
        Currency           CHAR(3)          NOT NULL CONSTRAINT DF_Orders_Currency DEFAULT 'DKK',
        ShipName           NVARCHAR(100)    NOT NULL,
        ShipAddressLine    NVARCHAR(200)    NOT NULL,
        ShipPostalCode     NVARCHAR(10)     NOT NULL,
        ShipCity           NVARCHAR(100)    NOT NULL,
        ShipCountry        NVARCHAR(2)      NOT NULL CONSTRAINT DF_Orders_Country DEFAULT N'DK',
        IdempotencyKey     UNIQUEIDENTIFIER NOT NULL,   -- prevents double orders / double payment
        PaymentProviderRef NVARCHAR(100)    NULL,
        CreatedAtUtc       DATETIME2(0)     NOT NULL CONSTRAINT DF_Orders_Created DEFAULT SYSUTCDATETIME(),
        UpdatedAtUtc       DATETIME2(0)     NULL,
        PaidAtUtc          DATETIME2(0)     NULL
    );
    CREATE UNIQUE INDEX UX_Orders_Idempotency ON dbo.Orders (IdempotencyKey);
    CREATE INDEX IX_Orders_User ON dbo.Orders (UserId, CreatedAtUtc DESC);
END
GO
IF COL_LENGTH(N'dbo.Orders', N'UpdatedAtUtc') IS NULL
    ALTER TABLE dbo.Orders ADD UpdatedAtUtc DATETIME2(0) NULL;
GO
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = N'IX_Orders_StatusCreated' AND object_id = OBJECT_ID(N'dbo.Orders'))
    CREATE INDEX IX_Orders_StatusCreated ON dbo.Orders (Status, CreatedAtUtc);   -- used by the pending-order expiry
GO

IF OBJECT_ID(N'dbo.OrderItems', N'U') IS NULL
BEGIN
    CREATE TABLE dbo.OrderItems (
        OrderId      UNIQUEIDENTIFIER NOT NULL CONSTRAINT FK_OrderItems_Orders REFERENCES dbo.Orders(OrderId) ON DELETE CASCADE,
        ProductId    INT              NOT NULL CONSTRAINT FK_OrderItems_Products REFERENCES dbo.Products(ProductId),
        ProductName  NVARCHAR(150)    NOT NULL,           -- snapshot at purchase time
        UnitPrice    DECIMAL(10,2)    NOT NULL CONSTRAINT CK_OrderItems_Price CHECK (UnitPrice >= 0),   -- snapshot
        Quantity     INT              NOT NULL CONSTRAINT CK_OrderItems_Qty CHECK (Quantity BETWEEN 1 AND 99),
        CONSTRAINT PK_OrderItems PRIMARY KEY (OrderId, ProductId)
    );
END
GO

/* Webhook events from the payment provider. The primary key makes replays harmless:
   the same EventId can only be processed once. */
IF OBJECT_ID(N'dbo.PaymentEvents', N'U') IS NULL
BEGIN
    CREATE TABLE dbo.PaymentEvents (
        EventId       NVARCHAR(100)    NOT NULL CONSTRAINT PK_PaymentEvents PRIMARY KEY,
        OrderId       UNIQUEIDENTIFIER NULL CONSTRAINT FK_PaymentEvents_Orders REFERENCES dbo.Orders(OrderId),
        EventType     NVARCHAR(100)    NOT NULL,
        ReceivedAtUtc DATETIME2(0)     NOT NULL CONSTRAINT DF_PaymentEvents_At DEFAULT SYSUTCDATETIME()
    );
END
GO

/* ---------------------------------------------------------------------
   7. Audit log and security log (US9, US10). Append-only + hash chain.
      NEVER log passwords, tokens, session ids, card data or e-mail addresses.
   --------------------------------------------------------------------- */
IF OBJECT_ID(N'dbo.AuditLog', N'U') IS NULL
BEGIN
    CREATE TABLE dbo.AuditLog (
        AuditId       BIGINT IDENTITY(1,1) NOT NULL CONSTRAINT PK_AuditLog PRIMARY KEY,
        OccurredAtUtc DATETIME2(3)     NOT NULL CONSTRAINT DF_AuditLog_At DEFAULT SYSUTCDATETIME(),
        ActorUserId   UNIQUEIDENTIFIER NULL,
        Action        VARCHAR(50)      NOT NULL,   -- ProductCreated, ProductUpdated, ProductDeleted, ProductRestored, OrderViewedByAdmin, LogViewed ...
        EntityType    VARCHAR(50)      NOT NULL,
        EntityId      NVARCHAR(100)    NULL,
        OldValueJson  NVARCHAR(MAX)    NULL,
        NewValueJson  NVARCHAR(MAX)    NULL,
        IpAddress     VARCHAR(45)      NULL,
        CorrelationId UNIQUEIDENTIFIER NULL,
        PrevHash      BINARY(32)       NULL,
        RowHash       BINARY(32)       NULL
    );
    CREATE INDEX IX_AuditLog_Actor ON dbo.AuditLog (ActorUserId, OccurredAtUtc);
END
GO
IF COL_LENGTH(N'dbo.AuditLog', N'RowHash') IS NULL
    ALTER TABLE dbo.AuditLog ADD PrevHash BINARY(32) NULL, RowHash BINARY(32) NULL;
GO

IF OBJECT_ID(N'dbo.SecurityEvents', N'U') IS NULL
BEGIN
    CREATE TABLE dbo.SecurityEvents (
        EventId       BIGINT IDENTITY(1,1) NOT NULL CONSTRAINT PK_SecurityEvents PRIMARY KEY,
        OccurredAtUtc DATETIME2(3)     NOT NULL CONSTRAINT DF_SecEvents_At DEFAULT SYSUTCDATETIME(),
        EventType     VARCHAR(50)      NOT NULL,   -- LoginSuccess, LoginFailed, AccountLocked, AccessDenied, PasswordChanged ...
        Severity      VARCHAR(10)      NOT NULL CONSTRAINT CK_SecEvents_Sev CHECK (Severity IN ('Info','Warning','Error','Critical')),
        UserId        UNIQUEIDENTIFIER NULL,
        IpAddress     VARCHAR(45)      NULL,
        Resource      NVARCHAR(200)    NULL,
        Details       NVARCHAR(1000)   NULL,       -- sanitised: no control characters
        CorrelationId UNIQUEIDENTIFIER NULL,
        PrevHash      BINARY(32)       NULL,
        RowHash       BINARY(32)       NULL
    );
    CREATE INDEX IX_SecEvents_Time ON dbo.SecurityEvents (OccurredAtUtc DESC, EventType);
    CREATE INDEX IX_SecEvents_Ip   ON dbo.SecurityEvents (IpAddress, OccurredAtUtc);
END
GO
IF COL_LENGTH(N'dbo.SecurityEvents', N'RowHash') IS NULL
    ALTER TABLE dbo.SecurityEvents ADD PrevHash BINARY(32) NULL, RowHash BINARY(32) NULL;
GO

/* Remembers the hash of the last purged row so the chain remains verifiable after retention purges */
IF OBJECT_ID(N'dbo.LogAnchors', N'U') IS NULL
BEGIN
    CREATE TABLE dbo.LogAnchors (
        LogName        VARCHAR(30)  NOT NULL CONSTRAINT PK_LogAnchors PRIMARY KEY,   -- 'SecurityEvents' | 'AuditLog'
        LastPurgedId   BIGINT       NOT NULL,
        LastPurgedHash BINARY(32)   NOT NULL,
        PurgedAtUtc    DATETIME2(0) NOT NULL CONSTRAINT DF_LogAnchors_At DEFAULT SYSUTCDATETIME()
    );
END
GO

/* ---------------------------------------------------------------------
   8. Sample catalogue data (only when the catalogue is empty)
   --------------------------------------------------------------------- */
IF NOT EXISTS (SELECT 1 FROM dbo.Categories)
BEGIN
    INSERT INTO dbo.Categories (Name) VALUES (N'Elektronik'), (N'Bøger'), (N'Tøj');

    INSERT INTO dbo.Products (CategoryId, Name, Description, Price, StockQuantity)
    VALUES (1, N'Trådløse hovedtelefoner', N'Over-ear med støjreduktion.', 799.00, 25),
           (1, N'USB-C kabel 2 m',          N'Flettet kabel, 100 W.',        89.00, 200),
           (2, N'Secure Coding i praksis',  N'Introduktion til sikker udvikling.', 249.00, 40),
           (3, N'Hættetrøje',               N'100 % økologisk bomuld.',      399.00, 60);
END
GO
/* =====================================================================
   PART 2 - INTERNAL HELPERS (schema dbo)
   Not callable by the web app (DENY on schema dbo, see permissions part). They are used
   by the procedures in [app]/[admin]/[sysadmin]/[maint] through ownership chaining.
   ===================================================================== */
USE Webshop;
GO

/* Replaces control characters with spaces so one log entry can never look like several
   (log injection). Handles TAB, LF, VT, FF, CR, ESC, NEL and the Unicode line/paragraph separators. */
CREATE OR ALTER FUNCTION dbo.fn_StripControlChars (@s NVARCHAR(MAX))
RETURNS NVARCHAR(MAX)
AS
BEGIN
    RETURN TRANSLATE(@s,
        NCHAR(9) + NCHAR(10) + NCHAR(11) + NCHAR(12) + NCHAR(13) + NCHAR(27) + NCHAR(133) + NCHAR(8232) + NCHAR(8233),
        REPLICATE(N' ', 9));
END
GO

/* The hash of one log row = SHA-256(fields | previous hash). Used when writing AND when verifying,
   so the two can never drift apart. */
CREATE OR ALTER FUNCTION dbo.fn_SecurityEventHash (
    @OccurredAtUtc DATETIME2(3), @EventType VARCHAR(50), @Severity VARCHAR(10), @UserId UNIQUEIDENTIFIER,
    @IpAddress VARCHAR(45), @Resource NVARCHAR(200), @Details NVARCHAR(1000), @CorrelationId UNIQUEIDENTIFIER,
    @PrevHash BINARY(32))
RETURNS BINARY(32)
AS
BEGIN
    RETURN HASHBYTES('SHA2_256', CONCAT(
        CONVERT(VARCHAR(30), @OccurredAtUtc, 126), N'|', @EventType, N'|', @Severity, N'|',
        CONVERT(VARCHAR(36), @UserId), N'|', @IpAddress, N'|', @Resource, N'|', @Details, N'|',
        CONVERT(VARCHAR(36), @CorrelationId), N'|', CONVERT(VARCHAR(66), @PrevHash, 1)));
END
GO

CREATE OR ALTER FUNCTION dbo.fn_AuditHash (
    @OccurredAtUtc DATETIME2(3), @ActorUserId UNIQUEIDENTIFIER, @Action VARCHAR(50), @EntityType VARCHAR(50),
    @EntityId NVARCHAR(100), @OldValueJson NVARCHAR(MAX), @NewValueJson NVARCHAR(MAX), @IpAddress VARCHAR(45),
    @CorrelationId UNIQUEIDENTIFIER, @PrevHash BINARY(32))
RETURNS BINARY(32)
AS
BEGIN
    RETURN HASHBYTES('SHA2_256', CONCAT(
        CONVERT(VARCHAR(30), @OccurredAtUtc, 126), N'|', CONVERT(VARCHAR(36), @ActorUserId), N'|', @Action, N'|',
        @EntityType, N'|', @EntityId, N'|', @OldValueJson, N'|', @NewValueJson, N'|', @IpAddress, N'|',
        CONVERT(VARCHAR(36), @CorrelationId), N'|', CONVERT(VARCHAR(66), @PrevHash, 1)));
END
GO

/* Splits a blob of N x 32 bytes (max 10 hashes) into rows. Used to pass the 10 MFA backup-code
   hashes in ONE parameter without table-valued parameters. */
CREATE OR ALTER FUNCTION dbo.fn_SplitHashes (@Blob VARBINARY(320))
RETURNS TABLE
AS
RETURN
    SELECT CONVERT(BINARY(32), SUBSTRING(@Blob, v.i * 32 + 1, 32)) AS CodeHash
    FROM (VALUES (0),(1),(2),(3),(4),(5),(6),(7),(8),(9)) AS v(i)
    WHERE v.i * 32 + 1 <= DATALENGTH(@Blob);
GO

/* ---------------------------------------------------------------------
   Security log writer (hash chained). Never throws on lock timeout: the row is then written
   "unchained" (RowHash NULL) so that no event is ever lost; the verifier reports unchained rows.
   --------------------------------------------------------------------- */
CREATE OR ALTER PROCEDURE dbo.usp_Internal_LogSecurityEvent
    @EventType     VARCHAR(50),
    @Severity      VARCHAR(10),
    @UserId        UNIQUEIDENTIFIER = NULL,
    @IpAddress     VARCHAR(45)      = NULL,
    @Resource      NVARCHAR(200)    = NULL,
    @Details       NVARCHAR(1000)   = NULL,
    @CorrelationId UNIQUEIDENTIFIER = NULL
AS
BEGIN
    SET NOCOUNT ON;
    DECLARE @now DATETIME2(3) = SYSUTCDATETIME();
    DECLARE @prev BINARY(32), @hash BINARY(32), @ownTran BIT = 0, @lock INT;

    SET @Resource = CONVERT(NVARCHAR(200),  dbo.fn_StripControlChars(@Resource));
    SET @Details  = CONVERT(NVARCHAR(1000), dbo.fn_StripControlChars(@Details));

    BEGIN TRY
        IF @@TRANCOUNT = 0
        BEGIN
            BEGIN TRANSACTION;
            SET @ownTran = 1;
        END

        -- One writer at a time so PrevHash is always the true predecessor
        EXEC @lock = sys.sp_getapplock @Resource = N'log-chain:SecurityEvents', @LockMode = N'Exclusive',
                                       @LockOwner = N'Transaction', @LockTimeout = 5000;

        IF @lock >= 0
        BEGIN
            SELECT TOP (1) @prev = RowHash FROM dbo.SecurityEvents WHERE RowHash IS NOT NULL ORDER BY EventId DESC;
            IF @prev IS NULL SELECT @prev = LastPurgedHash FROM dbo.LogAnchors WHERE LogName = 'SecurityEvents';
            IF @prev IS NULL SET @prev = CONVERT(BINARY(32), REPLICATE(CAST(0x00 AS VARBINARY(1)), 32));   -- genesis

            SET @hash = dbo.fn_SecurityEventHash(@now, @EventType, @Severity, @UserId, @IpAddress, @Resource, @Details, @CorrelationId, @prev);
        END

        INSERT INTO dbo.SecurityEvents (OccurredAtUtc, EventType, Severity, UserId, IpAddress, Resource, Details, CorrelationId, PrevHash, RowHash)
        VALUES (@now, @EventType, @Severity, @UserId, @IpAddress, @Resource, @Details, @CorrelationId,
                CASE WHEN @lock >= 0 THEN @prev END, @hash);

        IF @ownTran = 1 COMMIT TRANSACTION;
    END TRY
    BEGIN CATCH
        IF @ownTran = 1 AND @@TRANCOUNT > 0 ROLLBACK TRANSACTION;
        THROW;
    END CATCH
END
GO

/* Audit log writer (who / what / when / before / after). Same chaining as above. */
CREATE OR ALTER PROCEDURE dbo.usp_Internal_LogAudit
    @ActorUserId   UNIQUEIDENTIFIER = NULL,
    @Action        VARCHAR(50),
    @EntityType    VARCHAR(50),
    @EntityId      NVARCHAR(100)    = NULL,
    @OldValueJson  NVARCHAR(MAX)    = NULL,
    @NewValueJson  NVARCHAR(MAX)    = NULL,
    @IpAddress     VARCHAR(45)      = NULL,
    @CorrelationId UNIQUEIDENTIFIER = NULL
AS
BEGIN
    SET NOCOUNT ON;
    DECLARE @now DATETIME2(3) = SYSUTCDATETIME();
    DECLARE @prev BINARY(32), @hash BINARY(32), @ownTran BIT = 0, @lock INT;

    BEGIN TRY
        IF @@TRANCOUNT = 0
        BEGIN
            BEGIN TRANSACTION;
            SET @ownTran = 1;
        END

        EXEC @lock = sys.sp_getapplock @Resource = N'log-chain:AuditLog', @LockMode = N'Exclusive',
                                       @LockOwner = N'Transaction', @LockTimeout = 5000;
        IF @lock < 0
            THROW 50500, N'Audit log chain busy', 1;      -- audit entries are mandatory: fail closed, never skip

        SELECT TOP (1) @prev = RowHash FROM dbo.AuditLog WHERE RowHash IS NOT NULL ORDER BY AuditId DESC;
        IF @prev IS NULL SELECT @prev = LastPurgedHash FROM dbo.LogAnchors WHERE LogName = 'AuditLog';
        IF @prev IS NULL SET @prev = CONVERT(BINARY(32), REPLICATE(CAST(0x00 AS VARBINARY(1)), 32));

        SET @hash = dbo.fn_AuditHash(@now, @ActorUserId, @Action, @EntityType, @EntityId, @OldValueJson, @NewValueJson, @IpAddress, @CorrelationId, @prev);

        INSERT INTO dbo.AuditLog (OccurredAtUtc, ActorUserId, Action, EntityType, EntityId, OldValueJson, NewValueJson, IpAddress, CorrelationId, PrevHash, RowHash)
        VALUES (@now, @ActorUserId, @Action, @EntityType, @EntityId, @OldValueJson, @NewValueJson, @IpAddress, @CorrelationId, @prev, @hash);

        IF @ownTran = 1 COMMIT TRANSACTION;
    END TRY
    BEGIN CATCH
        IF @ownTran = 1 AND @@TRANCOUNT > 0 ROLLBACK TRANSACTION;
        THROW;
    END CATCH
END
GO

/* ---------------------------------------------------------------------
   THE AUTHORISATION GATE. Call it FIRST in every procedure that needs an identity, and BEFORE
   BEGIN TRAN (the AccessDenied entry must survive, and the THROW must not doom a transaction).

     @AllowedRoles          constant list such as '2' or '1,2' (NULL = any logged-in user)
     @RequireEmailConfirmed 1 = reject unconfirmed accounts (checkout)
     @MaxReauthAgeMinutes   NOT NULL = the user must have re-authenticated within that many
                            minutes (delete product, disable MFA, delete account)
   Outputs the acting @UserId and @RoleId taken from the session.
   Throws 50401 / 50403 / 50402 (see header).
   --------------------------------------------------------------------- */
CREATE OR ALTER PROCEDURE dbo.usp_Internal_ResolveSession
    @SessionIdHash         BINARY(32),
    @AllowedRoles          VARCHAR(20)  = NULL,
    @Resource              NVARCHAR(200),
    @RequireEmailConfirmed BIT          = 0,
    @MaxReauthAgeMinutes   INT          = NULL,
    @IpAddress             VARCHAR(45)  = NULL,
    @UserId                UNIQUEIDENTIFIER OUTPUT,
    @RoleId                TINYINT          OUTPUT
AS
BEGIN
    SET NOCOUNT ON;
    DECLARE @now DATETIME2(0) = SYSUTCDATETIME();
    DECLARE @emailConfirmed BIT, @reauth DATETIME2(0);

    SET @UserId = NULL;
    SET @RoleId = NULL;

    SELECT @UserId = u.UserId, @RoleId = u.RoleId, @emailConfirmed = u.EmailConfirmed,
           @reauth = COALESCE(s.ReauthAtUtc, s.CreatedAtUtc)
    FROM dbo.Sessions s
    JOIN dbo.Users u ON u.UserId = s.UserId
    WHERE s.SessionIdHash = @SessionIdHash
      AND s.RevokedAtUtc IS NULL
      AND s.AbsoluteExpiryUtc > @now
      AND s.LastSeenAtUtc > DATEADD(MINUTE, -(CASE WHEN u.RoleId >= 2 THEN 10 ELSE 20 END), @now)   -- shorter idle timeout for privileged roles
      AND u.IsDeleted = 0;

    IF @UserId IS NULL
    BEGIN
        EXEC dbo.usp_Internal_LogSecurityEvent @EventType = 'AccessDenied', @Severity = 'Warning', @UserId = NULL,
             @IpAddress = @IpAddress, @Resource = @Resource, @Details = N'invalid-session';
        THROW 50401, N'Unauthenticated', 1;
    END

    IF @AllowedRoles IS NOT NULL
       AND NOT EXISTS (SELECT 1 FROM STRING_SPLIT(@AllowedRoles, ',') WHERE TRY_CAST([value] AS TINYINT) = @RoleId)
    BEGIN
        EXEC dbo.usp_Internal_LogSecurityEvent @EventType = 'AccessDenied', @Severity = 'Warning', @UserId = @UserId,
             @IpAddress = @IpAddress, @Resource = @Resource, @Details = N'role-not-allowed';
        THROW 50403, N'Forbidden', 1;      -- generic: reveals neither which role is required nor whether the resource exists
    END

    IF @RequireEmailConfirmed = 1 AND @emailConfirmed = 0
    BEGIN
        EXEC dbo.usp_Internal_LogSecurityEvent @EventType = 'AccessDenied', @Severity = 'Info', @UserId = @UserId,
             @IpAddress = @IpAddress, @Resource = @Resource, @Details = N'email-not-confirmed';
        THROW 50403, N'EmailNotConfirmed', 1;
    END

    IF @MaxReauthAgeMinutes IS NOT NULL AND @reauth < DATEADD(MINUTE, -@MaxReauthAgeMinutes, @now)
        THROW 50402, N'ReauthRequired', 1;
END
GO

/* ---------------------------------------------------------------------
   Cart owner resolution (US4). Signed-in users: the cart is found through the SESSION.
   Anonymous visitors: through the hash of their random cart cookie. If both are supplied the
   session wins. The caller can never name a cart id, so cart IDOR is impossible.
   Call before BEGIN TRAN (a duplicate-key race is handled with TRY/CATCH + re-select).
   --------------------------------------------------------------------- */
CREATE OR ALTER PROCEDURE dbo.usp_Internal_GetCart
    @SessionIdHash BINARY(32) = NULL,
    @AnonKeyHash   BINARY(32) = NULL,
    @Create        BIT,
    @Resource      NVARCHAR(200),
    @IpAddress     VARCHAR(45) = NULL,
    @CartId        UNIQUEIDENTIFIER OUTPUT,
    @UserId        UNIQUEIDENTIFIER OUTPUT
AS
BEGIN
    SET NOCOUNT ON;
    DECLARE @role TINYINT;
    SET @CartId = NULL;
    SET @UserId = NULL;

    IF @SessionIdHash IS NOT NULL
        EXEC dbo.usp_Internal_ResolveSession @SessionIdHash = @SessionIdHash, @AllowedRoles = NULL, @Resource = @Resource,
             @IpAddress = @IpAddress, @UserId = @UserId OUTPUT, @RoleId = @role OUTPUT;
    ELSE IF @AnonKeyHash IS NULL
        THROW 50401, N'Unauthenticated', 1;

    IF @UserId IS NOT NULL
        SELECT @CartId = CartId FROM dbo.Carts WHERE UserId = @UserId;
    ELSE
        SELECT @CartId = CartId FROM dbo.Carts WHERE AnonymousKeyHash = @AnonKeyHash;

    IF @CartId IS NULL AND @Create = 1
    BEGIN
        BEGIN TRY
            SET @CartId = NEWID();
            INSERT INTO dbo.Carts (CartId, UserId, AnonymousKeyHash)
            VALUES (@CartId, @UserId, CASE WHEN @UserId IS NULL THEN @AnonKeyHash END);
        END TRY
        BEGIN CATCH
            IF ERROR_NUMBER() NOT IN (2601, 2627) THROW;
            -- A parallel request created the cart first: use that one
            IF @UserId IS NOT NULL SELECT @CartId = CartId FROM dbo.Carts WHERE UserId = @UserId;
            ELSE SELECT @CartId = CartId FROM dbo.Carts WHERE AnonymousKeyHash = @AnonKeyHash;
        END CATCH
    END
END
GO

/* ---------------------------------------------------------------------
   Orders: give stock back (US5). Only a Pending order can be released, and only once,
   because the status change is the guard: UPDATE ... WHERE Status='Pending'.
   Must run inside the caller's transaction.
   --------------------------------------------------------------------- */
CREATE OR ALTER PROCEDURE dbo.usp_Internal_ReleaseOrder
    @OrderId   UNIQUEIDENTIFIER,
    @NewStatus VARCHAR(15),             -- 'Failed' or 'Cancelled'
    @Released  BIT OUTPUT
AS
BEGIN
    SET NOCOUNT ON;
    SET @Released = 0;

    UPDATE dbo.Orders SET Status = @NewStatus, UpdatedAtUtc = SYSUTCDATETIME()
    WHERE OrderId = @OrderId AND Status = 'Pending';

    IF @@ROWCOUNT = 1
    BEGIN
        UPDATE p
        SET p.StockQuantity = CASE WHEN p.StockQuantity + oi.Quantity > 100000 THEN 100000 ELSE p.StockQuantity + oi.Quantity END,
            p.UpdatedAtUtc  = SYSUTCDATETIME()
        FROM dbo.Products p
        JOIN dbo.OrderItems oi ON oi.ProductId = p.ProductId
        WHERE oi.OrderId = @OrderId;
        SET @Released = 1;
    END
END
GO

/* Unpaid orders older than @MaxAgeMinutes are cancelled and their stock released.
   Called lazily from usp_Order_Create (so stock is correct without a scheduled job) and from maint.usp_Purge_All. */
CREATE OR ALTER PROCEDURE dbo.usp_Internal_ExpirePendingOrders
    @MaxAgeMinutes INT = 60
AS
BEGIN
    SET NOCOUNT ON;
    DECLARE @expired TABLE (OrderId UNIQUEIDENTIFIER PRIMARY KEY);
    DECLARE @own BIT = 0;

    BEGIN TRY
        IF @@TRANCOUNT = 0
        BEGIN
            BEGIN TRANSACTION;
            SET @own = 1;
        END

        UPDATE o
        SET o.Status = 'Cancelled', o.UpdatedAtUtc = SYSUTCDATETIME()
        OUTPUT inserted.OrderId INTO @expired (OrderId)
        FROM dbo.Orders o
        WHERE o.Status = 'Pending' AND o.CreatedAtUtc < DATEADD(MINUTE, -@MaxAgeMinutes, SYSUTCDATETIME());

        IF EXISTS (SELECT 1 FROM @expired)
            UPDATE p
            SET p.StockQuantity = CASE WHEN p.StockQuantity + x.Qty > 100000 THEN 100000 ELSE p.StockQuantity + x.Qty END,
                p.UpdatedAtUtc  = SYSUTCDATETIME()
            FROM dbo.Products p
            JOIN (SELECT oi.ProductId, SUM(oi.Quantity) AS Qty
                  FROM dbo.OrderItems oi JOIN @expired e ON e.OrderId = oi.OrderId
                  GROUP BY oi.ProductId) x ON x.ProductId = p.ProductId;

        DECLARE @n INT = (SELECT COUNT(*) FROM @expired);
        IF @own = 1 COMMIT TRANSACTION;
        RETURN @n;      -- number of orders released (used by maint.usp_Purge_All)
    END TRY
    BEGIN CATCH
        IF @own = 1 AND @@TRANCOUNT > 0 ROLLBACK TRANSACTION;
        THROW;
    END CATCH
END
GO

/* ---------------------------------------------------------------------
   Role changes are only possible for a DBA, and they are always logged (US10):
   "Change a role and check that the event is logged with who and when."
   ORIGINAL_LOGIN() = the real login even when impersonation is used.
   --------------------------------------------------------------------- */
CREATE OR ALTER TRIGGER dbo.trg_Users_RoleChange
ON dbo.Users
AFTER UPDATE
AS
BEGIN
    SET NOCOUNT ON;
    IF NOT UPDATE(RoleId) RETURN;

    DECLARE @id UNIQUEIDENTIFIER, @old TINYINT, @new TINYINT, @details NVARCHAR(1000);
    DECLARE @idText NVARCHAR(100), @oldText NVARCHAR(10), @newText NVARCHAR(10);
    DECLARE c CURSOR LOCAL FAST_FORWARD FOR
        SELECT i.UserId, d.RoleId, i.RoleId FROM inserted i JOIN deleted d ON d.UserId = i.UserId WHERE i.RoleId <> d.RoleId;
    OPEN c;
    FETCH NEXT FROM c INTO @id, @old, @new;
    WHILE @@FETCH_STATUS = 0
    BEGIN
        SET @details = CONCAT(N'role ', @old, N' -> ', @new, N' by ', ORIGINAL_LOGIN());
        SET @idText  = CONVERT(NVARCHAR(100), @id);
        SET @oldText = CONVERT(NVARCHAR(10), @old);
        SET @newText = CONVERT(NVARCHAR(10), @new);
        EXEC dbo.usp_Internal_LogSecurityEvent @EventType = 'RoleChanged', @Severity = 'Critical', @UserId = @id,
             @Resource = N'dbo.Users', @Details = @details;
        EXEC dbo.usp_Internal_LogAudit @ActorUserId = NULL, @Action = 'RoleChanged', @EntityType = 'User',
             @EntityId = @idText, @OldValueJson = @oldText, @NewValueJson = @newText;
        FETCH NEXT FROM c INTO @id, @old, @new;
    END
    CLOSE c;
    DEALLOCATE c;
END
GO
/* =====================================================================
   PART 3 - SCHEMA [app]: PUBLIC AND CUSTOMER PROCEDURES
   Conventions used by every procedure below:
     * First lines: SET NOCOUNT ON; (and SET XACT_ABORT ON when a transaction is used).
     * Identity ALWAYS comes from @SessionIdHash via dbo.usp_Internal_ResolveSession.
     * The resolver is called BEFORE BEGIN TRAN.
     * No dynamic SQL (it would break ownership chaining).
     * "Returns:" documents the result set so the C# mapper can be written without guessing.
   ===================================================================== */
USE Webshop;
GO

/* ---------------------------------------------------------------------
   US1 - Create account
   Role (Customer) and EmailConfirmed (0) come from table defaults, so the application can never set them.
   The e-mail is normalised again here (defence in depth; the app normalises first).
   Returns: nothing. OUTPUT @Created = 1 when the account was created, 0 for a duplicate e-mail.
   The caller must answer identically in both cases (anti-enumeration).
   --------------------------------------------------------------------- */
CREATE OR ALTER PROCEDURE app.usp_User_Register
    @Email                 NVARCHAR(254),
    @DisplayName           NVARCHAR(100),
    @PasswordHash          NVARCHAR(255),
    @PrivacyConsentVersion NVARCHAR(20),
    @ConfirmTokenHash      BINARY(32),
    @IpAddress             VARCHAR(45) = NULL,
    @Created               BIT OUTPUT
AS
BEGIN
    SET NOCOUNT ON;
    SET XACT_ABORT ON;
    SET @Created = 0;
    SET @Email = LOWER(LTRIM(RTRIM(@Email)));

    DECLARE @UserId UNIQUEIDENTIFIER;
    DECLARE @new TABLE (UserId UNIQUEIDENTIFIER);

    BEGIN TRY
        BEGIN TRANSACTION;

        IF EXISTS (SELECT 1 FROM dbo.Users WHERE Email = @Email)
        BEGIN
            EXEC dbo.usp_Internal_LogSecurityEvent @EventType = 'RegistrationDuplicate', @Severity = 'Info',
                 @IpAddress = @IpAddress, @Resource = N'/Register', @Details = N'E-mail already registered';
            COMMIT TRANSACTION;
            RETURN;
        END

        INSERT dbo.Users (Email, DisplayName, PasswordHash, PrivacyConsentVersion, PrivacyConsentAtUtc)
        OUTPUT inserted.UserId INTO @new
        VALUES (@Email, @DisplayName, @PasswordHash, @PrivacyConsentVersion, SYSUTCDATETIME());

        SELECT @UserId = UserId FROM @new;

        INSERT dbo.UserTokens (UserId, Purpose, TokenHash, ExpiresAtUtc)
        VALUES (@UserId, 'EmailConfirm', @ConfirmTokenHash, DATEADD(HOUR, 24, SYSUTCDATETIME()));

        -- Registration + privacy consent (version and time are also stored on the user row)
        EXEC dbo.usp_Internal_LogSecurityEvent @EventType = 'AccountCreated', @Severity = 'Info', @UserId = @UserId,
             @IpAddress = @IpAddress, @Resource = N'/Register',
             @Details = @PrivacyConsentVersion;      -- consent version accepted

        COMMIT TRANSACTION;
        SET @Created = 1;
    END TRY
    BEGIN CATCH
        IF @@TRANCOUNT > 0 ROLLBACK TRANSACTION;
        -- Race: two simultaneous registrations with the same e-mail. The unique index wins; treat as duplicate.
        IF ERROR_NUMBER() IN (2601, 2627)
        BEGIN
            SET @Created = 0;
            RETURN;
        END;
        THROW;
    END CATCH
END
GO

/* US1 - Confirm e-mail. The token can be used once and only before it expires (atomic UPDATE).
   Returns: nothing. OUTPUT @Confirmed. */
CREATE OR ALTER PROCEDURE app.usp_User_ConfirmEmail
    @TokenHash BINARY(32),
    @IpAddress VARCHAR(45) = NULL,
    @Confirmed BIT OUTPUT
AS
BEGIN
    SET NOCOUNT ON;
    SET XACT_ABORT ON;
    SET @Confirmed = 0;

    DECLARE @UserId UNIQUEIDENTIFIER;

    BEGIN TRANSACTION;

    UPDATE dbo.UserTokens
       SET UsedAtUtc = SYSUTCDATETIME(),
           @UserId   = UserId
     WHERE TokenHash    = @TokenHash
       AND Purpose      = 'EmailConfirm'
       AND UsedAtUtc    IS NULL
       AND ExpiresAtUtc > SYSUTCDATETIME();

    IF @UserId IS NOT NULL
    BEGIN
        UPDATE dbo.Users SET EmailConfirmed = 1 WHERE UserId = @UserId AND IsDeleted = 0;
        EXEC dbo.usp_Internal_LogSecurityEvent @EventType = 'EmailConfirmed', @Severity = 'Info', @UserId = @UserId,
             @IpAddress = @IpAddress, @Resource = N'/ConfirmEmail';
        SET @Confirmed = 1;
    END
    ELSE
    BEGIN
        EXEC dbo.usp_Internal_LogSecurityEvent @EventType = 'EmailConfirmFailed', @Severity = 'Warning',
             @IpAddress = @IpAddress, @Resource = N'/ConfirmEmail', @Details = N'Invalid, used or expired token';
    END

    COMMIT TRANSACTION;
END
GO

/* ---------------------------------------------------------------------
   US2 - Login lookups
   These run BEFORE a session exists, so they cannot use the session gate. They only return what the
   login flow needs for a given e-mail / user id.
   --------------------------------------------------------------------- */
-- Returns: UserId, PasswordHash, RoleId, EmailConfirmed, MfaEnabled, LockoutEndUtc  (0 or 1 row)
CREATE OR ALTER PROCEDURE app.usp_Login_GetCredentials
    @Email NVARCHAR(254)
AS
BEGIN
    SET NOCOUNT ON;
    SELECT UserId, PasswordHash, RoleId, EmailConfirmed, MfaEnabled, LockoutEndUtc
    FROM dbo.Users
    WHERE Email = @Email AND IsDeleted = 0;
END
GO

-- Returns: UserId, RoleId, MfaEnabled, MfaSecretEncrypted, LockoutEndUtc  (0 or 1 row)
CREATE OR ALTER PROCEDURE app.usp_Login_GetMfaData
    @UserId UNIQUEIDENTIFIER
AS
BEGIN
    SET NOCOUNT ON;
    SELECT UserId, RoleId, MfaEnabled, MfaSecretEncrypted, LockoutEndUtc
    FROM dbo.Users
    WHERE UserId = @UserId AND IsDeleted = 0;
END
GO

-- Failed attempts inside the window, per e-mail hash and per IP. Identical for known/unknown e-mails.
-- Returns: FailedByEmail, FailedByIp  (1 row)
CREATE OR ALTER PROCEDURE app.usp_Login_GetThrottle
    @EmailHash     BINARY(32),
    @IpAddress     VARCHAR(45),
    @WindowMinutes INT = 15
AS
BEGIN
    SET NOCOUNT ON;
    DECLARE @since DATETIME2(0) = DATEADD(MINUTE, -@WindowMinutes, SYSUTCDATETIME());
    SELECT
        (SELECT COUNT(*) FROM dbo.LoginAttempts WHERE EmailHash = @EmailHash AND Succeeded = 0 AND AttemptedAtUtc >= @since) AS FailedByEmail,
        (SELECT COUNT(*) FROM dbo.LoginAttempts WHERE IpAddress = @IpAddress AND Succeeded = 0 AND AttemptedAtUtc >= @since) AS FailedByIp;
END
GO

/* Records an attempt and applies the lockout.
   - Success resets the counter and the lock.
   - 5 failures within 15 minutes lock the account for 15 minutes. Progressive delay: if there were
     >= 10 failures in the last 24 h the lock is 30 min, >= 15 failures: 60 min.
   - The lock is always temporary (a permanent lock would let an attacker lock out other people = DoS).
   Returns: AccountLocked (1 row) = 1 when THIS attempt caused a lock. */
CREATE OR ALTER PROCEDURE app.usp_Login_RecordAttempt
    @EmailHash BINARY(32) = NULL,
    @IpAddress VARCHAR(45),
    @Succeeded BIT,
    @UserId    UNIQUEIDENTIFIER = NULL
AS
BEGIN
    SET NOCOUNT ON;
    DECLARE @now DATETIME2(0) = SYSUTCDATETIME();
    DECLARE @locked BIT = 0, @recent INT = 0, @day INT = 0, @minutes INT;

    INSERT INTO dbo.LoginAttempts (EmailHash, IpAddress, Succeeded, AttemptedAtUtc)
    VALUES (@EmailHash, @IpAddress, @Succeeded, @now);

    IF @UserId IS NOT NULL
    BEGIN
        IF @Succeeded = 1
        BEGIN
            UPDATE dbo.Users SET FailedLoginCount = 0, LockoutEndUtc = NULL WHERE UserId = @UserId;
        END
        ELSE
        BEGIN
            UPDATE dbo.Users SET FailedLoginCount = FailedLoginCount + 1 WHERE UserId = @UserId;

            IF @EmailHash IS NOT NULL
                SELECT @recent = ISNULL(SUM(CASE WHEN AttemptedAtUtc >= DATEADD(MINUTE, -15, @now) THEN 1 ELSE 0 END), 0),
                       @day    = COUNT(*)
                FROM dbo.LoginAttempts
                WHERE EmailHash = @EmailHash AND Succeeded = 0 AND AttemptedAtUtc >= DATEADD(HOUR, -24, @now);

            IF @recent >= 5
            BEGIN
                SET @minutes = 15 * CASE WHEN @day >= 15 THEN 4 WHEN @day >= 10 THEN 2 ELSE 1 END;
                UPDATE dbo.Users SET LockoutEndUtc = DATEADD(MINUTE, @minutes, @now) WHERE UserId = @UserId;
                SET @locked = 1;
            END
        END
    END

    SELECT @locked AS AccountLocked;
END
GO

/* Password hash parameter upgrade ("needs rehash"): compare-and-swap, only succeeds if the stored hash
   is still @OldHash. Returns: Updated (1 row). */
CREATE OR ALTER PROCEDURE app.usp_Password_Rehash
    @UserId  UNIQUEIDENTIFIER,
    @OldHash NVARCHAR(255),
    @NewHash NVARCHAR(255)
AS
BEGIN
    SET NOCOUNT ON;
    UPDATE dbo.Users SET PasswordHash = @NewHash WHERE UserId = @UserId AND PasswordHash = @OldHash AND IsDeleted = 0;
    SELECT CASE WHEN @@ROWCOUNT = 1 THEN 1 ELSE 0 END AS Updated;
END
GO

/* ---------------------------------------------------------------------
   US2 - MFA during login
   --------------------------------------------------------------------- */
-- A TOTP step can be used once (ASVS 2.8.4). Returns: Consumed (1 row)
CREATE OR ALTER PROCEDURE app.usp_Mfa_TryAdvanceStep
    @UserId UNIQUEIDENTIFIER,
    @Step   BIGINT
AS
BEGIN
    SET NOCOUNT ON;
    UPDATE dbo.Users SET MfaLastUsedStep = @Step
    WHERE UserId = @UserId AND (MfaLastUsedStep IS NULL OR MfaLastUsedStep < @Step);
    SELECT CASE WHEN @@ROWCOUNT = 1 THEN 1 ELSE 0 END AS Consumed;
END
GO

-- Atomic single use of a backup code. Returns: Consumed (1 row)
CREATE OR ALTER PROCEDURE app.usp_Mfa_ConsumeBackupCode
    @UserId   UNIQUEIDENTIFIER,
    @CodeHash BINARY(32)
AS
BEGIN
    SET NOCOUNT ON;
    UPDATE TOP (1) dbo.MfaBackupCodes SET UsedAtUtc = SYSUTCDATETIME()
    WHERE UserId = @UserId AND CodeHash = @CodeHash AND UsedAtUtc IS NULL;
    SELECT CASE WHEN @@ROWCOUNT = 1 THEN 1 ELSE 0 END AS Consumed;
END
GO

/* ---------------------------------------------------------------------
   US2 - Server-side sessions
   --------------------------------------------------------------------- */
CREATE OR ALTER PROCEDURE app.usp_Session_Create
    @SessionIdHash BINARY(32),
    @UserId        UNIQUEIDENTIFIER,
    @AbsoluteHours INT = 8,
    @IpAddress     VARCHAR(45)   = NULL,
    @UserAgent     NVARCHAR(300) = NULL
AS
BEGIN
    SET NOCOUNT ON;
    DECLARE @now DATETIME2(0) = SYSUTCDATETIME();
    INSERT INTO dbo.Sessions (SessionIdHash, UserId, CreatedAtUtc, LastSeenAtUtc, AbsoluteExpiryUtc, IpAddress, UserAgent, ReauthAtUtc)
    VALUES (@SessionIdHash, @UserId, @now, @now, DATEADD(HOUR, @AbsoluteHours, @now), @IpAddress, @UserAgent, @now);
END
GO

/* Called by the authentication handler on every request: validates the session and slides the idle window.
   Idle timeout: 10 min for Admin/SysAdmin, 20 min for customers. Absolute lifetime is set at creation.
   Returns: UserId, RoleId, DisplayName, EmailConfirmed  (0 rows = not authenticated) */
CREATE OR ALTER PROCEDURE app.usp_Session_Validate
    @SessionIdHash BINARY(32)
AS
BEGIN
    SET NOCOUNT ON;
    DECLARE @now DATETIME2(0) = SYSUTCDATETIME();

    UPDATE s SET LastSeenAtUtc = @now
    FROM dbo.Sessions s
    JOIN dbo.Users u ON u.UserId = s.UserId
    WHERE s.SessionIdHash = @SessionIdHash
      AND s.RevokedAtUtc IS NULL
      AND s.AbsoluteExpiryUtc > @now
      AND s.LastSeenAtUtc > DATEADD(MINUTE, -(CASE WHEN u.RoleId >= 2 THEN 10 ELSE 20 END), @now)
      AND u.IsDeleted = 0;

    IF @@ROWCOUNT = 1
        SELECT u.UserId, u.RoleId, u.DisplayName, u.EmailConfirmed
        FROM dbo.Sessions s
        JOIN dbo.Users u ON u.UserId = s.UserId
        WHERE s.SessionIdHash = @SessionIdHash;
END
GO

CREATE OR ALTER PROCEDURE app.usp_Session_Revoke
    @SessionIdHash BINARY(32)
AS
BEGIN
    SET NOCOUNT ON;
    UPDATE dbo.Sessions SET RevokedAtUtc = SYSUTCDATETIME()
    WHERE SessionIdHash = @SessionIdHash AND RevokedAtUtc IS NULL;
END
GO

/* Call ONLY after the application has verified the user's password (and MFA code, if enabled) again.
   Sensitive procedures (product delete, MFA disable, account delete) demand a recent re-authentication. */
CREATE OR ALTER PROCEDURE app.usp_Session_MarkReauth
    @SessionIdHash BINARY(32),
    @IpAddress     VARCHAR(45) = NULL
AS
BEGIN
    SET NOCOUNT ON;
    DECLARE @u UNIQUEIDENTIFIER, @r TINYINT;
    EXEC dbo.usp_Internal_ResolveSession @SessionIdHash = @SessionIdHash, @AllowedRoles = NULL,
         @Resource = N'app.usp_Session_MarkReauth', @IpAddress = @IpAddress, @UserId = @u OUTPUT, @RoleId = @r OUTPUT;

    UPDATE dbo.Sessions SET ReauthAtUtc = SYSUTCDATETIME() WHERE SessionIdHash = @SessionIdHash;
    EXEC dbo.usp_Internal_LogSecurityEvent @EventType = 'Reauthenticated', @Severity = 'Info', @UserId = @u,
         @IpAddress = @IpAddress, @Resource = N'/Account/Reauth';
END
GO

/* "Login from a new device" notification (US2 stretch goal). Call right after the session was created.
   DeviceHash = SHA-256(User-Agent). Send the mail only when IsNew = 1 AND HadPreviousDevices = 1
   (the very first login of an account is not "new").
   Returns: IsNew, HadPreviousDevices, Email, DisplayName (1 row) */
CREATE OR ALTER PROCEDURE app.usp_Login_RegisterDevice
    @SessionIdHash BINARY(32),
    @DeviceHash    BINARY(32)
AS
BEGIN
    SET NOCOUNT ON;
    DECLARE @u UNIQUEIDENTIFIER, @r TINYINT, @isNew BIT = 0, @had BIT = 0;
    EXEC dbo.usp_Internal_ResolveSession @SessionIdHash = @SessionIdHash, @AllowedRoles = NULL,
         @Resource = N'app.usp_Login_RegisterDevice', @UserId = @u OUTPUT, @RoleId = @r OUTPUT;

    IF EXISTS (SELECT 1 FROM dbo.KnownDevices WHERE UserId = @u) SET @had = 1;

    UPDATE dbo.KnownDevices SET LastSeenUtc = SYSUTCDATETIME() WHERE UserId = @u AND DeviceHash = @DeviceHash;
    IF @@ROWCOUNT = 0
    BEGIN
        BEGIN TRY
            INSERT dbo.KnownDevices (UserId, DeviceHash) VALUES (@u, @DeviceHash);
            SET @isNew = 1;
        END TRY
        BEGIN CATCH
            IF ERROR_NUMBER() NOT IN (2601, 2627) THROW;
        END CATCH
    END

    SELECT @isNew AS IsNew, @had AS HadPreviousDevices, Email, DisplayName FROM dbo.Users WHERE UserId = @u;
END
GO

/* Generic security-event writer for events that only the application can see
   (validation failures, 401/403 at the web layer, payment webhook problems ...).
   Free text is sanitised by the helper. Do not pass passwords, tokens, session ids or card data. */
CREATE OR ALTER PROCEDURE app.usp_SecurityEvent_Log
    @EventType     VARCHAR(50),
    @Severity      VARCHAR(10),
    @UserId        UNIQUEIDENTIFIER = NULL,
    @IpAddress     VARCHAR(45)      = NULL,
    @Resource      NVARCHAR(200)    = NULL,
    @Details       NVARCHAR(1000)   = NULL,
    @CorrelationId UNIQUEIDENTIFIER = NULL
AS
BEGIN
    SET NOCOUNT ON;
    EXEC dbo.usp_Internal_LogSecurityEvent @EventType = @EventType, @Severity = @Severity, @UserId = @UserId,
         @IpAddress = @IpAddress, @Resource = @Resource, @Details = @Details, @CorrelationId = @CorrelationId;
END
GO

/* ---------------------------------------------------------------------
   MFA enrolment (US2: optional for customers, mandatory for Admin/SysAdmin).
   Flow: BeginEnroll (store encrypted secret, MFA still off) -> app shows QR code ->
         user types a code -> app verifies it -> Activate (turns MFA on + stores 10 hashed backup codes).
   --------------------------------------------------------------------- */
-- Returns: Started (1 row). 0 if MFA is already enabled.
CREATE OR ALTER PROCEDURE app.usp_Mfa_BeginEnroll
    @SessionIdHash   BINARY(32),
    @SecretEncrypted VARBINARY(512),
    @IpAddress       VARCHAR(45) = NULL
AS
BEGIN
    SET NOCOUNT ON;
    DECLARE @u UNIQUEIDENTIFIER, @r TINYINT, @rows INT;
    EXEC dbo.usp_Internal_ResolveSession @SessionIdHash = @SessionIdHash, @AllowedRoles = NULL,
         @Resource = N'app.usp_Mfa_BeginEnroll', @IpAddress = @IpAddress, @UserId = @u OUTPUT, @RoleId = @r OUTPUT;

    UPDATE dbo.Users SET MfaSecretEncrypted = @SecretEncrypted WHERE UserId = @u AND MfaEnabled = 0;
    SET @rows = @@ROWCOUNT;
    SELECT CASE WHEN @rows = 1 THEN 1 ELSE 0 END AS Started;
END
GO

-- The (encrypted) secret of the signed-in user, so the app can verify the enrolment code.
-- Returns: MfaEnabled, SecretEncrypted (1 row)
CREATE OR ALTER PROCEDURE app.usp_Mfa_GetSecret
    @SessionIdHash BINARY(32),
    @IpAddress     VARCHAR(45) = NULL
AS
BEGIN
    SET NOCOUNT ON;
    DECLARE @u UNIQUEIDENTIFIER, @r TINYINT;
    EXEC dbo.usp_Internal_ResolveSession @SessionIdHash = @SessionIdHash, @AllowedRoles = NULL,
         @Resource = N'app.usp_Mfa_GetSecret', @IpAddress = @IpAddress, @UserId = @u OUTPUT, @RoleId = @r OUTPUT;
    SELECT MfaEnabled, MfaSecretEncrypted AS SecretEncrypted FROM dbo.Users WHERE UserId = @u;
END
GO

-- @BackupCodeHashes = N x 32 bytes (1..10 SHA-256 hashes concatenated). Returns: Activated (1 row)
CREATE OR ALTER PROCEDURE app.usp_Mfa_Activate
    @SessionIdHash    BINARY(32),
    @Step             BIGINT,
    @BackupCodeHashes VARBINARY(320),
    @IpAddress        VARCHAR(45) = NULL
AS
BEGIN
    SET NOCOUNT ON;
    SET XACT_ABORT ON;
    DECLARE @u UNIQUEIDENTIFIER, @r TINYINT, @rows INT;
    EXEC dbo.usp_Internal_ResolveSession @SessionIdHash = @SessionIdHash, @AllowedRoles = NULL,
         @Resource = N'app.usp_Mfa_Activate', @IpAddress = @IpAddress, @UserId = @u OUTPUT, @RoleId = @r OUTPUT;

    IF @BackupCodeHashes IS NULL OR DATALENGTH(@BackupCodeHashes) = 0 OR DATALENGTH(@BackupCodeHashes) % 32 <> 0
        THROW 50400, N'Invalid backup code list', 1;

    BEGIN TRANSACTION;

    UPDATE dbo.Users SET MfaEnabled = 1, MfaLastUsedStep = @Step
    WHERE UserId = @u AND MfaEnabled = 0 AND MfaSecretEncrypted IS NOT NULL;
    SET @rows = @@ROWCOUNT;

    IF @rows = 1
    BEGIN
        DELETE FROM dbo.MfaBackupCodes WHERE UserId = @u;
        INSERT dbo.MfaBackupCodes (UserId, CodeHash) SELECT @u, CodeHash FROM dbo.fn_SplitHashes(@BackupCodeHashes);
        EXEC dbo.usp_Internal_LogSecurityEvent @EventType = 'MfaEnabled', @Severity = 'Info', @UserId = @u,
             @IpAddress = @IpAddress, @Resource = N'/Account/MfaSetup';
    END

    COMMIT TRANSACTION;
    SELECT CASE WHEN @rows = 1 THEN 1 ELSE 0 END AS Activated;
END
GO

-- Customers only (Admin/SysAdmin must keep MFA) and only after a recent re-authentication. Returns: Disabled (1 row)
CREATE OR ALTER PROCEDURE app.usp_Mfa_Disable
    @SessionIdHash BINARY(32),
    @IpAddress     VARCHAR(45) = NULL
AS
BEGIN
    SET NOCOUNT ON;
    SET XACT_ABORT ON;
    DECLARE @u UNIQUEIDENTIFIER, @r TINYINT, @rows INT;
    EXEC dbo.usp_Internal_ResolveSession @SessionIdHash = @SessionIdHash, @AllowedRoles = '1',
         @Resource = N'app.usp_Mfa_Disable', @MaxReauthAgeMinutes = 5, @IpAddress = @IpAddress,
         @UserId = @u OUTPUT, @RoleId = @r OUTPUT;

    BEGIN TRANSACTION;
    UPDATE dbo.Users SET MfaEnabled = 0, MfaSecretEncrypted = NULL, MfaLastUsedStep = NULL
    WHERE UserId = @u AND MfaEnabled = 1;
    SET @rows = @@ROWCOUNT;
    IF @rows = 1
    BEGIN
        DELETE FROM dbo.MfaBackupCodes WHERE UserId = @u;
        EXEC dbo.usp_Internal_LogSecurityEvent @EventType = 'MfaDisabled', @Severity = 'Warning', @UserId = @u,
             @IpAddress = @IpAddress, @Resource = N'/Account/MfaSetup';
    END
    COMMIT TRANSACTION;
    SELECT CASE WHEN @rows = 1 THEN 1 ELSE 0 END AS Disabled;
END
GO

-- Replace all backup codes (needs a recent re-authentication). Returns: Replaced (1 row)
CREATE OR ALTER PROCEDURE app.usp_Mfa_ReplaceBackupCodes
    @SessionIdHash    BINARY(32),
    @BackupCodeHashes VARBINARY(320),
    @IpAddress        VARCHAR(45) = NULL
AS
BEGIN
    SET NOCOUNT ON;
    SET XACT_ABORT ON;
    DECLARE @u UNIQUEIDENTIFIER, @r TINYINT, @enabled BIT;
    EXEC dbo.usp_Internal_ResolveSession @SessionIdHash = @SessionIdHash, @AllowedRoles = NULL,
         @Resource = N'app.usp_Mfa_ReplaceBackupCodes', @MaxReauthAgeMinutes = 5, @IpAddress = @IpAddress,
         @UserId = @u OUTPUT, @RoleId = @r OUTPUT;

    IF @BackupCodeHashes IS NULL OR DATALENGTH(@BackupCodeHashes) = 0 OR DATALENGTH(@BackupCodeHashes) % 32 <> 0
        THROW 50400, N'Invalid backup code list', 1;

    SELECT @enabled = MfaEnabled FROM dbo.Users WHERE UserId = @u;
    IF @enabled = 0
    BEGIN
        SELECT CAST(0 AS BIT) AS Replaced;
        RETURN;
    END

    BEGIN TRANSACTION;
    DELETE FROM dbo.MfaBackupCodes WHERE UserId = @u;
    INSERT dbo.MfaBackupCodes (UserId, CodeHash) SELECT @u, CodeHash FROM dbo.fn_SplitHashes(@BackupCodeHashes);
    EXEC dbo.usp_Internal_LogSecurityEvent @EventType = 'MfaBackupCodesReplaced', @Severity = 'Info', @UserId = @u,
         @IpAddress = @IpAddress, @Resource = N'/Account/MfaSetup';
    COMMIT TRANSACTION;
    SELECT CAST(1 AS BIT) AS Replaced;
END
GO

-- Profile for the "my account" page. Returns: DisplayName, Email, RoleId, EmailConfirmed, MfaEnabled, UnusedBackupCodes
CREATE OR ALTER PROCEDURE app.usp_User_GetProfile
    @SessionIdHash BINARY(32),
    @IpAddress     VARCHAR(45) = NULL
AS
BEGIN
    SET NOCOUNT ON;
    DECLARE @u UNIQUEIDENTIFIER, @r TINYINT;
    EXEC dbo.usp_Internal_ResolveSession @SessionIdHash = @SessionIdHash, @AllowedRoles = NULL,
         @Resource = N'app.usp_User_GetProfile', @IpAddress = @IpAddress, @UserId = @u OUTPUT, @RoleId = @r OUTPUT;

    SELECT us.DisplayName, us.Email, us.RoleId, us.EmailConfirmed, us.MfaEnabled,
           (SELECT COUNT(*) FROM dbo.MfaBackupCodes b WHERE b.UserId = us.UserId AND b.UsedAtUtc IS NULL) AS UnusedBackupCodes
    FROM dbo.Users us WHERE us.UserId = @u;
END
GO

/* ---------------------------------------------------------------------
   US3 + US7 - Browse and search products (public, no session needed)
   One procedure serves list, category filter, sorting, paging AND search, so paging logic exists once.
   * @Sort is matched against a fixed whitelist inside ORDER BY (no dynamic SQL); unknown value = name_asc.
   * @SearchTerm is trimmed, then the LIKE wildcards % _ [ and the escape character \ are escaped HERE,
     so a user cannot craft an expensive wildcard search. Used only as a parameter, never concatenated.
   * @PageSize is clamped to 1..100 and @Page to 1..10000.
   * Result set contains TotalCount on every row (COUNT(*) OVER()); empty set = no results.
   Sort values: name_asc, name_desc, price_asc, price_desc, newest
   Returns: ProductId, CategoryId, CategoryName, Name, ShortDescription (first 200 chars), Price,
            StockQuantity, ImageFileName, TotalCount
   --------------------------------------------------------------------- */
CREATE OR ALTER PROCEDURE app.usp_Product_List
    @SearchTerm NVARCHAR(100) = NULL,
    @CategoryId INT           = NULL,
    @Sort       VARCHAR(20)   = 'name_asc',
    @Page       INT           = 1,
    @PageSize   INT           = 20
AS
BEGIN
    SET NOCOUNT ON;
    IF @Page < 1 SET @Page = 1;
    IF @Page > 10000 SET @Page = 10000;
    IF @PageSize < 1 SET @PageSize = 20;
    IF @PageSize > 100 SET @PageSize = 100;

    DECLARE @pattern NVARCHAR(220) = NULL;
    SET @SearchTerm = LTRIM(RTRIM(@SearchTerm));
    IF @SearchTerm IS NOT NULL AND LEN(@SearchTerm) > 0
        SET @pattern = N'%' + REPLACE(REPLACE(REPLACE(REPLACE(@SearchTerm, N'\', N'\\'), N'%', N'\%'), N'_', N'\_'), N'[', N'\[') + N'%';

    SELECT p.ProductId, p.CategoryId, c.Name AS CategoryName, p.Name,
           LEFT(p.Description, 200) AS ShortDescription, p.Price, p.StockQuantity, p.ImageFileName,
           COUNT(*) OVER () AS TotalCount
    FROM dbo.Products p
    JOIN dbo.Categories c ON c.CategoryId = p.CategoryId
    WHERE p.IsActive = 1
      AND (@CategoryId IS NULL OR p.CategoryId = @CategoryId)
      AND (@pattern IS NULL OR p.Name LIKE @pattern ESCAPE N'\' OR p.Description LIKE @pattern ESCAPE N'\')
    ORDER BY
        CASE WHEN @Sort = 'name_asc'   THEN p.Name END ASC,
        CASE WHEN @Sort = 'name_desc'  THEN p.Name END DESC,
        CASE WHEN @Sort = 'price_asc'  THEN p.Price END ASC,
        CASE WHEN @Sort = 'price_desc' THEN p.Price END DESC,
        CASE WHEN @Sort = 'newest'     THEN p.CreatedAtUtc END DESC,
        p.Name ASC, p.ProductId ASC
    OFFSET (@Page - 1) * @PageSize ROWS FETCH NEXT @PageSize ROWS ONLY;
END
GO

-- Returns: ProductId, CategoryId, CategoryName, Name, Description, Price, StockQuantity, ImageFileName (0 or 1 row; inactive = 0 rows)
CREATE OR ALTER PROCEDURE app.usp_Product_Get
    @ProductId INT
AS
BEGIN
    SET NOCOUNT ON;
    SELECT p.ProductId, p.CategoryId, c.Name AS CategoryName, p.Name, p.Description, p.Price, p.StockQuantity, p.ImageFileName
    FROM dbo.Products p
    JOIN dbo.Categories c ON c.CategoryId = p.CategoryId
    WHERE p.ProductId = @ProductId AND p.IsActive = 1;
END
GO

-- Returns: CategoryId, Name
CREATE OR ALTER PROCEDURE app.usp_Category_List
AS
BEGIN
    SET NOCOUNT ON;
    SELECT CategoryId, Name FROM dbo.Categories ORDER BY Name;
END
GO

/* ---------------------------------------------------------------------
   US4 - Cart. The client only ever sends productId + quantity. Price, name and stock are looked up here.
   Owner = the session's user, or the anonymous cart cookie (hash). There is no cart id parameter at all.
   Result codes of the mutating procedures (1 row, column Result):
     0 = ok   1 = product unavailable   2 = not enough stock   3 = invalid quantity (must be 1..99)
   --------------------------------------------------------------------- */
-- Returns: ProductId, Name, UnitPrice, Quantity, LineTotal, StockQuantity, IsActive, ImageFileName
CREATE OR ALTER PROCEDURE app.usp_Cart_Get
    @SessionIdHash BINARY(32) = NULL,
    @AnonKeyHash   BINARY(32) = NULL,
    @IpAddress     VARCHAR(45) = NULL
AS
BEGIN
    SET NOCOUNT ON;
    DECLARE @cart UNIQUEIDENTIFIER, @u UNIQUEIDENTIFIER;
    EXEC dbo.usp_Internal_GetCart @SessionIdHash = @SessionIdHash, @AnonKeyHash = @AnonKeyHash, @Create = 0,
         @Resource = N'app.usp_Cart_Get', @IpAddress = @IpAddress, @CartId = @cart OUTPUT, @UserId = @u OUTPUT;

    SELECT ci.ProductId, p.Name, p.Price AS UnitPrice, ci.Quantity,
           CAST(p.Price * ci.Quantity AS DECIMAL(12,2)) AS LineTotal,
           p.StockQuantity, p.IsActive, p.ImageFileName
    FROM dbo.CartItems ci
    JOIN dbo.Products p ON p.ProductId = ci.ProductId
    WHERE ci.CartId = @cart
    ORDER BY ci.AddedAtUtc, p.Name;
END
GO

-- Adds @Quantity to the line (creates the cart/line when needed). Stock is checked now and again at checkout.
CREATE OR ALTER PROCEDURE app.usp_Cart_AddItem
    @SessionIdHash BINARY(32) = NULL,
    @AnonKeyHash   BINARY(32) = NULL,
    @ProductId     INT,
    @Quantity      INT,
    @IpAddress     VARCHAR(45) = NULL
AS
BEGIN
    SET NOCOUNT ON;
    SET XACT_ABORT ON;
    DECLARE @cart UNIQUEIDENTIFIER, @u UNIQUEIDENTIFIER, @stock INT, @current INT, @new INT;

    IF @Quantity IS NULL OR @Quantity < 1 OR @Quantity > 99
    BEGIN
        SELECT 3 AS Result;
        RETURN;
    END

    SELECT @stock = StockQuantity FROM dbo.Products WHERE ProductId = @ProductId AND IsActive = 1;
    IF @stock IS NULL
    BEGIN
        SELECT 1 AS Result;
        RETURN;
    END

    EXEC dbo.usp_Internal_GetCart @SessionIdHash = @SessionIdHash, @AnonKeyHash = @AnonKeyHash, @Create = 1,
         @Resource = N'app.usp_Cart_AddItem', @IpAddress = @IpAddress, @CartId = @cart OUTPUT, @UserId = @u OUTPUT;

    BEGIN TRANSACTION;

    SELECT @current = Quantity FROM dbo.CartItems WITH (UPDLOCK, HOLDLOCK) WHERE CartId = @cart AND ProductId = @ProductId;
    SET @new = ISNULL(@current, 0) + @Quantity;

    IF @new > 99
    BEGIN
        ROLLBACK TRANSACTION;
        SELECT 3 AS Result;
        RETURN;
    END
    IF @new > @stock
    BEGIN
        ROLLBACK TRANSACTION;
        SELECT 2 AS Result;
        RETURN;
    END

    IF @current IS NULL
        INSERT dbo.CartItems (CartId, ProductId, Quantity) VALUES (@cart, @ProductId, @new);
    ELSE
        UPDATE dbo.CartItems SET Quantity = @new WHERE CartId = @cart AND ProductId = @ProductId;

    UPDATE dbo.Carts SET UpdatedAtUtc = SYSUTCDATETIME() WHERE CartId = @cart;
    COMMIT TRANSACTION;
    SELECT 0 AS Result;
END
GO

-- Sets the line to an absolute quantity (0 removes the line).
CREATE OR ALTER PROCEDURE app.usp_Cart_SetQuantity
    @SessionIdHash BINARY(32) = NULL,
    @AnonKeyHash   BINARY(32) = NULL,
    @ProductId     INT,
    @Quantity      INT,
    @IpAddress     VARCHAR(45) = NULL
AS
BEGIN
    SET NOCOUNT ON;
    SET XACT_ABORT ON;
    DECLARE @cart UNIQUEIDENTIFIER, @u UNIQUEIDENTIFIER, @stock INT;

    IF @Quantity IS NULL OR @Quantity < 0 OR @Quantity > 99
    BEGIN
        SELECT 3 AS Result;
        RETURN;
    END

    EXEC dbo.usp_Internal_GetCart @SessionIdHash = @SessionIdHash, @AnonKeyHash = @AnonKeyHash, @Create = 0,
         @Resource = N'app.usp_Cart_SetQuantity', @IpAddress = @IpAddress, @CartId = @cart OUTPUT, @UserId = @u OUTPUT;

    IF @cart IS NULL OR NOT EXISTS (SELECT 1 FROM dbo.CartItems WHERE CartId = @cart AND ProductId = @ProductId)
    BEGIN
        SELECT 1 AS Result;      -- nothing to change (also the answer for somebody else's product id: no information leaks)
        RETURN;
    END

    IF @Quantity = 0
    BEGIN
        DELETE FROM dbo.CartItems WHERE CartId = @cart AND ProductId = @ProductId;
    END
    ELSE
    BEGIN
        SELECT @stock = StockQuantity FROM dbo.Products WHERE ProductId = @ProductId AND IsActive = 1;
        IF @stock IS NULL
        BEGIN
            SELECT 1 AS Result;
            RETURN;
        END
        IF @Quantity > @stock
        BEGIN
            SELECT 2 AS Result;
            RETURN;
        END
        UPDATE dbo.CartItems SET Quantity = @Quantity WHERE CartId = @cart AND ProductId = @ProductId;
    END

    UPDATE dbo.Carts SET UpdatedAtUtc = SYSUTCDATETIME() WHERE CartId = @cart;
    SELECT 0 AS Result;
END
GO

CREATE OR ALTER PROCEDURE app.usp_Cart_RemoveItem
    @SessionIdHash BINARY(32) = NULL,
    @AnonKeyHash   BINARY(32) = NULL,
    @ProductId     INT,
    @IpAddress     VARCHAR(45) = NULL
AS
BEGIN
    SET NOCOUNT ON;
    DECLARE @cart UNIQUEIDENTIFIER, @u UNIQUEIDENTIFIER;
    EXEC dbo.usp_Internal_GetCart @SessionIdHash = @SessionIdHash, @AnonKeyHash = @AnonKeyHash, @Create = 0,
         @Resource = N'app.usp_Cart_RemoveItem', @IpAddress = @IpAddress, @CartId = @cart OUTPUT, @UserId = @u OUTPUT;

    DELETE FROM dbo.CartItems WHERE CartId = @cart AND ProductId = @ProductId;
    UPDATE dbo.Carts SET UpdatedAtUtc = SYSUTCDATETIME() WHERE CartId = @cart;
    SELECT 0 AS Result;
END
GO

/* Merge the anonymous cart (cookie) into the signed-in user's cart right after login.
   Quantity per line = min(99, stock, sum). Inactive or sold-out products are dropped.
   Returns: Result (1 row): 0 = merged, 1 = there was no anonymous cart. */
CREATE OR ALTER PROCEDURE app.usp_Cart_MergeAnonymous
    @SessionIdHash BINARY(32),
    @AnonKeyHash   BINARY(32),
    @IpAddress     VARCHAR(45) = NULL
AS
BEGIN
    SET NOCOUNT ON;
    SET XACT_ABORT ON;
    DECLARE @userCart UNIQUEIDENTIFIER, @u UNIQUEIDENTIFIER, @anon UNIQUEIDENTIFIER;

    -- Session only: resolves + creates the user's cart
    EXEC dbo.usp_Internal_GetCart @SessionIdHash = @SessionIdHash, @AnonKeyHash = NULL, @Create = 1,
         @Resource = N'app.usp_Cart_MergeAnonymous', @IpAddress = @IpAddress, @CartId = @userCart OUTPUT, @UserId = @u OUTPUT;

    SELECT @anon = CartId FROM dbo.Carts WHERE AnonymousKeyHash = @AnonKeyHash;
    IF @anon IS NULL
    BEGIN
        SELECT 1 AS Result;
        RETURN;
    END

    BEGIN TRANSACTION;

    UPDATE t
    SET t.Quantity = (SELECT MIN(x.v) FROM (VALUES (t.Quantity + s.Quantity), (99), (p.StockQuantity)) AS x(v))
    FROM dbo.CartItems t
    JOIN dbo.CartItems s ON s.ProductId = t.ProductId AND s.CartId = @anon
    JOIN dbo.Products p ON p.ProductId = t.ProductId AND p.IsActive = 1 AND p.StockQuantity >= 1
    WHERE t.CartId = @userCart;

    INSERT dbo.CartItems (CartId, ProductId, Quantity)
    SELECT @userCart, s.ProductId, (SELECT MIN(x.v) FROM (VALUES (s.Quantity), (p.StockQuantity)) AS x(v))
    FROM dbo.CartItems s
    JOIN dbo.Products p ON p.ProductId = s.ProductId AND p.IsActive = 1 AND p.StockQuantity >= 1
    WHERE s.CartId = @anon
      AND NOT EXISTS (SELECT 1 FROM dbo.CartItems t WHERE t.CartId = @userCart AND t.ProductId = s.ProductId);

    DELETE FROM dbo.Carts WHERE CartId = @anon;      -- cascades to its items
    UPDATE dbo.Carts SET UpdatedAtUtc = SYSUTCDATETIME() WHERE CartId = @userCart;

    COMMIT TRANSACTION;
    SELECT 0 AS Result;
END
GO

/* ---------------------------------------------------------------------
   US5 - Checkout and payment
   --------------------------------------------------------------------- */
/* Creates a Pending order from the signed-in customer's cart AND reserves stock in ONE transaction.
   * Roles: Customer and Admin may buy (RBAC matrix); SysAdmin may not. E-mail must be confirmed.
   * The total is calculated here from database prices, never from the client.
   * @IdempotencyKey: the same key by the same user returns the existing order (double click / reload).
   * Stock: UPDATE ... WHERE StockQuantity >= qty is atomic; if any line fails, everything rolls back.
   * A user can hold at most 3 unpaid orders at a time (prevents reserving all stock without paying).
   * Result: 0 created  1 cart empty  2 a product is unavailable / out of stock  3 too many unpaid orders
           5 replay of an earlier request (OrderId = the existing order)
   Returns: Result, OrderId, TotalAmount  (1 row; OrderId/TotalAmount NULL unless Result in (0,5)) */
CREATE OR ALTER PROCEDURE app.usp_Order_Create
    @SessionIdHash   BINARY(32),
    @IdempotencyKey  UNIQUEIDENTIFIER,
    @ShipName        NVARCHAR(100),
    @ShipAddressLine NVARCHAR(200),
    @ShipPostalCode  NVARCHAR(10),
    @ShipCity        NVARCHAR(100),
    @ShipCountry     NVARCHAR(2) = N'DK',
    @IpAddress       VARCHAR(45) = NULL
AS
BEGIN
    SET NOCOUNT ON;
    SET XACT_ABORT ON;
    DECLARE @u UNIQUEIDENTIFIER, @r TINYINT;
    EXEC dbo.usp_Internal_ResolveSession @SessionIdHash = @SessionIdHash, @AllowedRoles = '1,2',
         @Resource = N'app.usp_Order_Create', @RequireEmailConfirmed = 1, @IpAddress = @IpAddress,
         @UserId = @u OUTPUT, @RoleId = @r OUTPUT;

    SET @ShipName = LTRIM(RTRIM(@ShipName));
    SET @ShipAddressLine = LTRIM(RTRIM(@ShipAddressLine));
    SET @ShipPostalCode = LTRIM(RTRIM(@ShipPostalCode));
    SET @ShipCity = LTRIM(RTRIM(@ShipCity));
    SET @ShipCountry = UPPER(LTRIM(RTRIM(@ShipCountry)));
    IF LEN(@ShipName) = 0 OR LEN(@ShipAddressLine) = 0 OR LEN(@ShipPostalCode) = 0 OR LEN(@ShipCity) = 0 OR LEN(@ShipCountry) <> 2
        THROW 50400, N'Invalid shipping data', 1;

    -- Lazy housekeeping: give back stock reserved by abandoned unpaid orders
    EXEC dbo.usp_Internal_ExpirePendingOrders @MaxAgeMinutes = 60;

    DECLARE @cart UNIQUEIDENTIFIER, @lines INT, @ok INT, @total DECIMAL(12,2), @orderId UNIQUEIDENTIFIER,
            @existing UNIQUEIDENTIFIER, @existingUser UNIQUEIDENTIFIER, @existingTotal DECIMAL(12,2);

    BEGIN TRANSACTION;

    SELECT @existing = OrderId, @existingUser = UserId, @existingTotal = TotalAmount
    FROM dbo.Orders WITH (UPDLOCK, HOLDLOCK) WHERE IdempotencyKey = @IdempotencyKey;

    IF @existing IS NOT NULL
    BEGIN
        COMMIT TRANSACTION;
        IF @existingUser = @u
            SELECT 5 AS Result, @existing AS OrderId, @existingTotal AS TotalAmount;
        ELSE
            SELECT 2 AS Result, CAST(NULL AS UNIQUEIDENTIFIER) AS OrderId, CAST(NULL AS DECIMAL(12,2)) AS TotalAmount;   -- key belongs to someone else: reveal nothing
        RETURN;
    END

    SELECT @cart = CartId FROM dbo.Carts WHERE UserId = @u;
    SELECT @lines = COUNT(*) FROM dbo.CartItems WHERE CartId = @cart;
    IF @cart IS NULL OR @lines = 0
    BEGIN
        ROLLBACK TRANSACTION;
        SELECT 1 AS Result, CAST(NULL AS UNIQUEIDENTIFIER) AS OrderId, CAST(NULL AS DECIMAL(12,2)) AS TotalAmount;
        RETURN;
    END

    IF (SELECT COUNT(*) FROM dbo.Orders WHERE UserId = @u AND Status = 'Pending') >= 3
    BEGIN
        ROLLBACK TRANSACTION;
        SELECT 3 AS Result, CAST(NULL AS UNIQUEIDENTIFIER) AS OrderId, CAST(NULL AS DECIMAL(12,2)) AS TotalAmount;
        RETURN;
    END

    -- Atomic stock reservation. Concurrent buyers of the last item serialise on the row lock; the loser's
    -- predicate (StockQuantity >= qty) is re-evaluated after the winner commits and fails.
    UPDATE p
    SET p.StockQuantity = p.StockQuantity - ci.Quantity, p.UpdatedAtUtc = SYSUTCDATETIME()
    FROM dbo.Products p
    JOIN dbo.CartItems ci ON ci.ProductId = p.ProductId
    WHERE ci.CartId = @cart AND p.IsActive = 1 AND p.StockQuantity >= ci.Quantity;
    SET @ok = @@ROWCOUNT;

    IF @ok <> @lines
    BEGIN
        ROLLBACK TRANSACTION;       -- undoes the lines that did succeed
        SELECT 2 AS Result, CAST(NULL AS UNIQUEIDENTIFIER) AS OrderId, CAST(NULL AS DECIMAL(12,2)) AS TotalAmount;
        RETURN;
    END

    -- Product rows are now exclusively locked by this transaction, so prices cannot change under us
    SELECT @total = SUM(p.Price * ci.Quantity)
    FROM dbo.CartItems ci JOIN dbo.Products p ON p.ProductId = ci.ProductId
    WHERE ci.CartId = @cart;

    SET @orderId = NEWID();
    INSERT dbo.Orders (OrderId, UserId, Status, TotalAmount, Currency, ShipName, ShipAddressLine, ShipPostalCode, ShipCity, ShipCountry, IdempotencyKey)
    VALUES (@orderId, @u, 'Pending', @total, 'DKK', @ShipName, @ShipAddressLine, @ShipPostalCode, @ShipCity, @ShipCountry, @IdempotencyKey);

    INSERT dbo.OrderItems (OrderId, ProductId, ProductName, UnitPrice, Quantity)
    SELECT @orderId, p.ProductId, p.Name, p.Price, ci.Quantity
    FROM dbo.CartItems ci JOIN dbo.Products p ON p.ProductId = ci.ProductId
    WHERE ci.CartId = @cart;

    EXEC dbo.usp_Internal_LogSecurityEvent @EventType = 'OrderCreated', @Severity = 'Info', @UserId = @u,
         @IpAddress = @IpAddress, @Resource = N'/Checkout', @Details = @orderId;

    COMMIT TRANSACTION;
    SELECT 0 AS Result, @orderId AS OrderId, @total AS TotalAmount;
END
GO

-- Stores the payment provider's checkout reference on the caller's own Pending order. Returns: Updated (1 row)
CREATE OR ALTER PROCEDURE app.usp_Order_SetPaymentRef
    @SessionIdHash BINARY(32),
    @OrderId       UNIQUEIDENTIFIER,
    @ProviderRef   NVARCHAR(100),
    @IpAddress     VARCHAR(45) = NULL
AS
BEGIN
    SET NOCOUNT ON;
    DECLARE @u UNIQUEIDENTIFIER, @r TINYINT, @rows INT;
    EXEC dbo.usp_Internal_ResolveSession @SessionIdHash = @SessionIdHash, @AllowedRoles = '1,2',
         @Resource = N'app.usp_Order_SetPaymentRef', @RequireEmailConfirmed = 1, @IpAddress = @IpAddress,
         @UserId = @u OUTPUT, @RoleId = @r OUTPUT;

    UPDATE dbo.Orders SET PaymentProviderRef = @ProviderRef, UpdatedAtUtc = SYSUTCDATETIME()
    WHERE OrderId = @OrderId AND UserId = @u AND Status = 'Pending' AND PaymentProviderRef IS NULL;
    SET @rows = @@ROWCOUNT;
    SELECT CASE WHEN @rows = 1 THEN 1 ELSE 0 END AS Updated;
END
GO

/* Applies a payment-provider webhook event. The application has ALREADY verified the HMAC signature and
   timestamp; this procedure adds the database-level protections:
     * replay: the same @EventId is processed only once (primary key on PaymentEvents)
     * the event must carry the provider reference that belongs to the order
     * the paid amount and currency must equal the order total ("tampered amount" test)
     * Pending -> Paid, or Pending -> Failed (stock released). Closed orders are never re-opened:
       a success for a Cancelled/Failed order is logged as Critical for manual refund.
   @EventType: 'payment_succeeded' | 'payment_failed'
   Result: 0 applied/no-op-ok  1 duplicate event  2 unknown order or reference mismatch
           3 amount/currency mismatch  4 payment arrived for a closed order
   Returns: Result, Transitioned (1 = status changed now), Status, OrderId, UserEmail, DisplayName, TotalAmount
            (1 row; use Transitioned + Status to decide whether to send the confirmation e-mail) */
CREATE OR ALTER PROCEDURE app.usp_Payment_ApplyEvent
    @EventId     NVARCHAR(100),
    @EventType   NVARCHAR(100),
    @OrderId     UNIQUEIDENTIFIER,
    @ProviderRef NVARCHAR(100),
    @AmountPaid  DECIMAL(12,2) = NULL,
    @Currency    CHAR(3)       = NULL
AS
BEGIN
    SET NOCOUNT ON;
    SET XACT_ABORT ON;
    DECLARE @result INT = 0, @transitioned BIT = 0, @status VARCHAR(15), @total DECIMAL(12,2), @cur CHAR(3),
            @ref NVARCHAR(100), @u UNIQUEIDENTIFIER, @released BIT, @orderText NVARCHAR(100) = CONVERT(NVARCHAR(100), @OrderId);

    IF @EventType NOT IN (N'payment_succeeded', N'payment_failed')
        THROW 50400, N'Unknown payment event type', 1;

    BEGIN TRY
        BEGIN TRANSACTION;

        BEGIN TRY
            INSERT dbo.PaymentEvents (EventId, OrderId, EventType)
            VALUES (@EventId, CASE WHEN EXISTS (SELECT 1 FROM dbo.Orders WHERE OrderId = @OrderId) THEN @OrderId END, @EventType);
        END TRY
        BEGIN CATCH
            IF ERROR_NUMBER() IN (2601, 2627)
            BEGIN
                IF @@TRANCOUNT > 0 ROLLBACK TRANSACTION;
                EXEC dbo.usp_Internal_LogSecurityEvent @EventType = 'PaymentEventReplay', @Severity = 'Warning',
                     @Resource = N'/api/payments/webhook', @Details = @EventId;
                SELECT 1 AS Result, CAST(0 AS BIT) AS Transitioned, CAST(NULL AS VARCHAR(15)) AS Status, @OrderId AS OrderId,
                       CAST(NULL AS NVARCHAR(254)) AS UserEmail, CAST(NULL AS NVARCHAR(100)) AS DisplayName, CAST(NULL AS DECIMAL(12,2)) AS TotalAmount;
                RETURN;
            END;
            THROW;
        END CATCH

        SELECT @status = o.Status, @total = o.TotalAmount, @cur = o.Currency, @ref = o.PaymentProviderRef, @u = o.UserId
        FROM dbo.Orders o WITH (UPDLOCK) WHERE o.OrderId = @OrderId;

        IF @status IS NULL OR @ref IS NULL OR @ref <> @ProviderRef
        BEGIN
            SET @result = 2;
            EXEC dbo.usp_Internal_LogSecurityEvent @EventType = 'PaymentUnknownOrder', @Severity = 'Warning',
                 @Resource = N'/api/payments/webhook', @Details = @orderText;
        END
        ELSE IF @EventType = N'payment_succeeded'
        BEGIN
            IF @AmountPaid IS NULL OR @AmountPaid <> @total OR @Currency IS NULL OR @Currency <> @cur
            BEGIN
                SET @result = 3;
                EXEC dbo.usp_Internal_LogSecurityEvent @EventType = 'PaymentAmountMismatch', @Severity = 'Critical', @UserId = @u,
                     @Resource = N'/api/payments/webhook', @Details = @orderText;
            END
            ELSE IF @status = 'Pending'
            BEGIN
                UPDATE dbo.Orders SET Status = 'Paid', PaidAtUtc = SYSUTCDATETIME(), UpdatedAtUtc = SYSUTCDATETIME() WHERE OrderId = @OrderId;
                SET @status = 'Paid';
                SET @transitioned = 1;

                -- Remove the bought lines from the buyer's cart (anything added meanwhile is kept)
                DELETE ci
                FROM dbo.CartItems ci
                JOIN dbo.Carts c ON c.CartId = ci.CartId AND c.UserId = @u
                JOIN dbo.OrderItems oi ON oi.ProductId = ci.ProductId AND oi.OrderId = @OrderId;

                EXEC dbo.usp_Internal_LogSecurityEvent @EventType = 'PaymentSucceeded', @Severity = 'Info', @UserId = @u,
                     @Resource = N'/api/payments/webhook', @Details = @orderText;
            END
            ELSE IF @status IN ('Cancelled', 'Failed')
            BEGIN
                SET @result = 4;
                EXEC dbo.usp_Internal_LogSecurityEvent @EventType = 'PaymentOnClosedOrder', @Severity = 'Critical', @UserId = @u,
                     @Resource = N'/api/payments/webhook', @Details = @orderText;
            END
            -- Paid / Shipped: already paid, nothing to do (idempotent)
        END
        ELSE    -- payment_failed
        BEGIN
            IF @status = 'Pending'
            BEGIN
                EXEC dbo.usp_Internal_ReleaseOrder @OrderId = @OrderId, @NewStatus = 'Failed', @Released = @released OUTPUT;
                SET @status = 'Failed';
                SET @transitioned = 1;
                EXEC dbo.usp_Internal_LogSecurityEvent @EventType = 'PaymentFailed', @Severity = 'Info', @UserId = @u,
                     @Resource = N'/api/payments/webhook', @Details = @orderText;
            END
        END

        COMMIT TRANSACTION;
    END TRY
    BEGIN CATCH
        IF @@TRANCOUNT > 0 ROLLBACK TRANSACTION;
        THROW;
    END CATCH

    SELECT @result AS Result, @transitioned AS Transitioned, @status AS Status, @OrderId AS OrderId,
           us.Email AS UserEmail, us.DisplayName, @total AS TotalAmount
    FROM (SELECT 1 AS one) d
    LEFT JOIN dbo.Users us ON us.UserId = @u;
END
GO

/* ---------------------------------------------------------------------
   US8 - Order history. Ownership is part of the query itself (WHERE UserId = <session user>).
   An order that exists but belongs to somebody else returns exactly the same EMPTY result as an
   order that does not exist (the app answers 404 for both), but the attempt is logged.
   --------------------------------------------------------------------- */
-- Returns: OrderId, CreatedAtUtc, Status, TotalAmount, Currency, TotalCount
CREATE OR ALTER PROCEDURE app.usp_Order_ListMine
    @SessionIdHash BINARY(32),
    @Page          INT = 1,
    @PageSize      INT = 20,
    @IpAddress     VARCHAR(45) = NULL
AS
BEGIN
    SET NOCOUNT ON;
    DECLARE @u UNIQUEIDENTIFIER, @r TINYINT;
    EXEC dbo.usp_Internal_ResolveSession @SessionIdHash = @SessionIdHash, @AllowedRoles = '1,2',
         @Resource = N'app.usp_Order_ListMine', @IpAddress = @IpAddress, @UserId = @u OUTPUT, @RoleId = @r OUTPUT;

    IF @Page < 1 SET @Page = 1;
    IF @Page > 10000 SET @Page = 10000;
    IF @PageSize < 1 SET @PageSize = 20;
    IF @PageSize > 100 SET @PageSize = 100;

    SELECT o.OrderId, o.CreatedAtUtc, o.Status, o.TotalAmount, o.Currency, COUNT(*) OVER () AS TotalCount
    FROM dbo.Orders o
    WHERE o.UserId = @u
    ORDER BY o.CreatedAtUtc DESC, o.OrderId
    OFFSET (@Page - 1) * @PageSize ROWS FETCH NEXT @PageSize ROWS ONLY;
END
GO

-- One row per order line (order columns repeat). Never returns card data.
-- Returns: OrderId, CreatedAtUtc, Status, PaidAtUtc, TotalAmount, Currency, ShipName, ShipAddressLine,
--          ShipPostalCode, ShipCity, ShipCountry, ProductId, ProductName, UnitPrice, Quantity
CREATE OR ALTER PROCEDURE app.usp_Order_GetMine
    @SessionIdHash BINARY(32),
    @OrderId       UNIQUEIDENTIFIER,
    @IpAddress     VARCHAR(45) = NULL
AS
BEGIN
    SET NOCOUNT ON;
    DECLARE @u UNIQUEIDENTIFIER, @r TINYINT, @orderText NVARCHAR(100) = CONVERT(NVARCHAR(100), @OrderId);
    EXEC dbo.usp_Internal_ResolveSession @SessionIdHash = @SessionIdHash, @AllowedRoles = '1,2',
         @Resource = N'app.usp_Order_GetMine', @IpAddress = @IpAddress, @UserId = @u OUTPUT, @RoleId = @r OUTPUT;

    IF NOT EXISTS (SELECT 1 FROM dbo.Orders WHERE OrderId = @OrderId AND UserId = @u)
    BEGIN
        IF EXISTS (SELECT 1 FROM dbo.Orders WHERE OrderId = @OrderId)
            EXEC dbo.usp_Internal_LogSecurityEvent @EventType = 'AccessDenied', @Severity = 'Warning', @UserId = @u,
                 @IpAddress = @IpAddress, @Resource = @orderText, @Details = N'order-not-owned';
        RETURN;      -- empty result set: indistinguishable from "does not exist"
    END

    SELECT o.OrderId, o.CreatedAtUtc, o.Status, o.PaidAtUtc, o.TotalAmount, o.Currency,
           o.ShipName, o.ShipAddressLine, o.ShipPostalCode, o.ShipCity, o.ShipCountry,
           oi.ProductId, oi.ProductName, oi.UnitPrice, oi.Quantity
    FROM dbo.Orders o
    JOIN dbo.OrderItems oi ON oi.OrderId = o.OrderId
    WHERE o.OrderId = @OrderId AND o.UserId = @u
    ORDER BY oi.ProductName;
END
GO

/* ---------------------------------------------------------------------
   US6 - Change and reset password
   The application verifies the CURRENT password (Argon2id) and the policy; these procedures make the
   state change atomic and revoke sessions. Passwords/hashes are never logged.
   --------------------------------------------------------------------- */
-- Data the app needs to verify the current password / MFA code. Returns: UserId, Email, PasswordHash, MfaEnabled, RoleId
CREATE OR ALTER PROCEDURE app.usp_Password_GetForChange
    @SessionIdHash BINARY(32),
    @IpAddress     VARCHAR(45) = NULL
AS
BEGIN
    SET NOCOUNT ON;
    DECLARE @u UNIQUEIDENTIFIER, @r TINYINT;
    EXEC dbo.usp_Internal_ResolveSession @SessionIdHash = @SessionIdHash, @AllowedRoles = NULL,
         @Resource = N'app.usp_Password_GetForChange', @IpAddress = @IpAddress, @UserId = @u OUTPUT, @RoleId = @r OUTPUT;
    SELECT UserId, Email, PasswordHash, MfaEnabled, RoleId FROM dbo.Users WHERE UserId = @u;
END
GO

/* Change password (logged in). Compare-and-swap on the old hash closes the check-then-update race.
   All OTHER sessions are revoked, outstanding reset links are invalidated.
   Result: 0 changed  1 stale (the stored hash changed in the meantime: retry)
   Returns: Result, Email, DisplayName (1 row; Email/DisplayName only when Result = 0, for the confirmation mail) */
CREATE OR ALTER PROCEDURE app.usp_Password_Change
    @SessionIdHash BINARY(32),
    @OldHash       NVARCHAR(255),
    @NewHash       NVARCHAR(255),
    @IpAddress     VARCHAR(45) = NULL
AS
BEGIN
    SET NOCOUNT ON;
    SET XACT_ABORT ON;
    DECLARE @u UNIQUEIDENTIFIER, @r TINYINT, @now DATETIME2(0) = SYSUTCDATETIME(), @rows INT;
    EXEC dbo.usp_Internal_ResolveSession @SessionIdHash = @SessionIdHash, @AllowedRoles = NULL,
         @Resource = N'app.usp_Password_Change', @IpAddress = @IpAddress, @UserId = @u OUTPUT, @RoleId = @r OUTPUT;

    BEGIN TRANSACTION;

    UPDATE dbo.Users SET PasswordHash = @NewHash, PasswordChangedAtUtc = @now
    WHERE UserId = @u AND PasswordHash = @OldHash;
    SET @rows = @@ROWCOUNT;

    IF @rows = 0
    BEGIN
        ROLLBACK TRANSACTION;
        SELECT 1 AS Result, CAST(NULL AS NVARCHAR(254)) AS Email, CAST(NULL AS NVARCHAR(100)) AS DisplayName;
        RETURN;
    END

    UPDATE dbo.Sessions SET RevokedAtUtc = @now
    WHERE UserId = @u AND RevokedAtUtc IS NULL AND SessionIdHash <> @SessionIdHash;

    UPDATE dbo.UserTokens SET UsedAtUtc = @now
    WHERE UserId = @u AND Purpose = 'PasswordReset' AND UsedAtUtc IS NULL;

    EXEC dbo.usp_Internal_LogSecurityEvent @EventType = 'PasswordChanged', @Severity = 'Info', @UserId = @u,
         @IpAddress = @IpAddress, @Resource = N'/Account/ChangePassword';

    COMMIT TRANSACTION;
    SELECT 0 AS Result, Email, DisplayName FROM dbo.Users WHERE UserId = @u;
END
GO

/* "Forgot password". The application answers identically whether or not the account exists.
   Limits: 3 reset requests per account per hour, 10 per IP per hour (counted in the security log).
   A new request invalidates all earlier unused reset links. Token lifetime: 30 minutes. Only the hash is stored.
   Returns: Created, DisplayName (1 row). Send the e-mail only when Created = 1 (do it in the background queue
   so the response time does not reveal anything). */
CREATE OR ALTER PROCEDURE app.usp_PasswordReset_Request
    @Email     NVARCHAR(254),
    @TokenHash BINARY(32),
    @IpAddress VARCHAR(45) = NULL
AS
BEGIN
    SET NOCOUNT ON;
    SET XACT_ABORT ON;
    SET @Email = LOWER(LTRIM(RTRIM(@Email)));

    DECLARE @u UNIQUEIDENTIFIER, @name NVARCHAR(100), @created BIT = 0, @now DATETIME2(0) = SYSUTCDATETIME(),
            @ipCount INT = 0, @userCount INT = 0, @details NVARCHAR(100);

    IF @IpAddress IS NOT NULL
        SELECT @ipCount = COUNT(*) FROM dbo.SecurityEvents
        WHERE EventType = 'PasswordResetRequested' AND IpAddress = @IpAddress AND OccurredAtUtc > DATEADD(HOUR, -1, @now);

    SELECT @u = UserId, @name = DisplayName FROM dbo.Users WHERE Email = @Email AND IsDeleted = 0;

    IF @u IS NOT NULL
        SELECT @userCount = COUNT(*) FROM dbo.UserTokens
        WHERE UserId = @u AND Purpose = 'PasswordReset' AND CreatedAtUtc > DATEADD(HOUR, -1, @now);

    BEGIN TRANSACTION;

    IF @u IS NOT NULL AND @ipCount < 10 AND @userCount < 3
    BEGIN
        UPDATE dbo.UserTokens SET UsedAtUtc = @now WHERE UserId = @u AND Purpose = 'PasswordReset' AND UsedAtUtc IS NULL;
        INSERT dbo.UserTokens (UserId, Purpose, TokenHash, ExpiresAtUtc)
        VALUES (@u, 'PasswordReset', @TokenHash, DATEADD(MINUTE, 30, @now));
        SET @created = 1;
    END

    SET @details = CASE WHEN @created = 1 THEN N'token-issued' WHEN @u IS NULL THEN N'unknown-account' ELSE N'rate-limited' END;
    EXEC dbo.usp_Internal_LogSecurityEvent @EventType = 'PasswordResetRequested', @Severity = 'Info', @UserId = @u,
         @IpAddress = @IpAddress, @Resource = N'/Account/ForgotPassword', @Details = @details;

    COMMIT TRANSACTION;
    SELECT @created AS Created, @name AS DisplayName;
END
GO

-- Checks a reset link WITHOUT consuming it. Returns: UserId, RoleId, MfaEnabled (0 rows = invalid/used/expired)
CREATE OR ALTER PROCEDURE app.usp_PasswordReset_Validate
    @TokenHash BINARY(32)
AS
BEGIN
    SET NOCOUNT ON;
    SELECT u.UserId, u.RoleId, u.MfaEnabled
    FROM dbo.UserTokens t
    JOIN dbo.Users u ON u.UserId = t.UserId
    WHERE t.TokenHash = @TokenHash AND t.Purpose = 'PasswordReset' AND t.UsedAtUtc IS NULL
      AND t.ExpiresAtUtc > SYSUTCDATETIME() AND u.IsDeleted = 0;
END
GO

/* Completes a reset: consumes the token (single use), sets the new hash, ends EVERY session, clears any lock.
   The user is NOT logged in automatically and MFA stays on (recovery cannot bypass MFA).
   Admin/SysAdmin accounts need extra verification: the app must have verified an MFA/backup code and passes
   @MfaVerified = 1; otherwise Result = 2 and the token stays valid.
   Result: 0 done  1 invalid/used/expired token  2 extra verification required
   Returns: Result, Email, DisplayName (Email/DisplayName only when Result = 0, for the confirmation mail) */
CREATE OR ALTER PROCEDURE app.usp_PasswordReset_Complete
    @TokenHash   BINARY(32),
    @NewHash     NVARCHAR(255),
    @MfaVerified BIT         = 0,
    @IpAddress   VARCHAR(45) = NULL
AS
BEGIN
    SET NOCOUNT ON;
    SET XACT_ABORT ON;
    DECLARE @u UNIQUEIDENTIFIER, @role TINYINT, @mfa BIT, @now DATETIME2(0) = SYSUTCDATETIME(), @rows INT;

    BEGIN TRANSACTION;

    SELECT @u = t.UserId, @role = u.RoleId, @mfa = u.MfaEnabled
    FROM dbo.UserTokens t WITH (UPDLOCK)
    JOIN dbo.Users u ON u.UserId = t.UserId
    WHERE t.TokenHash = @TokenHash AND t.Purpose = 'PasswordReset' AND t.UsedAtUtc IS NULL
      AND t.ExpiresAtUtc > @now AND u.IsDeleted = 0;

    IF @u IS NULL
    BEGIN
        EXEC dbo.usp_Internal_LogSecurityEvent @EventType = 'PasswordResetFailed', @Severity = 'Warning',
             @IpAddress = @IpAddress, @Resource = N'/Account/ResetPassword', @Details = N'invalid-used-or-expired-token';
        COMMIT TRANSACTION;
        SELECT 1 AS Result, CAST(NULL AS NVARCHAR(254)) AS Email, CAST(NULL AS NVARCHAR(100)) AS DisplayName;
        RETURN;
    END

    IF @role >= 2 AND (@MfaVerified = 0 OR @mfa = 0)
    BEGIN
        EXEC dbo.usp_Internal_LogSecurityEvent @EventType = 'PasswordResetBlocked', @Severity = 'Warning', @UserId = @u,
             @IpAddress = @IpAddress, @Resource = N'/Account/ResetPassword', @Details = N'privileged-account-needs-extra-verification';
        COMMIT TRANSACTION;
        SELECT 2 AS Result, CAST(NULL AS NVARCHAR(254)) AS Email, CAST(NULL AS NVARCHAR(100)) AS DisplayName;
        RETURN;
    END

    UPDATE dbo.UserTokens SET UsedAtUtc = @now WHERE TokenHash = @TokenHash AND UsedAtUtc IS NULL;
    SET @rows = @@ROWCOUNT;
    IF @rows = 0
    BEGIN
        COMMIT TRANSACTION;
        SELECT 1 AS Result, CAST(NULL AS NVARCHAR(254)) AS Email, CAST(NULL AS NVARCHAR(100)) AS DisplayName;
        RETURN;
    END

    UPDATE dbo.Users SET PasswordHash = @NewHash, PasswordChangedAtUtc = @now, FailedLoginCount = 0, LockoutEndUtc = NULL
    WHERE UserId = @u;

    UPDATE dbo.Sessions SET RevokedAtUtc = @now WHERE UserId = @u AND RevokedAtUtc IS NULL;
    UPDATE dbo.UserTokens SET UsedAtUtc = @now WHERE UserId = @u AND Purpose = 'PasswordReset' AND UsedAtUtc IS NULL;

    EXEC dbo.usp_Internal_LogSecurityEvent @EventType = 'PasswordReset', @Severity = 'Warning', @UserId = @u,
         @IpAddress = @IpAddress, @Resource = N'/Account/ResetPassword';

    COMMIT TRANSACTION;
    SELECT 0 AS Result, Email, DisplayName FROM dbo.Users WHERE UserId = @u;
END
GO

/* ---------------------------------------------------------------------
   GDPR (cross-cutting requirement): right of access and right to erasure
   --------------------------------------------------------------------- */
-- Everything we hold about the signed-in user as ONE JSON document. Returns: Json (1 row)
CREATE OR ALTER PROCEDURE app.usp_Account_Export
    @SessionIdHash BINARY(32),
    @IpAddress     VARCHAR(45) = NULL
AS
BEGIN
    SET NOCOUNT ON;
    DECLARE @u UNIQUEIDENTIFIER, @r TINYINT;
    EXEC dbo.usp_Internal_ResolveSession @SessionIdHash = @SessionIdHash, @AllowedRoles = NULL,
         @Resource = N'app.usp_Account_Export', @IpAddress = @IpAddress, @UserId = @u OUTPUT, @RoleId = @r OUTPUT;

    EXEC dbo.usp_Internal_LogSecurityEvent @EventType = 'AccountExported', @Severity = 'Info', @UserId = @u,
         @IpAddress = @IpAddress, @Resource = N'/Account/Privacy';

    SELECT (
        SELECT
            (SELECT us.UserId, us.Email, us.DisplayName, us.CreatedAtUtc, us.EmailConfirmed, us.MfaEnabled,
                    us.PrivacyConsentVersion, us.PrivacyConsentAtUtc
             FROM dbo.Users us WHERE us.UserId = @u FOR JSON PATH, WITHOUT_ARRAY_WRAPPER) AS profile,
            (SELECT o.OrderId, o.CreatedAtUtc, o.Status, o.TotalAmount, o.Currency, o.ShipName, o.ShipAddressLine,
                    o.ShipPostalCode, o.ShipCity, o.ShipCountry,
                    (SELECT oi.ProductName, oi.UnitPrice, oi.Quantity FROM dbo.OrderItems oi WHERE oi.OrderId = o.OrderId FOR JSON PATH) AS items
             FROM dbo.Orders o WHERE o.UserId = @u FOR JSON PATH) AS orders
        FOR JSON PATH, WITHOUT_ARRAY_WRAPPER
    ) AS Json;
END
GO

/* Right to erasure = anonymisation. The user row stays (orders must be kept for bookkeeping) but all
   personal data is overwritten, every session/token/cart/MFA secret is removed and the account can no longer log in.
   Needs a recent re-authentication. Customers only (admin accounts are removed by a DBA). Returns: Deleted (1 row) */
CREATE OR ALTER PROCEDURE app.usp_Account_Delete
    @SessionIdHash BINARY(32),
    @IpAddress     VARCHAR(45) = NULL
AS
BEGIN
    SET NOCOUNT ON;
    SET XACT_ABORT ON;
    DECLARE @u UNIQUEIDENTIFIER, @r TINYINT, @now DATETIME2(0) = SYSUTCDATETIME();
    EXEC dbo.usp_Internal_ResolveSession @SessionIdHash = @SessionIdHash, @AllowedRoles = '1',
         @Resource = N'app.usp_Account_Delete', @MaxReauthAgeMinutes = 5, @IpAddress = @IpAddress,
         @UserId = @u OUTPUT, @RoleId = @r OUTPUT;

    BEGIN TRANSACTION;

    UPDATE dbo.Users
    SET Email = CONCAT(N'deleted-', REPLACE(CONVERT(NVARCHAR(36), NEWID()), N'-', N''), N'@deleted.invalid'),
        DisplayName = N'Deleted user', PasswordHash = N'!', MfaEnabled = 0, MfaSecretEncrypted = NULL,
        MfaLastUsedStep = NULL, EmailConfirmed = 0, IsDeleted = 1, LockoutEndUtc = NULL
    WHERE UserId = @u;

    UPDATE dbo.Sessions SET RevokedAtUtc = @now WHERE UserId = @u AND RevokedAtUtc IS NULL;
    DELETE FROM dbo.UserTokens WHERE UserId = @u;
    DELETE FROM dbo.MfaBackupCodes WHERE UserId = @u;
    DELETE FROM dbo.KnownDevices WHERE UserId = @u;
    DELETE FROM dbo.Carts WHERE UserId = @u;

    EXEC dbo.usp_Internal_LogSecurityEvent @EventType = 'AccountDeleted', @Severity = 'Warning', @UserId = @u,
         @IpAddress = @IpAddress, @Resource = N'/Account/Privacy';

    COMMIT TRANSACTION;
    SELECT CAST(1 AS BIT) AS Deleted;
END
GO
/* =====================================================================
   PART 4 - SCHEMAS [admin] AND [sysadmin]
   [admin]    : Admin role only (RoleId 2). Product management and customer-support order lookup.
   [sysadmin] : SysAdmin role only (RoleId 3). Log viewing, alerts, log integrity check.
   Every procedure starts with the session gate, so even a stolen connection string for the web app
   cannot call these without a valid Admin / SysAdmin session.
   ===================================================================== */
USE Webshop;
GO

/* ---------------------------------------------------------------------
   US9 - Product management (Admin only)
   Result codes for Create/Update/Delete/Restore (column Result):
     0 ok   1 not found   2 category does not exist
   Concurrency: Update demands the RowVersion the admin loaded; if somebody else saved first the
   procedure throws 50409 and nothing is changed (no "last write wins" overwrites).
   Every change writes before/after JSON to dbo.AuditLog IN THE SAME TRANSACTION. If the audit
   write fails, the change is rolled back (fail closed).
   --------------------------------------------------------------------- */
-- Includes inactive (soft-deleted) products. Returns: ProductId, CategoryId, CategoryName, Name, Price,
--   StockQuantity, IsActive, UpdatedAtUtc, TotalCount
CREATE OR ALTER PROCEDURE [admin].usp_Product_List
    @SessionIdHash   BINARY(32),
    @IncludeInactive BIT = 1,
    @Page            INT = 1,
    @PageSize        INT = 25,
    @IpAddress       VARCHAR(45) = NULL
AS
BEGIN
    SET NOCOUNT ON;
    DECLARE @u UNIQUEIDENTIFIER, @r TINYINT;
    EXEC dbo.usp_Internal_ResolveSession @SessionIdHash = @SessionIdHash, @AllowedRoles = '2',
         @Resource = N'admin.usp_Product_List', @IpAddress = @IpAddress, @UserId = @u OUTPUT, @RoleId = @r OUTPUT;

    IF @Page < 1 SET @Page = 1;
    IF @Page > 10000 SET @Page = 10000;
    IF @PageSize < 1 SET @PageSize = 25;
    IF @PageSize > 100 SET @PageSize = 100;

    SELECT p.ProductId, p.CategoryId, c.Name AS CategoryName, p.Name, p.Price, p.StockQuantity, p.IsActive,
           p.UpdatedAtUtc, COUNT(*) OVER () AS TotalCount
    FROM dbo.Products p JOIN dbo.Categories c ON c.CategoryId = p.CategoryId
    WHERE (@IncludeInactive = 1 OR p.IsActive = 1)
    ORDER BY p.Name, p.ProductId
    OFFSET (@Page - 1) * @PageSize ROWS FETCH NEXT @PageSize ROWS ONLY;
END
GO

-- Returns: ProductId, CategoryId, Name, Description, Price, StockQuantity, ImageFileName, IsActive, RowVersion (0/1 row)
CREATE OR ALTER PROCEDURE [admin].usp_Product_Get
    @SessionIdHash BINARY(32),
    @ProductId     INT,
    @IpAddress     VARCHAR(45) = NULL
AS
BEGIN
    SET NOCOUNT ON;
    DECLARE @u UNIQUEIDENTIFIER, @r TINYINT;
    EXEC dbo.usp_Internal_ResolveSession @SessionIdHash = @SessionIdHash, @AllowedRoles = '2',
         @Resource = N'admin.usp_Product_Get', @IpAddress = @IpAddress, @UserId = @u OUTPUT, @RoleId = @r OUTPUT;

    SELECT ProductId, CategoryId, Name, Description, Price, StockQuantity, ImageFileName, IsActive, RowVersion
    FROM dbo.Products WHERE ProductId = @ProductId;
END
GO

/* @ImageFileName must be the server-generated name returned by the image upload service (never the
   client's file name). Returns: Result, ProductId */
CREATE OR ALTER PROCEDURE [admin].usp_Product_Create
    @SessionIdHash BINARY(32),
    @CategoryId    INT,
    @Name          NVARCHAR(150),
    @Description   NVARCHAR(2000),
    @Price         DECIMAL(10,2),
    @StockQuantity INT,
    @ImageFileName NVARCHAR(100) = NULL,
    @IpAddress     VARCHAR(45)   = NULL
AS
BEGIN
    SET NOCOUNT ON;
    SET XACT_ABORT ON;
    DECLARE @u UNIQUEIDENTIFIER, @r TINYINT, @new INT, @json NVARCHAR(MAX);
    EXEC dbo.usp_Internal_ResolveSession @SessionIdHash = @SessionIdHash, @AllowedRoles = '2',
         @Resource = N'admin.usp_Product_Create', @IpAddress = @IpAddress, @UserId = @u OUTPUT, @RoleId = @r OUTPUT;

    SET @Name = LTRIM(RTRIM(@Name));
    SET @Description = LTRIM(RTRIM(@Description));
    IF LEN(@Name) = 0 OR LEN(@Description) = 0 OR @Price IS NULL OR @Price <= 0 OR @Price > 1000000
       OR @StockQuantity IS NULL OR @StockQuantity < 0 OR @StockQuantity > 100000
        THROW 50400, N'Invalid product data', 1;
    IF @ImageFileName IS NOT NULL AND @ImageFileName NOT LIKE N'[0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f].%'
        THROW 50400, N'Invalid image file name', 1;

    IF NOT EXISTS (SELECT 1 FROM dbo.Categories WHERE CategoryId = @CategoryId)
    BEGIN
        SELECT 2 AS Result, CAST(NULL AS INT) AS ProductId;
        RETURN;
    END

    BEGIN TRANSACTION;
    INSERT dbo.Products (CategoryId, Name, Description, Price, StockQuantity, ImageFileName)
    VALUES (@CategoryId, @Name, @Description, @Price, @StockQuantity, @ImageFileName);
    SET @new = CONVERT(INT, SCOPE_IDENTITY());

    SELECT @json = (SELECT ProductId, CategoryId, Name, Price, StockQuantity, ImageFileName, IsActive
                    FROM dbo.Products WHERE ProductId = @new FOR JSON PATH, WITHOUT_ARRAY_WRAPPER);
    DECLARE @idText NVARCHAR(20) = CONVERT(NVARCHAR(20), @new);
    EXEC dbo.usp_Internal_LogAudit @ActorUserId = @u, @Action = 'ProductCreated', @EntityType = 'Product',
         @EntityId = @idText, @NewValueJson = @json, @IpAddress = @IpAddress;
    COMMIT TRANSACTION;

    SELECT 0 AS Result, @new AS ProductId;
END
GO

/* @ImageFileName: NULL keeps the current image; pass the new generated name to replace it.
   @RowVersion: the value read by admin.usp_Product_Get. Returns: Result */
CREATE OR ALTER PROCEDURE [admin].usp_Product_Update
    @SessionIdHash BINARY(32),
    @ProductId     INT,
    @CategoryId    INT,
    @Name          NVARCHAR(150),
    @Description   NVARCHAR(2000),
    @Price         DECIMAL(10,2),
    @StockQuantity INT,
    @ImageFileName NVARCHAR(100) = NULL,
    @RowVersion    BINARY(8),
    @IpAddress     VARCHAR(45)   = NULL
AS
BEGIN
    SET NOCOUNT ON;
    SET XACT_ABORT ON;
    DECLARE @u UNIQUEIDENTIFIER, @r TINYINT, @old NVARCHAR(MAX), @new NVARCHAR(MAX), @rows INT,
            @idText NVARCHAR(20) = CONVERT(NVARCHAR(20), @ProductId);
    EXEC dbo.usp_Internal_ResolveSession @SessionIdHash = @SessionIdHash, @AllowedRoles = '2',
         @Resource = N'admin.usp_Product_Update', @IpAddress = @IpAddress, @UserId = @u OUTPUT, @RoleId = @r OUTPUT;

    SET @Name = LTRIM(RTRIM(@Name));
    SET @Description = LTRIM(RTRIM(@Description));
    IF LEN(@Name) = 0 OR LEN(@Description) = 0 OR @Price IS NULL OR @Price <= 0 OR @Price > 1000000
       OR @StockQuantity IS NULL OR @StockQuantity < 0 OR @StockQuantity > 100000
        THROW 50400, N'Invalid product data', 1;

    IF NOT EXISTS (SELECT 1 FROM dbo.Categories WHERE CategoryId = @CategoryId)
    BEGIN
        SELECT 2 AS Result;
        RETURN;
    END

    BEGIN TRANSACTION;

    SELECT @old = (SELECT ProductId, CategoryId, Name, Price, StockQuantity, ImageFileName, IsActive
                   FROM dbo.Products WHERE ProductId = @ProductId FOR JSON PATH, WITHOUT_ARRAY_WRAPPER);
    IF @old IS NULL
    BEGIN
        ROLLBACK TRANSACTION;
        SELECT 1 AS Result;
        RETURN;
    END

    UPDATE dbo.Products
    SET CategoryId = @CategoryId, Name = @Name, Description = @Description, Price = @Price,
        StockQuantity = @StockQuantity, ImageFileName = ISNULL(@ImageFileName, ImageFileName),
        UpdatedAtUtc = SYSUTCDATETIME()
    WHERE ProductId = @ProductId AND RowVersion = @RowVersion;
    SET @rows = @@ROWCOUNT;

    IF @rows = 0
    BEGIN
        ROLLBACK TRANSACTION;
        THROW 50409, N'Product was changed by someone else', 1;
    END

    SELECT @new = (SELECT ProductId, CategoryId, Name, Price, StockQuantity, ImageFileName, IsActive
                   FROM dbo.Products WHERE ProductId = @ProductId FOR JSON PATH, WITHOUT_ARRAY_WRAPPER);
    EXEC dbo.usp_Internal_LogAudit @ActorUserId = @u, @Action = 'ProductUpdated', @EntityType = 'Product',
         @EntityId = @idText, @OldValueJson = @old, @NewValueJson = @new, @IpAddress = @IpAddress;
    COMMIT TRANSACTION;
    SELECT 0 AS Result;
END
GO

/* Soft delete: the row stays so old orders keep their product reference; it simply disappears from the shop
   and from all carts. Needs a re-authentication within the last 5 minutes. */
CREATE OR ALTER PROCEDURE [admin].usp_Product_Delete
    @SessionIdHash BINARY(32),
    @ProductId     INT,
    @IpAddress     VARCHAR(45) = NULL
AS
BEGIN
    SET NOCOUNT ON;
    SET XACT_ABORT ON;
    DECLARE @u UNIQUEIDENTIFIER, @r TINYINT, @old NVARCHAR(MAX), @rows INT,
            @idText NVARCHAR(20) = CONVERT(NVARCHAR(20), @ProductId);
    EXEC dbo.usp_Internal_ResolveSession @SessionIdHash = @SessionIdHash, @AllowedRoles = '2',
         @Resource = N'admin.usp_Product_Delete', @MaxReauthAgeMinutes = 5, @IpAddress = @IpAddress,
         @UserId = @u OUTPUT, @RoleId = @r OUTPUT;

    BEGIN TRANSACTION;
    SELECT @old = (SELECT ProductId, Name, Price, StockQuantity, IsActive
                   FROM dbo.Products WHERE ProductId = @ProductId FOR JSON PATH, WITHOUT_ARRAY_WRAPPER);

    UPDATE dbo.Products SET IsActive = 0, UpdatedAtUtc = SYSUTCDATETIME() WHERE ProductId = @ProductId AND IsActive = 1;
    SET @rows = @@ROWCOUNT;

    IF @rows = 1
    BEGIN
        DELETE FROM dbo.CartItems WHERE ProductId = @ProductId;
        EXEC dbo.usp_Internal_LogAudit @ActorUserId = @u, @Action = 'ProductDeleted', @EntityType = 'Product',
             @EntityId = @idText, @OldValueJson = @old, @IpAddress = @IpAddress;
    END
    COMMIT TRANSACTION;
    SELECT CASE WHEN @rows = 1 THEN 0 ELSE 1 END AS Result;
END
GO

CREATE OR ALTER PROCEDURE [admin].usp_Product_Restore
    @SessionIdHash BINARY(32),
    @ProductId     INT,
    @IpAddress     VARCHAR(45) = NULL
AS
BEGIN
    SET NOCOUNT ON;
    SET XACT_ABORT ON;
    DECLARE @u UNIQUEIDENTIFIER, @r TINYINT, @rows INT, @idText NVARCHAR(20) = CONVERT(NVARCHAR(20), @ProductId);
    EXEC dbo.usp_Internal_ResolveSession @SessionIdHash = @SessionIdHash, @AllowedRoles = '2',
         @Resource = N'admin.usp_Product_Restore', @IpAddress = @IpAddress, @UserId = @u OUTPUT, @RoleId = @r OUTPUT;

    BEGIN TRANSACTION;
    UPDATE dbo.Products SET IsActive = 1, UpdatedAtUtc = SYSUTCDATETIME() WHERE ProductId = @ProductId AND IsActive = 0;
    SET @rows = @@ROWCOUNT;
    IF @rows = 1
        EXEC dbo.usp_Internal_LogAudit @ActorUserId = @u, @Action = 'ProductRestored', @EntityType = 'Product',
             @EntityId = @idText, @IpAddress = @IpAddress;
    COMMIT TRANSACTION;
    SELECT CASE WHEN @rows = 1 THEN 0 ELSE 1 END AS Result;
END
GO

-- Categories for the admin product form (same data as app.usp_Category_List, but behind the admin gate)
CREATE OR ALTER PROCEDURE [admin].usp_Category_List
    @SessionIdHash BINARY(32),
    @IpAddress     VARCHAR(45) = NULL
AS
BEGIN
    SET NOCOUNT ON;
    DECLARE @u UNIQUEIDENTIFIER, @r TINYINT;
    EXEC dbo.usp_Internal_ResolveSession @SessionIdHash = @SessionIdHash, @AllowedRoles = '2',
         @Resource = N'admin.usp_Category_List', @IpAddress = @IpAddress, @UserId = @u OUTPUT, @RoleId = @r OUTPUT;
    SELECT CategoryId, Name FROM dbo.Categories ORDER BY Name;
END
GO

/* ---------------------------------------------------------------------
   US8/US9 - Customer support: an Admin may look at ANY order. Every lookup is audited
   ('OrderViewedByAdmin') so support access is accountable. Customers never reach this procedure.
   Returns (0 rows when the order does not exist): OrderId, CustomerName, CreatedAtUtc, Status, PaidAtUtc,
     TotalAmount, Currency, ShipName, ShipAddressLine, ShipPostalCode, ShipCity, ShipCountry,
     ProductId, ProductName, UnitPrice, Quantity
   --------------------------------------------------------------------- */
CREATE OR ALTER PROCEDURE [admin].usp_Order_GetForSupport
    @SessionIdHash BINARY(32),
    @OrderId       UNIQUEIDENTIFIER,
    @IpAddress     VARCHAR(45) = NULL
AS
BEGIN
    SET NOCOUNT ON;
    SET XACT_ABORT ON;
    DECLARE @u UNIQUEIDENTIFIER, @r TINYINT, @orderText NVARCHAR(100) = CONVERT(NVARCHAR(100), @OrderId);
    EXEC dbo.usp_Internal_ResolveSession @SessionIdHash = @SessionIdHash, @AllowedRoles = '2',
         @Resource = N'admin.usp_Order_GetForSupport', @IpAddress = @IpAddress, @UserId = @u OUTPUT, @RoleId = @r OUTPUT;

    IF NOT EXISTS (SELECT 1 FROM dbo.Orders WHERE OrderId = @OrderId) RETURN;

    EXEC dbo.usp_Internal_LogAudit @ActorUserId = @u, @Action = 'OrderViewedByAdmin', @EntityType = 'Order',
         @EntityId = @orderText, @IpAddress = @IpAddress;

    SELECT o.OrderId, us.DisplayName AS CustomerName, o.CreatedAtUtc, o.Status, o.PaidAtUtc, o.TotalAmount, o.Currency,
           o.ShipName, o.ShipAddressLine, o.ShipPostalCode, o.ShipCity, o.ShipCountry,
           oi.ProductId, oi.ProductName, oi.UnitPrice, oi.Quantity
    FROM dbo.Orders o
    JOIN dbo.Users us ON us.UserId = o.UserId
    JOIN dbo.OrderItems oi ON oi.OrderId = o.OrderId
    WHERE o.OrderId = @OrderId
    ORDER BY oi.ProductName;
END
GO

/* =====================================================================
   US10 - Log viewing (SysAdmin only). Viewing the logs is itself audited.
   ===================================================================== */
/* Filters are all optional. @From/@To are UTC. Returns: EventId, OccurredAtUtc, EventType, Severity, UserId,
   IpAddress, Resource, Details, CorrelationId, TotalCount (newest first, max 200 per page) */
CREATE OR ALTER PROCEDURE sysadmin.usp_SecurityEvent_Search
    @SessionIdHash BINARY(32),
    @FromUtc       DATETIME2(3) = NULL,
    @ToUtc         DATETIME2(3) = NULL,
    @EventType     VARCHAR(50)  = NULL,
    @Severity      VARCHAR(10)  = NULL,
    @FilterUserId  UNIQUEIDENTIFIER = NULL,
    @FilterIp      VARCHAR(45)  = NULL,
    @Page          INT = 1,
    @PageSize      INT = 50,
    @IpAddress     VARCHAR(45)  = NULL
AS
BEGIN
    SET NOCOUNT ON;
    DECLARE @u UNIQUEIDENTIFIER, @r TINYINT;
    EXEC dbo.usp_Internal_ResolveSession @SessionIdHash = @SessionIdHash, @AllowedRoles = '3',
         @Resource = N'sysadmin.usp_SecurityEvent_Search', @IpAddress = @IpAddress, @UserId = @u OUTPUT, @RoleId = @r OUTPUT;

    IF @Page < 1 SET @Page = 1;
    IF @Page > 10000 SET @Page = 10000;
    IF @PageSize < 1 SET @PageSize = 50;
    IF @PageSize > 200 SET @PageSize = 200;

    EXEC dbo.usp_Internal_LogAudit @ActorUserId = @u, @Action = 'LogViewed', @EntityType = 'SecurityEvents', @IpAddress = @IpAddress;

    SELECT EventId, OccurredAtUtc, EventType, Severity, UserId, IpAddress, Resource, Details, CorrelationId,
           COUNT(*) OVER () AS TotalCount
    FROM dbo.SecurityEvents
    WHERE (@FromUtc IS NULL OR OccurredAtUtc >= @FromUtc)
      AND (@ToUtc IS NULL OR OccurredAtUtc < @ToUtc)
      AND (@EventType IS NULL OR EventType = @EventType)
      AND (@Severity IS NULL OR Severity = @Severity)
      AND (@FilterUserId IS NULL OR UserId = @FilterUserId)
      AND (@FilterIp IS NULL OR IpAddress = @FilterIp)
    ORDER BY EventId DESC
    OFFSET (@Page - 1) * @PageSize ROWS FETCH NEXT @PageSize ROWS ONLY;
END
GO

-- Returns: AuditId, OccurredAtUtc, ActorUserId, Action, EntityType, EntityId, OldValueJson, NewValueJson, IpAddress, TotalCount
CREATE OR ALTER PROCEDURE sysadmin.usp_AuditLog_Search
    @SessionIdHash BINARY(32),
    @FromUtc       DATETIME2(3) = NULL,
    @ToUtc         DATETIME2(3) = NULL,
    @Action        VARCHAR(50)  = NULL,
    @EntityType    VARCHAR(50)  = NULL,
    @ActorFilter   UNIQUEIDENTIFIER = NULL,
    @Page          INT = 1,
    @PageSize      INT = 50,
    @IpAddress     VARCHAR(45)  = NULL
AS
BEGIN
    SET NOCOUNT ON;
    DECLARE @u UNIQUEIDENTIFIER, @r TINYINT;
    EXEC dbo.usp_Internal_ResolveSession @SessionIdHash = @SessionIdHash, @AllowedRoles = '3',
         @Resource = N'sysadmin.usp_AuditLog_Search', @IpAddress = @IpAddress, @UserId = @u OUTPUT, @RoleId = @r OUTPUT;

    IF @Page < 1 SET @Page = 1;
    IF @Page > 10000 SET @Page = 10000;
    IF @PageSize < 1 SET @PageSize = 50;
    IF @PageSize > 200 SET @PageSize = 200;

    EXEC dbo.usp_Internal_LogAudit @ActorUserId = @u, @Action = 'LogViewed', @EntityType = 'AuditLog', @IpAddress = @IpAddress;

    SELECT AuditId, OccurredAtUtc, ActorUserId, Action, EntityType, EntityId, OldValueJson, NewValueJson, IpAddress,
           COUNT(*) OVER () AS TotalCount
    FROM dbo.AuditLog
    WHERE (@FromUtc IS NULL OR OccurredAtUtc >= @FromUtc)
      AND (@ToUtc IS NULL OR OccurredAtUtc < @ToUtc)
      AND (@Action IS NULL OR Action = @Action)
      AND (@EntityType IS NULL OR EntityType = @EntityType)
      AND (@ActorFilter IS NULL OR ActorUserId = @ActorFilter)
    ORDER BY AuditId DESC
    OFFSET (@Page - 1) * @PageSize ROWS FETCH NEXT @PageSize ROWS ONLY;
END
GO

/* Alerts (US10): computed from the security log over the last @Hours hours (default 24).
     BruteForceIp     more than 10 failed logins from one IP inside a 5-minute bucket
     AccessDeniedBurst more than 5 AccessDenied for one user inside a 1-minute bucket
     AdminOffHours    a successful login of an Admin/SysAdmin outside 06:00-20:00 Danish time
   Returns: AlertType, Subject, EventCount, FirstAtUtc, LastAtUtc */
CREATE OR ALTER PROCEDURE sysadmin.usp_Alerts_Get
    @SessionIdHash BINARY(32),
    @Hours         INT = 24,
    @IpAddress     VARCHAR(45) = NULL
AS
BEGIN
    SET NOCOUNT ON;
    DECLARE @u UNIQUEIDENTIFIER, @r TINYINT;
    EXEC dbo.usp_Internal_ResolveSession @SessionIdHash = @SessionIdHash, @AllowedRoles = '3',
         @Resource = N'sysadmin.usp_Alerts_Get', @IpAddress = @IpAddress, @UserId = @u OUTPUT, @RoleId = @r OUTPUT;

    IF @Hours < 1 SET @Hours = 24;
    IF @Hours > 720 SET @Hours = 720;
    DECLARE @since DATETIME2(3) = DATEADD(HOUR, -@Hours, SYSUTCDATETIME());

    SELECT AlertType, Subject, EventCount, FirstAtUtc, LastAtUtc FROM (
        SELECT 'BruteForceIp' AS AlertType, IpAddress AS Subject, COUNT(*) AS EventCount,
               MIN(OccurredAtUtc) AS FirstAtUtc, MAX(OccurredAtUtc) AS LastAtUtc
        FROM dbo.SecurityEvents
        WHERE EventType = 'LoginFailed' AND OccurredAtUtc >= @since AND IpAddress IS NOT NULL
        GROUP BY IpAddress, DATEDIFF(MINUTE, '2000-01-01', OccurredAtUtc) / 5
        HAVING COUNT(*) > 10

        UNION ALL
        SELECT 'AccessDeniedBurst', CONVERT(VARCHAR(36), UserId), COUNT(*), MIN(OccurredAtUtc), MAX(OccurredAtUtc)
        FROM dbo.SecurityEvents
        WHERE EventType = 'AccessDenied' AND OccurredAtUtc >= @since AND UserId IS NOT NULL
        GROUP BY UserId, DATEDIFF(MINUTE, '2000-01-01', OccurredAtUtc)
        HAVING COUNT(*) > 5

        UNION ALL
        SELECT 'AdminOffHours', CONVERT(VARCHAR(36), e.UserId), COUNT(*), MIN(e.OccurredAtUtc), MAX(e.OccurredAtUtc)
        FROM dbo.SecurityEvents e
        JOIN dbo.Users us ON us.UserId = e.UserId AND us.RoleId >= 2
        WHERE e.EventType = 'LoginSuccess' AND e.OccurredAtUtc >= @since
          AND DATEPART(HOUR, CONVERT(DATETIME2(0), (e.OccurredAtUtc AT TIME ZONE 'UTC') AT TIME ZONE 'Central European Standard Time')) NOT BETWEEN 6 AND 19
        GROUP BY e.UserId
    ) a
    ORDER BY LastAtUtc DESC;
END
GO

/* Integrity check of the hash chains (tamper evidence). A row is "broken" when
     (a) its stored RowHash does not match the recomputed hash of its content (row was edited), or
     (b) its PrevHash does not equal the RowHash of the previous chained row (a row was deleted/inserted).
   The first remaining row must link to the purge anchor (dbo.LogAnchors) or to 32 zero bytes.
   @LogName: 'SecurityEvents' | 'AuditLog'.   Returns: LogName, RowsChecked, BrokenRows, FirstBrokenId (1 row) */
CREATE OR ALTER PROCEDURE sysadmin.usp_Log_VerifyChain
    @SessionIdHash BINARY(32),
    @LogName       VARCHAR(30),
    @IpAddress     VARCHAR(45) = NULL
AS
BEGIN
    SET NOCOUNT ON;
    DECLARE @u UNIQUEIDENTIFIER, @r TINYINT, @first BINARY(32), @checked BIGINT, @broken BIGINT, @firstBroken BIGINT;
    EXEC dbo.usp_Internal_ResolveSession @SessionIdHash = @SessionIdHash, @AllowedRoles = '3',
         @Resource = N'sysadmin.usp_Log_VerifyChain', @IpAddress = @IpAddress, @UserId = @u OUTPUT, @RoleId = @r OUTPUT;

    IF @LogName NOT IN ('SecurityEvents', 'AuditLog') THROW 50400, N'Unknown log name', 1;

    SELECT @first = LastPurgedHash FROM dbo.LogAnchors WHERE LogName = @LogName;
    IF @first IS NULL SET @first = CONVERT(BINARY(32), REPLICATE(CAST(0x00 AS VARBINARY(1)), 32));

    IF @LogName = 'SecurityEvents'
    BEGIN
        ;WITH c AS (
            SELECT EventId AS Id, RowHash, PrevHash,
                   LAG(RowHash) OVER (ORDER BY EventId) AS ExpectedPrev,
                   dbo.fn_SecurityEventHash(OccurredAtUtc, EventType, Severity, UserId, IpAddress, Resource, Details, CorrelationId, PrevHash) AS Recomputed,
                   ROW_NUMBER() OVER (ORDER BY EventId) AS rn
            FROM dbo.SecurityEvents WHERE RowHash IS NOT NULL)
        SELECT @checked = COUNT(*),
               @broken  = SUM(CASE WHEN RowHash <> Recomputed OR PrevHash <> ISNULL(ExpectedPrev, @first) THEN 1 ELSE 0 END),
               @firstBroken = MIN(CASE WHEN RowHash <> Recomputed OR PrevHash <> ISNULL(ExpectedPrev, @first) THEN Id END)
        FROM c;
    END
    ELSE
    BEGIN
        ;WITH c AS (
            SELECT AuditId AS Id, RowHash, PrevHash,
                   LAG(RowHash) OVER (ORDER BY AuditId) AS ExpectedPrev,
                   dbo.fn_AuditHash(OccurredAtUtc, ActorUserId, Action, EntityType, EntityId, OldValueJson, NewValueJson, IpAddress, CorrelationId, PrevHash) AS Recomputed
            FROM dbo.AuditLog WHERE RowHash IS NOT NULL)
        SELECT @checked = COUNT(*),
               @broken  = SUM(CASE WHEN RowHash <> Recomputed OR PrevHash <> ISNULL(ExpectedPrev, @first) THEN 1 ELSE 0 END),
               @firstBroken = MIN(CASE WHEN RowHash <> Recomputed OR PrevHash <> ISNULL(ExpectedPrev, @first) THEN Id END)
        FROM c;
    END

    EXEC dbo.usp_Internal_LogAudit @ActorUserId = @u, @Action = 'LogChainVerified', @EntityType = @LogName, @IpAddress = @IpAddress;
    SELECT @LogName AS LogName, ISNULL(@checked, 0) AS RowsChecked, ISNULL(@broken, 0) AS BrokenRows, @firstBroken AS FirstBrokenId;
END
GO
/* =====================================================================
   PART 5 - MAINTENANCE PROCEDURES, LOG IMMUTABILITY AND PERMISSIONS
   ===================================================================== */
USE Webshop;
GO

/* ---------------------------------------------------------------------
   Log immutability. The logs are append-only:
     * UPDATE is always rejected.
     * DELETE is rejected unless the retention job (maint.usp_Purge_All) has set SESSION_CONTEXT 'purge' = 1.
   The web app cannot touch these tables anyway (DENY on dbo); the triggers also stop a careless DBA.
   --------------------------------------------------------------------- */
CREATE OR ALTER TRIGGER dbo.trg_SecurityEvents_Immutable ON dbo.SecurityEvents AFTER UPDATE, DELETE
AS
BEGIN
    SET NOCOUNT ON;
    IF EXISTS (SELECT 1 FROM inserted) OR ISNULL(CONVERT(INT, SESSION_CONTEXT(N'purge')), 0) <> 1
    BEGIN
        IF @@TRANCOUNT > 0 ROLLBACK TRANSACTION;
        THROW 50403, N'SecurityEvents is append-only', 1;
    END
END
GO
CREATE OR ALTER TRIGGER dbo.trg_AuditLog_Immutable ON dbo.AuditLog AFTER UPDATE, DELETE
AS
BEGIN
    SET NOCOUNT ON;
    IF EXISTS (SELECT 1 FROM inserted) OR ISNULL(CONVERT(INT, SESSION_CONTEXT(N'purge')), 0) <> 1
    BEGIN
        IF @@TRANCOUNT > 0 ROLLBACK TRANSACTION;
        THROW 50403, N'AuditLog is append-only', 1;
    END
END
GO

/* ---------------------------------------------------------------------
   maint.usp_Purge_All - retention job (run daily, e.g. SQL Agent, as [webshop_maint]).
     security log 90 days, audit log 2 years (GDPR storage limitation, requirement doc).
   Before deleting, the hash of the newest purged row is stored in dbo.LogAnchors so that
   sysadmin.usp_Log_VerifyChain can still verify the remaining chain.
   Also removes expired sessions/tokens/attempts/anonymous carts and releases expired unpaid orders.
   Returns: SecurityEventsPurged, AuditPurged, ExpiredOrdersReleased
   --------------------------------------------------------------------- */
CREATE OR ALTER PROCEDURE maint.usp_Purge_All
    @SecurityRetentionDays INT = 90,
    @AuditRetentionDays    INT = 730
AS
BEGIN
    SET NOCOUNT ON;
    SET XACT_ABORT ON;
    DECLARE @now DATETIME2(3) = SYSUTCDATETIME(), @id BIGINT, @hash BINARY(32), @sec INT = 0, @aud INT = 0, @exp INT = 0, @lock INT;

    IF @SecurityRetentionDays < 30 OR @AuditRetentionDays < 365 THROW 50400, N'Retention too short', 1;

    EXEC @exp = dbo.usp_Internal_ExpirePendingOrders @MaxAgeMinutes = 60;

    BEGIN TRANSACTION;
    EXEC sys.sp_set_session_context @key = N'purge', @value = 1;

    -- Security log
    EXEC @lock = sys.sp_getapplock @Resource = N'log-chain:SecurityEvents', @LockMode = N'Exclusive', @LockOwner = N'Transaction', @LockTimeout = 10000;
    IF @lock < 0 THROW 50500, N'Security log chain busy', 1;
    SELECT TOP (1) @id = EventId, @hash = RowHash FROM dbo.SecurityEvents
    WHERE OccurredAtUtc < DATEADD(DAY, -@SecurityRetentionDays, @now) AND RowHash IS NOT NULL ORDER BY EventId DESC;
    IF @id IS NOT NULL
    BEGIN
        MERGE dbo.LogAnchors AS t USING (SELECT 'SecurityEvents' AS LogName) s ON t.LogName = s.LogName
        WHEN MATCHED THEN UPDATE SET LastPurgedId = @id, LastPurgedHash = @hash, PurgedAtUtc = SYSUTCDATETIME()
        WHEN NOT MATCHED THEN INSERT (LogName, LastPurgedId, LastPurgedHash) VALUES ('SecurityEvents', @id, @hash);
        DELETE FROM dbo.SecurityEvents WHERE EventId <= @id;
        SET @sec = @@ROWCOUNT;
    END

    -- Audit log
    SET @id = NULL; SET @hash = NULL;
    EXEC @lock = sys.sp_getapplock @Resource = N'log-chain:AuditLog', @LockMode = N'Exclusive', @LockOwner = N'Transaction', @LockTimeout = 10000;
    IF @lock < 0 THROW 50500, N'Audit log chain busy', 1;
    SELECT TOP (1) @id = AuditId, @hash = RowHash FROM dbo.AuditLog
    WHERE OccurredAtUtc < DATEADD(DAY, -@AuditRetentionDays, @now) AND RowHash IS NOT NULL ORDER BY AuditId DESC;
    IF @id IS NOT NULL
    BEGIN
        MERGE dbo.LogAnchors AS t USING (SELECT 'AuditLog' AS LogName) s ON t.LogName = s.LogName
        WHEN MATCHED THEN UPDATE SET LastPurgedId = @id, LastPurgedHash = @hash, PurgedAtUtc = SYSUTCDATETIME()
        WHEN NOT MATCHED THEN INSERT (LogName, LastPurgedId, LastPurgedHash) VALUES ('AuditLog', @id, @hash);
        DELETE FROM dbo.AuditLog WHERE AuditId <= @id;
        SET @aud = @@ROWCOUNT;
    END

    EXEC sys.sp_set_session_context @key = N'purge', @value = 0;

    -- Operational clean-up (no hash chain involved)
    DELETE FROM dbo.Sessions WHERE AbsoluteExpiryUtc < DATEADD(DAY, -7, @now) OR RevokedAtUtc < DATEADD(DAY, -7, @now);
    DELETE FROM dbo.UserTokens WHERE ExpiresAtUtc < DATEADD(DAY, -7, @now);
    DELETE FROM dbo.LoginAttempts WHERE AttemptedAtUtc < DATEADD(DAY, -2, @now);
    DELETE FROM dbo.Carts WHERE UserId IS NULL AND UpdatedAtUtc < DATEADD(DAY, -30, @now);
    DELETE FROM dbo.KnownDevices WHERE LastSeenUtc < DATEADD(DAY, -180, @now);
    COMMIT TRANSACTION;

    SELECT @sec AS SecurityEventsPurged, @aud AS AuditPurged, ISNULL(@exp, 0) AS ExpiredOrdersReleased;
END
GO

/* ---------------------------------------------------------------------
   maint.usp_Seed_PrivilegedUser - the ONLY way to create an Admin / SysAdmin (there is no registration path
   for privileged roles). Run by a DBA / the admin-seed CLI with an Argon2id hash produced by the app.
   The account starts with MFA OFF; the application forces MFA enrolment at the first login (mandatory for
   RoleId >= 2). Re-running for an existing e-mail does NOT change its role (use a DBA UPDATE, which is logged).
   --------------------------------------------------------------------- */
CREATE OR ALTER PROCEDURE maint.usp_Seed_PrivilegedUser
    @Email        NVARCHAR(254),
    @DisplayName  NVARCHAR(100),
    @PasswordHash NVARCHAR(255),
    @RoleId       TINYINT
AS
BEGIN
    SET NOCOUNT ON;
    SET XACT_ABORT ON;
    SET @Email = LOWER(LTRIM(RTRIM(@Email)));
    IF @RoleId NOT IN (2, 3) THROW 50400, N'RoleId must be 2 (Admin) or 3 (SysAdmin)', 1;

    IF EXISTS (SELECT 1 FROM dbo.Users WHERE Email = @Email)
    BEGIN
        SELECT CAST(0 AS BIT) AS Created;
        RETURN;
    END

    BEGIN TRANSACTION;
    INSERT dbo.Users (Email, DisplayName, PasswordHash, RoleId, EmailConfirmed, PrivacyConsentVersion, PrivacyConsentAtUtc)
    VALUES (@Email, @DisplayName, @PasswordHash, @RoleId, 1, N'staff', SYSUTCDATETIME());
    EXEC dbo.usp_Internal_LogSecurityEvent @EventType = 'PrivilegedUserSeeded', @Severity = 'Critical',
         @Resource = N'maint.usp_Seed_PrivilegedUser', @Details = N'privileged account created by DBA/CLI';
    COMMIT TRANSACTION;
    SELECT CAST(1 AS BIT) AS Created;
END
GO

/* ---------------------------------------------------------------------
   PERMISSIONS (principle of least privilege)
   CHANGE THE PASSWORDS BELOW before running outside a local sandbox, and keep the real ones in
   user-secrets / a vault, never in source control.
     webshop_app       web application: EXECUTE on app, admin, sysadmin. DENIED on dbo (tables + internals).
     webshop_logreader optional read-only reporting login for the two log tables.
     webshop_maint     retention job / admin seeding: EXECUTE on maint only.
   Why DENY on dbo still lets the procedures work: ownership chaining. A procedure in [app] and the table in
   [dbo] have the same owner (dbo), so SQL Server checks only the EXECUTE permission on the procedure.
   --------------------------------------------------------------------- */
USE master;
GO
IF NOT EXISTS (SELECT 1 FROM sys.server_principals WHERE name = N'webshop_app')
    CREATE LOGIN webshop_app WITH PASSWORD = N'CHANGE-ME-App-4f9a!Qz7', CHECK_POLICY = ON, DEFAULT_DATABASE = Webshop;
IF NOT EXISTS (SELECT 1 FROM sys.server_principals WHERE name = N'webshop_logreader')
    CREATE LOGIN webshop_logreader WITH PASSWORD = N'CHANGE-ME-Log-81bd!Kp3', CHECK_POLICY = ON, DEFAULT_DATABASE = Webshop;
IF NOT EXISTS (SELECT 1 FROM sys.server_principals WHERE name = N'webshop_maint')
    CREATE LOGIN webshop_maint WITH PASSWORD = N'CHANGE-ME-Mnt-27ce!Rw5', CHECK_POLICY = ON, DEFAULT_DATABASE = Webshop;
GO
USE Webshop;
GO
IF USER_ID(N'webshop_app')       IS NULL CREATE USER webshop_app       FOR LOGIN webshop_app;
IF USER_ID(N'webshop_logreader') IS NULL CREATE USER webshop_logreader FOR LOGIN webshop_logreader;
IF USER_ID(N'webshop_maint')     IS NULL CREATE USER webshop_maint     FOR LOGIN webshop_maint;
GO
GRANT EXECUTE ON SCHEMA::app      TO webshop_app;
GRANT EXECUTE ON SCHEMA::[admin]  TO webshop_app;
GRANT EXECUTE ON SCHEMA::sysadmin TO webshop_app;
DENY  SELECT, INSERT, UPDATE, DELETE, EXECUTE, ALTER, REFERENCES ON SCHEMA::dbo TO webshop_app;
DENY  EXECUTE ON SCHEMA::maint TO webshop_app;

GRANT SELECT ON dbo.SecurityEvents TO webshop_logreader;
GRANT SELECT ON dbo.AuditLog       TO webshop_logreader;

GRANT EXECUTE ON SCHEMA::maint TO webshop_maint;
DENY  SELECT, INSERT, UPDATE, DELETE ON SCHEMA::dbo TO webshop_maint;
GO

PRINT N'Webshop database script finished.';
GO
