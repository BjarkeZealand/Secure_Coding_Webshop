/* =====================================================================
   Webshop – SQL Server schema (ingen ORM, kun parameteriserede queries)
   Køres i SSMS / sqlcmd som en bruger med rettigheder til at oprette
   databaser, logins og brugere (fx sa lokalt).
   ===================================================================== */

IF DB_ID(N'Webshop') IS NULL
    CREATE DATABASE Webshop COLLATE Danish_Norwegian_CI_AS;
GO
USE Webshop;
GO

/* ---------------------------------------------------------------------
   1. RBAC: roller
   --------------------------------------------------------------------- */
CREATE TABLE dbo.Roles (
    RoleId   TINYINT       NOT NULL CONSTRAINT PK_Roles PRIMARY KEY,
    Name     NVARCHAR(30)  NOT NULL CONSTRAINT UQ_Roles_Name UNIQUE
);
INSERT INTO dbo.Roles (RoleId, Name) VALUES (1, N'Customer'), (2, N'Admin'), (3, N'SysAdmin');
GO

/* ---------------------------------------------------------------------
   2. Brugere (user story 1, 2, 6, 11)
   PasswordHash: Argon2id-streng (inkl. salt og parametre) – aldrig klartekst
   MfaSecret: gemmes krypteret af applikationen (fx Data Protection API)
   --------------------------------------------------------------------- */
CREATE TABLE dbo.Users (
    UserId                 UNIQUEIDENTIFIER NOT NULL CONSTRAINT PK_Users PRIMARY KEY DEFAULT NEWSEQUENTIALID(),
    Email                  NVARCHAR(254)    NOT NULL,
    DisplayName            NVARCHAR(100)    NOT NULL,
    PasswordHash           NVARCHAR(255)    NOT NULL,
    PasswordChangedAtUtc   DATETIME2(0)     NOT NULL CONSTRAINT DF_Users_PwChanged DEFAULT SYSUTCDATETIME(),
    RoleId                 TINYINT          NOT NULL CONSTRAINT DF_Users_Role DEFAULT 1
                           CONSTRAINT FK_Users_Roles REFERENCES dbo.Roles(RoleId),
    EmailConfirmed         BIT              NOT NULL CONSTRAINT DF_Users_EmailConf DEFAULT 0,
    MfaEnabled             BIT              NOT NULL CONSTRAINT DF_Users_MfaEnabled DEFAULT 0,
    MfaSecretEncrypted     VARBINARY(512)   NULL,
    FailedLoginCount       INT              NOT NULL CONSTRAINT DF_Users_Failed DEFAULT 0,
    LockoutEndUtc          DATETIME2(0)     NULL,
    PrivacyConsentVersion  NVARCHAR(20)     NOT NULL,
    PrivacyConsentAtUtc    DATETIME2(0)     NOT NULL,
    CreatedAtUtc           DATETIME2(0)     NOT NULL CONSTRAINT DF_Users_Created DEFAULT SYSUTCDATETIME(),
    IsDeleted              BIT              NOT NULL CONSTRAINT DF_Users_Deleted DEFAULT 0,  -- GDPR: anonymisering
    CONSTRAINT CK_Users_Email CHECK (Email LIKE N'%_@_%._%')
);
-- Unik e-mail håndhæves i databasen (ikke kun i koden)
CREATE UNIQUE INDEX UX_Users_Email ON dbo.Users (Email);
GO

/* Engangs-tokens: e-mailbekræftelse og nulstilling af password.
   Kun SHA-256-hash af tokenet gemmes. */
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
GO

/* MFA backupkoder (hashet, engangsbrug) */
CREATE TABLE dbo.MfaBackupCodes (
    BackupCodeId BIGINT IDENTITY(1,1) NOT NULL CONSTRAINT PK_MfaBackupCodes PRIMARY KEY,
    UserId       UNIQUEIDENTIFIER NOT NULL CONSTRAINT FK_MfaBackup_Users REFERENCES dbo.Users(UserId) ON DELETE CASCADE,
    CodeHash     BINARY(32)       NOT NULL,
    UsedAtUtc    DATETIME2(0)     NULL
);
CREATE INDEX IX_MfaBackupCodes_User ON dbo.MfaBackupCodes (UserId);
GO

/* ---------------------------------------------------------------------
   3. Server-side sessioner (user story 2) – kan tilbagekaldes
   SessionIdHash = SHA-256 af session-id i cookien (selve id'et gemmes ikke)
   --------------------------------------------------------------------- */
CREATE TABLE dbo.Sessions (
    SessionIdHash   BINARY(32)       NOT NULL CONSTRAINT PK_Sessions PRIMARY KEY,
    UserId          UNIQUEIDENTIFIER NOT NULL CONSTRAINT FK_Sessions_Users REFERENCES dbo.Users(UserId) ON DELETE CASCADE,
    CreatedAtUtc    DATETIME2(0)     NOT NULL CONSTRAINT DF_Sessions_Created DEFAULT SYSUTCDATETIME(),
    LastSeenAtUtc   DATETIME2(0)     NOT NULL CONSTRAINT DF_Sessions_LastSeen DEFAULT SYSUTCDATETIME(),
    AbsoluteExpiryUtc DATETIME2(0)   NOT NULL,
    RevokedAtUtc    DATETIME2(0)     NULL,
    IpAddress       VARCHAR(45)      NULL,
    UserAgent       NVARCHAR(300)    NULL
);
CREATE INDEX IX_Sessions_User ON dbo.Sessions (UserId);
GO

/* Loginforsøg til rate-limiting pr. e-mail og IP (user story 2) */
CREATE TABLE dbo.LoginAttempts (
    AttemptId    BIGINT IDENTITY(1,1) NOT NULL CONSTRAINT PK_LoginAttempts PRIMARY KEY,
    EmailHash    BINARY(32)   NULL,           -- SHA-256 af normaliseret e-mail (ingen klartekst)
    IpAddress    VARCHAR(45)  NOT NULL,
    Succeeded    BIT          NOT NULL,
    AttemptedAtUtc DATETIME2(0) NOT NULL CONSTRAINT DF_LoginAttempts_At DEFAULT SYSUTCDATETIME()
);
CREATE INDEX IX_LoginAttempts_Ip    ON dbo.LoginAttempts (IpAddress, AttemptedAtUtc);
CREATE INDEX IX_LoginAttempts_Email ON dbo.LoginAttempts (EmailHash, AttemptedAtUtc);
GO

/* ---------------------------------------------------------------------
   4. Produkter (user story 3, 7, 9)
   --------------------------------------------------------------------- */
CREATE TABLE dbo.Categories (
    CategoryId INT IDENTITY(1,1) NOT NULL CONSTRAINT PK_Categories PRIMARY KEY,
    Name       NVARCHAR(100) NOT NULL CONSTRAINT UQ_Categories_Name UNIQUE
);
GO

CREATE TABLE dbo.Products (
    ProductId      INT IDENTITY(1,1) NOT NULL CONSTRAINT PK_Products PRIMARY KEY,
    CategoryId     INT           NOT NULL CONSTRAINT FK_Products_Categories REFERENCES dbo.Categories(CategoryId),
    Name           NVARCHAR(150) NOT NULL,
    Description    NVARCHAR(2000) NOT NULL,
    Price          DECIMAL(10,2) NOT NULL CONSTRAINT CK_Products_Price CHECK (Price > 0 AND Price <= 1000000),
    StockQuantity  INT           NOT NULL CONSTRAINT CK_Products_Stock CHECK (StockQuantity BETWEEN 0 AND 100000),
    ImageFileName  NVARCHAR(100) NULL,        -- genereret GUID-filnavn, filen ligger uden for webroot
    IsActive       BIT           NOT NULL CONSTRAINT DF_Products_Active DEFAULT 1,   -- soft delete
    CreatedAtUtc   DATETIME2(0)  NOT NULL CONSTRAINT DF_Products_Created DEFAULT SYSUTCDATETIME(),
    UpdatedAtUtc   DATETIME2(0)  NULL,
    RowVersion     ROWVERSION    -- optimistisk concurrency
);
CREATE INDEX IX_Products_Name     ON dbo.Products (Name) INCLUDE (Price, IsActive);
CREATE INDEX IX_Products_Category ON dbo.Products (CategoryId, IsActive);
GO

/* ---------------------------------------------------------------------
   5. Indkøbskurv (user story 4) – kun produkt-id og antal; pris slås op
   --------------------------------------------------------------------- */
CREATE TABLE dbo.Carts (
    CartId        UNIQUEIDENTIFIER NOT NULL CONSTRAINT PK_Carts PRIMARY KEY DEFAULT NEWID(),
    UserId        UNIQUEIDENTIFIER NULL CONSTRAINT FK_Carts_Users REFERENCES dbo.Users(UserId) ON DELETE CASCADE,
    AnonymousKeyHash BINARY(32)    NULL,      -- hash af tilfældig 128-bit cookieværdi for anonyme brugere
    CreatedAtUtc  DATETIME2(0)     NOT NULL CONSTRAINT DF_Carts_Created DEFAULT SYSUTCDATETIME(),
    UpdatedAtUtc  DATETIME2(0)     NOT NULL CONSTRAINT DF_Carts_Updated DEFAULT SYSUTCDATETIME(),
    CONSTRAINT CK_Carts_Owner CHECK ((UserId IS NOT NULL AND AnonymousKeyHash IS NULL)
                                  OR (UserId IS NULL AND AnonymousKeyHash IS NOT NULL))
);
CREATE UNIQUE INDEX UX_Carts_User ON dbo.Carts (UserId) WHERE UserId IS NOT NULL;
CREATE UNIQUE INDEX UX_Carts_Anon ON dbo.Carts (AnonymousKeyHash) WHERE AnonymousKeyHash IS NOT NULL;
GO

CREATE TABLE dbo.CartItems (
    CartId     UNIQUEIDENTIFIER NOT NULL CONSTRAINT FK_CartItems_Carts REFERENCES dbo.Carts(CartId) ON DELETE CASCADE,
    ProductId  INT              NOT NULL CONSTRAINT FK_CartItems_Products REFERENCES dbo.Products(ProductId),
    Quantity   INT              NOT NULL CONSTRAINT CK_CartItems_Qty CHECK (Quantity BETWEEN 1 AND 99),
    AddedAtUtc DATETIME2(0)     NOT NULL CONSTRAINT DF_CartItems_Added DEFAULT SYSUTCDATETIME(),
    CONSTRAINT PK_CartItems PRIMARY KEY (CartId, ProductId)
);
GO

/* ---------------------------------------------------------------------
   6. Ordrer og betaling (user story 5, 8)
   Ingen kortdata gemmes – kun betalingsudbyderens reference
   --------------------------------------------------------------------- */
CREATE TABLE dbo.Orders (
    OrderId            UNIQUEIDENTIFIER NOT NULL CONSTRAINT PK_Orders PRIMARY KEY DEFAULT NEWID(),
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
    IdempotencyKey     UNIQUEIDENTIFIER NOT NULL,   -- forhindrer dobbeltordre/dobbeltbetaling
    PaymentProviderRef NVARCHAR(100)    NULL,
    CreatedAtUtc       DATETIME2(0)     NOT NULL CONSTRAINT DF_Orders_Created DEFAULT SYSUTCDATETIME(),
    PaidAtUtc          DATETIME2(0)     NULL
);
CREATE UNIQUE INDEX UX_Orders_Idempotency ON dbo.Orders (IdempotencyKey);
CREATE INDEX IX_Orders_User ON dbo.Orders (UserId, CreatedAtUtc DESC);
GO

CREATE TABLE dbo.OrderItems (
    OrderId      UNIQUEIDENTIFIER NOT NULL CONSTRAINT FK_OrderItems_Orders REFERENCES dbo.Orders(OrderId) ON DELETE CASCADE,
    ProductId    INT              NOT NULL CONSTRAINT FK_OrderItems_Products REFERENCES dbo.Products(ProductId),
    ProductName  NVARCHAR(150)    NOT NULL,           -- snapshot
    UnitPrice    DECIMAL(10,2)    NOT NULL CONSTRAINT CK_OrderItems_Price CHECK (UnitPrice >= 0),  -- snapshot
    Quantity     INT              NOT NULL CONSTRAINT CK_OrderItems_Qty CHECK (Quantity BETWEEN 1 AND 99),
    CONSTRAINT PK_OrderItems PRIMARY KEY (OrderId, ProductId)
);
GO

/* Webhook-events fra betalingsudbyder (replay-beskyttelse: samme EventId kan kun behandles én gang) */
CREATE TABLE dbo.PaymentEvents (
    EventId        NVARCHAR(100)    NOT NULL CONSTRAINT PK_PaymentEvents PRIMARY KEY,
    OrderId        UNIQUEIDENTIFIER NULL CONSTRAINT FK_PaymentEvents_Orders REFERENCES dbo.Orders(OrderId),
    EventType      NVARCHAR(100)    NOT NULL,
    ReceivedAtUtc  DATETIME2(0)     NOT NULL CONSTRAINT DF_PaymentEvents_At DEFAULT SYSUTCDATETIME()
);
GO

/* ---------------------------------------------------------------------
   7. Audit og sikkerhedslog (user story 9, 10)
   Applikationen må kun INSERT (se rettigheder nedenfor)
   Log aldrig passwords, tokens, session-id eller kortdata
   --------------------------------------------------------------------- */
CREATE TABLE dbo.AuditLog (
    AuditId       BIGINT IDENTITY(1,1) NOT NULL CONSTRAINT PK_AuditLog PRIMARY KEY,
    OccurredAtUtc DATETIME2(3)     NOT NULL CONSTRAINT DF_AuditLog_At DEFAULT SYSUTCDATETIME(),
    ActorUserId   UNIQUEIDENTIFIER NULL,
    Action        VARCHAR(50)      NOT NULL,       -- fx ProductCreated, ProductUpdated, ProductDeleted, OrderViewedByAdmin
    EntityType    VARCHAR(50)      NOT NULL,
    EntityId      NVARCHAR(100)    NULL,
    OldValueJson  NVARCHAR(MAX)    NULL,
    NewValueJson  NVARCHAR(MAX)    NULL,
    IpAddress     VARCHAR(45)      NULL,
    CorrelationId UNIQUEIDENTIFIER NULL
);
CREATE INDEX IX_AuditLog_Actor ON dbo.AuditLog (ActorUserId, OccurredAtUtc);
GO

CREATE TABLE dbo.SecurityEvents (
    EventId       BIGINT IDENTITY(1,1) NOT NULL CONSTRAINT PK_SecurityEvents PRIMARY KEY,
    OccurredAtUtc DATETIME2(3)     NOT NULL CONSTRAINT DF_SecEvents_At DEFAULT SYSUTCDATETIME(),
    EventType     VARCHAR(50)      NOT NULL,       -- LoginSuccess, LoginFailed, AccountLocked, PasswordChanged, PasswordResetRequested, AccessDenied, ValidationFailed ...
    Severity      VARCHAR(10)      NOT NULL CONSTRAINT CK_SecEvents_Sev CHECK (Severity IN ('Info','Warning','Error','Critical')),
    UserId        UNIQUEIDENTIFIER NULL,
    IpAddress     VARCHAR(45)      NULL,
    Resource      NVARCHAR(200)    NULL,
    Details       NVARCHAR(1000)   NULL,           -- escapet/saniteret (ingen kontroltegn)
    CorrelationId UNIQUEIDENTIFIER NULL
);
CREATE INDEX IX_SecEvents_Time ON dbo.SecurityEvents (OccurredAtUtc DESC, EventType);
CREATE INDEX IX_SecEvents_Ip   ON dbo.SecurityEvents (IpAddress, OccurredAtUtc);
GO

/* ---------------------------------------------------------------------
   8. Seed-data (eksempel)
   Admin-brugeren oprettes via et engangsscript/CLI i applikationen, så
   hashen genereres med Argon2id – gem ALDRIG en klartekst-admin her.
   --------------------------------------------------------------------- */
INSERT INTO dbo.Categories (Name) VALUES (N'Elektronik'), (N'Bøger'), (N'Tøj');

INSERT INTO dbo.Products (CategoryId, Name, Description, Price, StockQuantity)
VALUES (1, N'Trådløse hovedtelefoner', N'Over-ear med støjreduktion.', 799.00, 25),
       (1, N'USB-C kabel 2 m',          N'Flettet kabel, 100 W.',        89.00, 200),
       (2, N'Secure Coding i praksis',  N'Introduktion til sikker udvikling.', 249.00, 40),
       (3, N'Hættetrøje',               N'100 % økologisk bomuld.',      399.00, 60);
GO

/* ---------------------------------------------------------------------
   9. Least privilege – databasebrugere (user story 9, 10, tværgående krav)
   SKIFT passwords! Gem dem i User Secrets / miljøvariabler, ikke i Git.
   --------------------------------------------------------------------- */
USE master;
GO
IF NOT EXISTS (SELECT 1 FROM sys.server_principals WHERE name = N'webshop_app')
    CREATE LOGIN webshop_app WITH PASSWORD = N'SKIFT-MIG-Lang-Tilfaeldig-Passphrase-1', CHECK_POLICY = ON;
IF NOT EXISTS (SELECT 1 FROM sys.server_principals WHERE name = N'webshop_logreader')
    CREATE LOGIN webshop_logreader WITH PASSWORD = N'SKIFT-MIG-Anden-Lang-Passphrase-2', CHECK_POLICY = ON;
GO
USE Webshop;
GO
CREATE USER webshop_app       FOR LOGIN webshop_app;
CREATE USER webshop_logreader FOR LOGIN webshop_logreader;
GO

-- Applikationen: kun nødvendige DML-rettigheder (ingen DDL, ingen DROP)
GRANT SELECT ON dbo.Roles       TO webshop_app;
GRANT SELECT, INSERT, UPDATE ON dbo.Users        TO webshop_app;
GRANT SELECT, INSERT, UPDATE ON dbo.UserTokens   TO webshop_app;
GRANT SELECT, INSERT, UPDATE ON dbo.MfaBackupCodes TO webshop_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON dbo.Sessions     TO webshop_app;
GRANT SELECT, INSERT, DELETE ON dbo.LoginAttempts TO webshop_app;  -- DELETE til oprydning af gamle rækker
GRANT SELECT ON dbo.Categories  TO webshop_app;
GRANT SELECT, INSERT, UPDATE ON dbo.Products     TO webshop_app;   -- ingen DELETE: soft delete via IsActive
GRANT SELECT, INSERT, UPDATE, DELETE ON dbo.Carts     TO webshop_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON dbo.CartItems TO webshop_app;
GRANT SELECT, INSERT, UPDATE ON dbo.Orders       TO webshop_app;
GRANT SELECT, INSERT         ON dbo.OrderItems   TO webshop_app;
GRANT SELECT, INSERT         ON dbo.PaymentEvents TO webshop_app;

-- Log: append-only for applikationen
GRANT INSERT ON dbo.AuditLog      TO webshop_app;
GRANT INSERT ON dbo.SecurityEvents TO webshop_app;
DENY  UPDATE, DELETE ON dbo.AuditLog       TO webshop_app;
DENY  UPDATE, DELETE ON dbo.SecurityEvents TO webshop_app;

-- SysAdmin-visning af logs: kun læseadgang
GRANT SELECT ON dbo.AuditLog       TO webshop_logreader;
GRANT SELECT ON dbo.SecurityEvents TO webshop_logreader;
GO

/* ---------------------------------------------------------------------
   10. Eksempel på parameteriserede queries (ADO.NET: SqlCommand + Parameters)
   ---------------------------------------------------------------------
   -- Søgning (user story 7); escape %, _ og [ i @term før kald, ESCAPE-tegn = '\'
   SELECT ProductId, Name, Price
   FROM dbo.Products
   WHERE IsActive = 1 AND Name LIKE @term ESCAPE N'\'
   ORDER BY Name
   OFFSET @offset ROWS FETCH NEXT @pageSize ROWS ONLY;

   -- Ordrehistorik med ejerskabstjek (user story 8)
   SELECT OrderId, Status, TotalAmount, CreatedAtUtc
   FROM dbo.Orders
   WHERE OrderId = @orderId AND UserId = @currentUserId;
   --------------------------------------------------------------------- */