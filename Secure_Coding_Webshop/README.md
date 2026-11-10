# Webshop – samlet projekt (US1–US11)

Jeg har ikke haft dotnet i mit miljø. Forvent en runde kompileringsfejl (manglende `using`, navne). Send dem til mig.
Databasescriptet `Webshop_Full.sql` er kørt af dig uden fejl.

## 0. Sådan bruges zip'en
Zip'en er nu et KOMPLET projekt (`Secure_Coding_Webshop.csproj`, net8.0), inklusive dine egne klasser, som jeg har gendannet fra vores samtale: connection factory, Argon2-hashing, adgangskodepolitik, mailkø, `ConfirmationToken`, `NewUser`, `AppSettings`, `LoggingUserRepo` og `Totp`. Hvis du sammenligner med dine originaler, så er dine originaler dem, der gælder.
Pak ud i en tom mappe, sæt hemmeligheder (se `SECRETS.md`), kør `Database/Webshop_Full.sql`, og kør `dotnet run`.
Jeg har tilføjet et minimalt `_Layout`, `_ViewImports`, forside, fejlside og CSS, som du kan erstatte med dine egne. `Resources/common-passwords.txt` er en lille startliste: udskift den med en rigtig liste (fx top 100.000 fra SecLists).
Ligger du i et eksisterende projekt, så sammenflet i stedet mappe for mappe og slet først dine gamle filer med samme klasser (`ForbiddenException`, gamle `BaseRepo`, `LoginRepo`, `LoginService`, `SessionAuth`, `UserRepo`, gamle Login/Mfa/Logout-sider).

## 1. Hvor ligger filerne
| Mappe/fil | Indhold |
|---|---|
| `Models/DbRuleException.cs` | **Erstatter** `ForbiddenException.cs` (slet den). Fejlkoder 50400–50409 |
| `Models/ShopModels.cs` | Alle records til US3–US11 |
| `Repo/BaseRepo.cs` | **Erstatter** din. Nyt: liste-helper, `ScalarInt/String`, timeout, `DbRuleException`, nye parameter-helpers |
| `Repo/Interfaces/IShopRepositories.cs` | 6 interfaces |
| `Repo/ProductRepo, CartRepo, OrderRepo, AccountRepo, AdminRepo, SysAdminRepo.cs` | Kun stored procedures |
| `Services/AccountService.cs` | Skift/glemt adgangskode, re-auth, MFA-tilmelding, backupkoder |
| `Services/PaymentServices.cs` | Mock-betaling, HMAC-webhook (`X-Signature: t=..,v1=..`), replay-grænse 5 min |
| `Services/ImageStorage.cs` | Upload (magic bytes, 2 MB, genereret navn, uden for wwwroot) |
| `Services/BreachedPasswords.cs` | HIBP k-anonymity + mønstertjek (tastatur, rækker, gentagelser) |
| `Services/WebHelpers.cs` | `ClientIp()`, anonym kurv-cookie, no-store filter, sikkerhedsheaders |
| `Pages/**` | Produkter, kurv, kasse, mock-betaling, ordrer, konto (skift/glemt/nulstil/reauth/MfaSetup/Privacy), Admin, SysAdmin |
| `wwwroot/js/password-meter.js` | Måler + forslag til adgangskode (kun hjælp, serveren håndhæver) |
| `Program.cs` | Din merged Program.cs med alt registreret |

## 1b. Tilføjet senere: UI til US1 og US2
`Pages/Account/`: `Register`, `ConfirmEmail` (POST-bekræftelse, så mail-scannere ikke bruger linket), `Login`, `Mfa` (login-trin), `Logout`, `Index` (min konto) samt `Pages/PrivacyPolicy.cshtml` (skabelon) og `Pages/Shared/_LoginPartial.cshtml` (indsæt `<partial name="_LoginPartial" />` i din `_Layout`).
`Services/PostLoginService.cs` fletter anonym kurv og sender "ny enhed"-mail efter login. `Repo/UserRepo.cs` er rettet til `app.usp_User_*`.
Namespace er nu `Secure_Coding_Webshop.Pages.Account` (de gamle `Webshop.Pages.Account`-filer skal slettes).

## 2. Ændringer i din eksisterende kode (vigtigt)
1. **`UserRepo`** (rettet fil ligger i zip): procedurerne er flyttet til schema `app`: `app.usp_User_Register` og `app.usp_User_ConfirmEmail`. Tjek parameternavnene mod SQL-scriptet (`@Email,@DisplayName,@PasswordHash,@PrivacyConsentVersion,@ConfirmTokenHash,@IpAddress,@Created OUT` og `@TokenHash,@IpAddress,@Confirmed OUT`). Hvis dine hed noget andet, ret dem i repoet.
2. ~~Login-siden skal flette kurv/sende ny-enhed-mail~~ Gjort af `PostLoginService`, som de nye Login- og Mfa-sider kalder.
5. **AdminOnly** er nu kun Admin (RBAC-matrix). SysAdmin har ikke adgang til produktstyring.
6. `ILoginRepository` bruges uændret. Gamle `ForbiddenException` → `DbRuleException`.

## 3. Konfiguration (user-secrets)
```
ConnectionStrings:Webshop   login webshop_app
DataProtection:KeyPath      sti uden for webroot
App:PublicBaseUrl, App:PrivacyPolicyVersion
Payment:WebhookSecret       mindst 32 tilfældige tegn
Uploads:Path                valgfri, ellers App_Data/product-images
```
Skift de tre `CHANGE-ME`-adgangskoder i SQL-scriptet.

## 4. Oprette en admin
Der findes ingen registreringsvej til Admin/SysAdmin. Kør (hash fra din `Argon2PasswordHashService`):
`EXEC maint.usp_Seed_PrivilegedUser @Email, @DisplayName, @PasswordHash, @RoleId` (2 = Admin, 3 = SysAdmin) som `webshop_maint` eller DBA.
Ved første login tvinges admin til `/Account/MfaSetup`. (Der er endnu ingen CLI; jeg kan lave en.)

## 5. Testmatrix (kort)
| US | Test | Forventet |
|---|---|---|
| 3 | `/Products` uden login | Liste, 12 pr. side, kun aktive |
| 3 | `?sort=;DROP` / `?p=-5` / `?q=%` | Falder tilbage til standard, ingen fejl, `%` er literal |
| 4 | Læg 100 stk i kurv | Afvist (max 99 / lager) |
| 4 | Ændr pris i formular | Ingen effekt, prisen findes ikke i formularen |
| 4 | Anonym kurv → login | Kurven flettes (kræver trin 2 ovenfor) |
| 5 | Dobbeltklik "Betal" | Én ordre (samme idempotency-nøgle) |
| 5 | Sidste vare, to browsere | Én får varen, den anden "udsolgt" |
| 5 | Webhook uden/forkert signatur | 401 + Critical-log |
| 5 | Webhook samme `id` to gange | Anden gang ignoreres (`PaymentEventReplay`) |
| 5 | Webhook med forkert beløb | Ordren forbliver Pending, Critical-log |
| 6 | Skift adgangskode | Andre sessioner logges ud, mail sendes |
| 6 | Glemt: kendt og ukendt e-mail | Identisk svar; link virker 1 gang, 30 min |
| 6 | Nulstil Admin uden MFA-kode | Afvist |
| 7 | Søg `' OR 1=1--` | Literal søgning, ingen fejl |
| 8 | `/Orders/{andres-id}` | 404, `AccessDenied` i sikkerhedsloggen |
| 9 | Customer → `/Admin/Products` | 403 (og DB afviser selv om siden omgås) |
| 9 | Slet produkt >5 min efter login | Sendes til re-auth, derefter slettet, audit-række |
| 9 | To admins redigerer samme produkt | Sidste får "ændret af en anden" |
| 9 | Upload `.php` omdøbt til `.jpg` | Afvist (magic bytes) |
| 10 | Customer/Admin → `/SysAdmin/Logs` | 403 |
| 10 | Rediger en logrække i DB | Trigger afviser; `VerifyChain` finder brud hvis trigger omgås |
| 10 | 11 fejl-logins fra samme IP | `BruteForceIp` i Alerts |
| 11 | Download mine data | JSON med profil + ordrer |
| 11 | Slet konto | Anonymiseret, kan ikke logge ind, ordrer bevaret |

## 6. Kendte begrænsninger
- Intet er kompileret eller kørt mod en rigtig browser.
- Mock-betalingssiden virker kun i Development.
- Ordreflow har ingen "Shipped"-side (status findes i databasen).
- Ingen QR-billede (nøgle + otpauth-link vises). Et lokalt QR-bibliotek kan tilføjes.
