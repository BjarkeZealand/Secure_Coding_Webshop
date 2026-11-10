Hemmeligheder må ikke stå i appsettings.json. Sæt dem med user-secrets:

    dotnet user-secrets init
    dotnet user-secrets set "ConnectionStrings:Webshop" "Server=localhost;Database=Webshop;User Id=webshop_app;Password=<adgangskode fra SQL-scriptet>;TrustServerCertificate=True"
    dotnet user-secrets set "Payment:WebhookSecret" "<mindst 32 tilfældige tegn>"

DataProtection:KeyPath skal pege på en mappe uden for projektet og uden for Git.
