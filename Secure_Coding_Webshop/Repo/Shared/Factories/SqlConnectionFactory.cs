using Microsoft.Data.SqlClient;
using Secure_Coding_Webshop.Repo.Shared.Factories.Interfaces;

namespace Secure_Coding_Webshop.Repo.Shared.Factories
{
    public sealed class SqlConnectionFactory : ISqlConnectionFactory
    {
        private readonly string _connectionString;

        public SqlConnectionFactory(IConfiguration config) =>
            _connectionString = config.GetConnectionString("Webshop")
                ?? throw new InvalidOperationException("ConnectionStrings:Webshop mangler (sæt den i User Secrets).");

        public SqlConnection Create() => new(_connectionString);
    }
}
