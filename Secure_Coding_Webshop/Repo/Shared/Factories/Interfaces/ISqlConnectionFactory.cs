using Microsoft.Data.SqlClient;

namespace Secure_Coding_Webshop.Repo.Shared.Factories.Interfaces
{
    public interface ISqlConnectionFactory { SqlConnection Create(); }
}
