using Microsoft.Data.SqlClient;
using Secure_Coding_Webshop.Models;
using Secure_Coding_Webshop.Repo.Shared.Factories.Interfaces;
using System.Data;

namespace Secure_Coding_Webshop.Repo
{
    public abstract class BaseRepo
    {
        private readonly ISqlConnectionFactory _connections;

        protected BaseRepo(ISqlConnectionFactory connections) => _connections = connections;

        /// <summary>Kalder en procedure uden resultatsæt (INSERT/UPDATE/DELETE).</summary>
        protected Task ExecuteProcAsync(string procedure, SqlParameter[] parameters, CancellationToken ct) =>
            RunAsync(procedure, parameters, async command =>
            {
                await command.ExecuteNonQueryAsync(ct);
                return true;
            }, 5, ct);

        /// <summary>Kalder en procedure og mapper første række (null hvis ingen rækker).</summary>
        protected Task<T?> QuerySingleProcAsync<T>(
            string procedure, SqlParameter[] parameters, Func<SqlDataReader, T> map, CancellationToken ct)
            where T : class =>
            RunAsync<T?>(procedure, parameters, async command =>
            {
                await using var reader = await command.ExecuteReaderAsync(CommandBehavior.SingleRow, ct);
                return await reader.ReadAsync(ct) ? map(reader) : null;
            }, 5, ct);

        /// <summary>Kalder en procedure og mapper ALLE rækker (tom liste hvis ingen).</summary>
        protected Task<IReadOnlyList<T>> QueryListProcAsync<T>(
            string procedure, SqlParameter[] parameters, Func<SqlDataReader, T> map, CancellationToken ct,
            int timeoutSeconds = 5) =>
            RunAsync<IReadOnlyList<T>>(procedure, parameters, async command =>
            {
                var list = new List<T>();
                await using var reader = await command.ExecuteReaderAsync(ct);
                while (await reader.ReadAsync(ct)) list.Add(map(reader));
                return list;
            }, timeoutSeconds, ct);

        /// <summary>Kalder en procedure, der returnerer ét BIT/INT (0/1), og giver det som bool.</summary>
        protected Task<bool> ScalarBoolProcAsync(string procedure, SqlParameter[] parameters, CancellationToken ct) =>
            RunAsync(procedure, parameters, async command =>
                Convert.ToBoolean(await command.ExecuteScalarAsync(ct)), 5, ct);

        /// <summary>Kalder en procedure, der returnerer ét heltal (resultatkode).</summary>
        protected Task<int> ScalarIntProcAsync(string procedure, SqlParameter[] parameters, CancellationToken ct) =>
            RunAsync(procedure, parameters, async command =>
                Convert.ToInt32(await command.ExecuteScalarAsync(ct)), 5, ct);

        /// <summary>Kalder en procedure, der returnerer én tekst (fx JSON). Null hvis ingen række.</summary>
        protected Task<string?> ScalarStringProcAsync(string procedure, SqlParameter[] parameters, CancellationToken ct) =>
            RunAsync<string?>(procedure, parameters, async command =>
                await command.ExecuteScalarAsync(ct) as string, 15, ct);

        // Fælles sted for forbindelse, timeout og fejlmapping, så ingen repo kan glemme dem
        private async Task<T> RunAsync<T>(
            string procedure, SqlParameter[] parameters, Func<SqlCommand, Task<T>> run, int timeoutSeconds, CancellationToken ct)
        {
            try
            {
                await using var connection = _connections.Create();
                await connection.OpenAsync(ct);

                await using var command = connection.CreateCommand();
                command.CommandType = CommandType.StoredProcedure;
                command.CommandText = procedure;
                command.CommandTimeout = timeoutSeconds;
                command.Parameters.AddRange(parameters);

                return await run(command);
            }
            catch (SqlException ex) when (DbRuleException.IsRuleError(ex.Number))
            {
                // Proceduren har afvist kaldet bevidst (rolle, session, validering, samtidighed)
                throw new DbRuleException(ex.Number, procedure);
            }
        }

        protected static SqlParameter NVarChar(string name, int size, string? value) =>
            new(name, SqlDbType.NVarChar, size) { Value = (object?)value ?? DBNull.Value };

        protected static SqlParameter VarChar(string name, int size, string? value) =>
            new(name, SqlDbType.VarChar, size) { Value = (object?)value ?? DBNull.Value };

        // byte[]? : login-forsøg for ukendte brugere gemmes uden e-mail-hash
        protected static SqlParameter Binary32(string name, byte[]? value) =>
            new(name, SqlDbType.Binary, 32) { Value = (object?)value ?? DBNull.Value };

        protected static SqlParameter Binary8(string name, byte[] value) =>
            new(name, SqlDbType.Binary, 8) { Value = value };

        protected static SqlParameter VarBinary(string name, int size, byte[]? value) =>
            new(name, SqlDbType.VarBinary, size) { Value = (object?)value ?? DBNull.Value };

        protected static SqlParameter UniqueId(string name, Guid? value) =>
            new(name, SqlDbType.UniqueIdentifier) { Value = (object?)value ?? DBNull.Value };

        protected static SqlParameter Bit(string name, bool value) =>
            new(name, SqlDbType.Bit) { Value = value };

        protected static SqlParameter Int(string name, int value) =>
            new(name, SqlDbType.Int) { Value = value };

        protected static SqlParameter IntOrNull(string name, int? value) =>
            new(name, SqlDbType.Int) { Value = (object?)value ?? DBNull.Value };

        protected static SqlParameter BigInt(string name, long value) =>
            new(name, SqlDbType.BigInt) { Value = value };

        protected static SqlParameter Money(string name, decimal? value) =>
            new(name, SqlDbType.Decimal) { Precision = 12, Scale = 2, Value = (object?)value ?? DBNull.Value };

        protected static SqlParameter DateTimeUtc(string name, DateTime? value) =>
            new(name, SqlDbType.DateTime2) { Scale = 3, Value = (object?)value ?? DBNull.Value };

        protected static SqlParameter OutputBit(string name) =>
            new(name, SqlDbType.Bit) { Direction = ParameterDirection.Output };

        // DATETIME2 kommer uden Kind fra SQL Server; vi gemmer altid UTC
        protected static DateTime Utc(SqlDataReader r, int ordinal) =>
            DateTime.SpecifyKind(r.GetDateTime(ordinal), DateTimeKind.Utc);

        protected static DateTime? UtcOrNull(SqlDataReader r, int ordinal) =>
            r.IsDBNull(ordinal) ? null : Utc(r, ordinal);
    }
}
