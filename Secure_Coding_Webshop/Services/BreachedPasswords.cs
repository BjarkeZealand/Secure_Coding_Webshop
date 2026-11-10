using System.Security.Cryptography;
using System.Text;

namespace Secure_Coding_Webshop.Services
{
    public interface IBreachedPasswordChecker
    {
        /// <summary>True hvis adgangskoden findes i kendte læk. Ved fejl/timeout returneres false (fail-open: HIBP må ikke kunne låse brugere ude).</summary>
        Task<bool> IsBreachedAsync(string normalizedPassword, CancellationToken ct);
    }

    /// <summary>
    /// Have I Been Pwned "k-anonymity": kun de første 5 tegn af SHA-1-hashen forlader serveren,
    /// aldrig adgangskoden eller hele hashen. Svaret (ca. 800 suffikser) sammenlignes lokalt.
    /// </summary>
    public sealed class HibpPasswordChecker : IBreachedPasswordChecker
    {
        private readonly HttpClient _http;
        private readonly ILogger<HibpPasswordChecker> _log;

        public HibpPasswordChecker(HttpClient http, ILogger<HibpPasswordChecker> log)
        {
            _http = http;
            _log = log;
        }

        public async Task<bool> IsBreachedAsync(string normalizedPassword, CancellationToken ct)
        {
            var sha1 = Convert.ToHexString(SHA1.HashData(Encoding.UTF8.GetBytes(normalizedPassword)));
            var prefix = sha1[..5];
            var suffix = sha1[5..];
            try
            {
                using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct);
                timeout.CancelAfter(TimeSpan.FromSeconds(2));
                using var request = new HttpRequestMessage(HttpMethod.Get, $"range/{prefix}");
                request.Headers.Add("Add-Padding", "true");          // skjuler antal resultater for netværksobservatører
                using var response = await _http.SendAsync(request, timeout.Token);
                response.EnsureSuccessStatusCode();

                foreach (var line in (await response.Content.ReadAsStringAsync(timeout.Token)).Split('\n'))
                {
                    var parts = line.Trim().Split(':');
                    if (parts.Length == 2 && parts[0] == suffix && long.TryParse(parts[1], out var count) && count > 0)
                        return true;
                }
                return false;
            }
            catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException or OperationCanceledException)
            {
                _log.LogWarning("HIBP-opslag mislykkedes ({Type}); fortsætter uden", ex.GetType().Name);
                return false;
            }
        }
    }

    /// <summary>Ekstra krav ud over din PasswordPolicy: gentagelser, rækkefølger og tastaturmønstre.</summary>
    public static class PasswordPatterns
    {
        private static readonly string[] Rows = ["qwertyuiopå", "asdfghjklæø", "zxcvbnm", "1234567890"];

        public static IEnumerable<string> Check(string password)
        {
            var lower = password.ToLowerInvariant();

            if (password.Distinct().Count() <= 3)
                yield return "Adgangskoden bruger for få forskellige tegn.";

            for (var i = 0; i + 3 <= lower.Length - 0 && i < lower.Length - 3; i++)
            {
                if (lower[i] == lower[i + 1] && lower[i] == lower[i + 2] && lower[i] == lower[i + 3])
                {
                    yield return "Undgå at gentage det samme tegn mange gange i træk.";
                    break;
                }
            }

            if (HasWalk(lower, 5))
                yield return "Undgå tastaturmønstre som qwerty eller 12345.";
        }

        private static bool HasWalk(string s, int length)
        {
            for (var i = 0; i + length <= s.Length; i++)
            {
                var seg = s.Substring(i, length);
                var rev = new string(seg.Reverse().ToArray());
                if (Rows.Any(r => r.Contains(seg) || r.Contains(rev))) return true;
                // a-b-c-d-e eller 5-4-3-2-1 (stigende/faldende rækkefølge)
                var asc = true; var desc = true;
                for (var k = 1; k < seg.Length; k++)
                {
                    if (seg[k] - seg[k - 1] != 1) asc = false;
                    if (seg[k - 1] - seg[k] != 1) desc = false;
                }
                if (asc || desc) return true;
            }
            return false;
        }
    }
}
