using System.Security.Cryptography;

namespace Secure_Coding_Webshop.Services
{
    public enum ImageSaveStatus { Saved, TooLarge, UnsupportedType }

    public sealed record ImageSaveResult(ImageSaveStatus Status, string? FileName);

    public interface IImageStorage
    {
        Task<ImageSaveResult> SaveAsync(IFormFile file, CancellationToken ct);
        /// <summary>Åbner filen kun hvis navnet har det genererede format. Aldrig en sti fra brugeren.</summary>
        FileStream? Open(string fileName, out string contentType);
    }

    /// <summary>
    /// Produktbilleder (US9). Filtypen afgøres af INDHOLDET (magic bytes), ikke af klientens filnavn eller Content-Type.
    /// Filen gemmes under et genereret navn (32 hex + endelse) uden for wwwroot og serveres af et endpoint med nosniff.
    /// </summary>
    public sealed class ImageStorage : IImageStorage
    {
        public const long MaxBytes = 2 * 1024 * 1024;
        private static readonly System.Text.RegularExpressions.Regex NameFormat =
            new(@"^[0-9a-f]{32}\.(jpg|png|webp)$", System.Text.RegularExpressions.RegexOptions.Compiled);

        private readonly string _root;

        public ImageStorage(IConfiguration config, IHostEnvironment env)
        {
            // Skal ligge UDEN FOR wwwroot, ellers kan en uploadet fil ende som eksekverbart indhold
            _root = Path.GetFullPath(config["Uploads:Path"] ?? Path.Combine(env.ContentRootPath, "App_Data", "product-images"));
            Directory.CreateDirectory(_root);
        }

        public async Task<ImageSaveResult> SaveAsync(IFormFile file, CancellationToken ct)
        {
            if (file.Length is 0 or > MaxBytes) return new ImageSaveResult(ImageSaveStatus.TooLarge, null);

            var header = new byte[12];
            await using (var probe = file.OpenReadStream())
            {
                var read = await probe.ReadAsync(header, ct);
                if (read < 12) return new ImageSaveResult(ImageSaveStatus.UnsupportedType, null);
            }

            string? ext =
                header[0] == 0xFF && header[1] == 0xD8 && header[2] == 0xFF ? "jpg" :
                header.AsSpan(0, 8).SequenceEqual(new byte[] { 0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A }) ? "png" :
                header.AsSpan(0, 4).SequenceEqual("RIFF"u8) && header.AsSpan(8, 4).SequenceEqual("WEBP"u8) ? "webp" : null;
            if (ext is null) return new ImageSaveResult(ImageSaveStatus.UnsupportedType, null);

            var name = Convert.ToHexString(RandomNumberGenerator.GetBytes(16)).ToLowerInvariant() + "." + ext;
            await using var target = new FileStream(Path.Combine(_root, name), FileMode.CreateNew, FileAccess.Write, FileShare.None);
            await using var source = file.OpenReadStream();
            await source.CopyToAsync(target, ct);
            return new ImageSaveResult(ImageSaveStatus.Saved, name);
        }

        public FileStream? Open(string fileName, out string contentType)
        {
            contentType = "application/octet-stream";
            if (!NameFormat.IsMatch(fileName)) return null;     // blokerer ../ og alt andet end vores egne navne
            var path = Path.Combine(_root, fileName);
            if (!File.Exists(path)) return null;
            contentType = fileName.EndsWith(".png") ? "image/png" : fileName.EndsWith(".webp") ? "image/webp" : "image/jpeg";
            return new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
        }
    }
}
