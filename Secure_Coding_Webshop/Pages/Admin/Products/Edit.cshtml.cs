using System.ComponentModel.DataAnnotations;
using Microsoft.AspNetCore.Mvc;
using Secure_Coding_Webshop.Models;
using Secure_Coding_Webshop.Repo.Interfaces;
using Secure_Coding_Webshop.Services;

namespace Secure_Coding_Webshop.Pages.Admin.Products
{
    public sealed class EditModel : ShopPageModel
    {
        private readonly IAdminRepository _admin;
        private readonly IImageStorage _images;

        public EditModel(IAdminRepository admin, IImageStorage images)
        {
            _admin = admin;
            _images = images;
        }

        public sealed class ProductForm
        {
            [Required, StringLength(150)] public string Name { get; set; } = "";
            [Required] public int CategoryId { get; set; }
            [Required, StringLength(2000)] public string Description { get; set; } = "";
            [Range(0.01, 1000000)] public decimal Price { get; set; }
            [Range(0, 100000)] public int StockQuantity { get; set; }
        }

        [BindProperty] public ProductForm Input { get; set; } = new();
        [BindProperty] public string? RowVersion { get; set; }          // base64 af ROWVERSION (samtidighedskontrol)
        [BindProperty] public IFormFile? Image { get; set; }
        public IReadOnlyList<CategoryRow> Categories { get; private set; } = [];
        public bool IsNew { get; private set; } = true;

        public Task<IActionResult> OnGetAsync(int? id) => GuardAsync(async () =>
        {
            Categories = await _admin.ListCategoriesAsync(SessionHash, Ip, Ct);
            if (id is null) return Page();

            var p = await _admin.GetProductAsync(SessionHash, id.Value, Ip, Ct);
            if (p is null) return NotFound();
            IsNew = false;
            Input = new ProductForm { Name = p.Name, CategoryId = p.CategoryId, Description = p.Description, Price = p.Price, StockQuantity = p.StockQuantity };
            RowVersion = Convert.ToBase64String(p.RowVersion);
            return Page();
        });

        public Task<IActionResult> OnPostAsync(int? id) => GuardAsync(async () =>
        {
            IsNew = id is null;
            Categories = await _admin.ListCategoriesAsync(SessionHash, Ip, Ct);
            if (!ModelState.IsValid) return Page();

            string? imageName = null;
            if (Image is { Length: > 0 })
            {
                var saved = await _images.SaveAsync(Image, Ct);
                if (saved.Status != ImageSaveStatus.Saved)
                {
                    ModelState.AddModelError(string.Empty, saved.Status == ImageSaveStatus.TooLarge
                        ? "Billedet må højst fylde 2 MB." : "Kun JPEG, PNG og WebP er tilladt.");
                    return Page();
                }
                imageName = saved.FileName;
            }

            var input = new ProductInput(Input.CategoryId, Input.Name, Input.Description, Input.Price, Input.StockQuantity, imageName);

            if (id is null)
            {
                if (await _admin.CreateProductAsync(SessionHash, input, Ip, Ct) is null)
                {
                    ModelState.AddModelError(string.Empty, "Kategorien findes ikke.");
                    return Page();
                }
                return RedirectToPage("Index");
            }

            byte[] version;
            try { version = Convert.FromBase64String(RowVersion ?? ""); }
            catch (FormatException) { return BadRequest(); }
            if (version.Length != 8) return BadRequest();

            var result = await _admin.UpdateProductAsync(SessionHash, id.Value, input, version, Ip, Ct);   // 50409 -> GuardAsync
            if (result == 1) return NotFound();
            if (result == 2)
            {
                ModelState.AddModelError(string.Empty, "Kategorien findes ikke.");
                return Page();
            }
            return RedirectToPage("Index");
        });
    }
}
