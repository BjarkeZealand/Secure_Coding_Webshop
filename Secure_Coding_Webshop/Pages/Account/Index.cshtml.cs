using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Secure_Coding_Webshop.Models;
using Secure_Coding_Webshop.Repo.Interfaces;

namespace Secure_Coding_Webshop.Pages.Account
{
    [Authorize]
    public sealed class IndexModel : ShopPageModel
    {
        private readonly IAccountRepository _repo;

        public IndexModel(IAccountRepository repo) => _repo = repo;

        public AccountProfile? Profile { get; private set; }

        public Task<IActionResult> OnGetAsync() => GuardAsync(async () =>
        {
            Profile = await _repo.GetProfileAsync(SessionHash, Ip, Ct);
            return Page();
        });
    }
}
