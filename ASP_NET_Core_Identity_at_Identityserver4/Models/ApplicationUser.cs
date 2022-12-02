using Microsoft.AspNetCore.Identity;

namespace ASP_NET_Core_Identity_at_Identityserver4.Models
{
    /// <summary>
    /// Додайте дані профілю для користувачів програми, додавши властивості до класу ApplicationUser
    /// </summary>
    public class ApplicationUser : IdentityUser
    {
        /// <summary>
        /// Поле яке буде містити опис користувача
        /// </summary>
        public string Description { get; set; } = "Пустий опис користувача";
    }
}
