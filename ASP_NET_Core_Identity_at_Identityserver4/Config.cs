using IdentityServer4.Models;
using System.Collections.Generic;

namespace ASP_NET_Core_Identity_at_Identityserver4
{
    public static class Config
    {
        /// <summary>
        /// Так звані ресурси що собою являють типи ідентифікації користувачів
        /// </summary>
        public static IEnumerable<IdentityResource> IdentityResources =>
                   new IdentityResource[]
                   {
                        new IdentityResources.OpenId(),
                        new IdentityResources.Profile(),
                   };

        /// <summary>
        /// Тут зберігаються так звані "Scope" які собою явдяють різновиди прав доступу до тих чи інших полів чи даних
        /// </summary>
        /// <remarks>
        /// Наприклад scope1 буде містити доступ до полів повязаних з авторизацією, але не міститиме доступ до файлів користувача і тд...
        /// </remarks>
        public static IEnumerable<ApiScope> ApiScopes =>
            new ApiScope[]
            {
                new ApiScope(IdentityConstants.ApiScope_Level1),//scope1
                new ApiScope(IdentityConstants.ApiScope_Level2),//scope2
            };

        /// <summary>
        /// Тут перераховані клієнти які будуть мамти доступ певних рівнів з певним видом шифрування даних а також з певним видом грантів дозволів 
        /// </summary>
        public static IEnumerable<Client> Clients =>
            new Client[]
            {
                // Клієнт потоку облікових даних клієнта m2m
                new Client
                {
                    ClientId = "m2m.client",
                    ClientName = "Client Credentials Client",

                    AllowedGrantTypes = GrantTypes.ClientCredentials,
                    ClientSecrets = { new Secret("511536EF-F270-4058-80CA-1C89C192F69A".Sha256()) },

                    AllowedScopes = { IdentityConstants.ApiScope_Level1 }
                },

                // Інтерактивний клієнт із використанням потоку коду + pkce
                new Client
                {
                    ClientId = "interactive",
                    ClientSecrets = { new Secret("49C1A7E1-0C79-4A89-A3D6-A37998FB86B0".Sha256()) },

                    AllowedGrantTypes = GrantTypes.Code,

                    RedirectUris = { "https://localhost:44300/signin-oidc" },
                    FrontChannelLogoutUri = "https://localhost:44300/signout-oidc",
                    PostLogoutRedirectUris = { "https://localhost:44300/signout-callback-oidc" },

                    AllowOfflineAccess = true,
                    AllowedScopes = { "openid", "profile", IdentityConstants.ApiScope_Level2 }
                },
            };
    }
}