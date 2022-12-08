using IdentityModel;
using IdentityServer4.Models;
using Newtonsoft.Json;
using System.Collections.Generic;
using System.Xml.Linq;

namespace ASP_NET_Core_Identity_at_Identityserver4
{
    public static class Config
    {
        /// <summary>
        /// Так звані ресурси що собою являють типи ідентифікації користувачів
        /// </summary>
        /// <remarks>
        /// Представляють претензії щодо користувача, як-от ідентифікатор користувача, відображуване ім’я, адреса електронної пошти тощо
        /// <para>
        /// Після визначення ресурсу ви можете надати доступ до нього клієнту за допомогою AllowedScopes параметра
        /// </para>
        /// </remarks>
        /// <example>
        /// <code>
        /// var client = new Client
        ///  {
        ///   ClientId = "client",
        ///
        ///     AllowedScopes = { "openid", "profile" }
        /// };
        /// </code>
        /// </example>
        public static IEnumerable<IdentityResource> IdentityResources =>
                   new IdentityResource[]
                   {
                       /* Параметри ресурсів:
                       //Name - Унікальна назва ідентифікаційного ресурсу. Це значення, яке клієнт використовуватиме для параметра області в запиті авторизації.
                       //DisplayName - Це значення використовуватиметься, наприклад, на екрані згоди
                       //Description - Це значення використовуватиметься, наприклад, на екрані згоди.
                       //Required - Указує, чи може користувач скасувати вибір області на екрані згоди (якщо екран згоди хоче реалізувати таку функцію). За замовчуванням значення false.
                       //Emphasize - Указує, чи підкреслюватиме цю область на екрані згоди (якщо на екрані згоди потрібно реалізувати таку функцію). Використовуйте це налаштування для конфіденційних або важливих областей. За замовчуванням значення false.
                       //ShowInDiscoveryDocument - Визначає, чи відображається ця область у документі відкриття. За замовчуванням значення true.
                       //UserClaims - Список пов’язаних типів претензій користувачів, які мають бути включені в маркер ідентифікації.
                       */

                        new IdentityResources.OpenId(),
                        /* Інший вигляд реалізації руками області OpenId
                        new IdentityResource(
                        name: "openid",
                        userClaims: new[] { "sub" },
                        displayName: "Your user identifier"),
                        */
                        new IdentityResources.Profile(),
                        /* Інший вигляд реалізації руками області Profile
                        new IdentityResource(
                        name: "profile",
                        userClaims: new[] { "name", "email", "website" },
                        displayName: "Your profile data"),
                        */
                        
                        /* Інші варіанти IdentityResources
                        new IdentityResources.OpenId(),
                        new IdentityResources.Email(),
                        new IdentityResources.Profile(),
                        new IdentityResources.Phone(),
                        new IdentityResources.Address()
                        */

                        new IdentityResource()
                        {
                            //Вказує, чи цей ресурс увімкнено та чи можна його запитувати.
                            //За замовчуванням значення true
                            Enabled = false,

                            //Унікальна назва ідентифікаційного ресурсу.
                            //Це значення, яке клієнт використовуватиме для параметра області в запиті авторизації.
                            Name = "custom.profile",

                            //Це значення використовуватиметься, наприклад, на екрані згоди.
                            DisplayName = "Custom profile",

                            //Це значення використовуватиметься, наприклад, на екрані згоди.
                            Description = "It`s tests profile",

                            //Указує, чи може користувач скасувати вибір області на екрані згоди
                            //(якщо екран згоди хоче реалізувати таку функцію). За замовчуванням значення false.
                            Required = false,

                            //Указує, чи підкреслюватиме цю область на екрані згоди
                            //(якщо на екрані згоди потрібно реалізувати таку функцію).
                            //Використовуйте це налаштування для конфіденційних або важливих областей.
                            //За замовчуванням значення false.
                            Emphasize = false,

                            //Визначає, чи відображається ця область у документі відкриття.
                            //За замовчуванням значення true.
                            ShowInDiscoveryDocument = true,

                            //Список пов’язаних типів претензій користувачів,
                            //які мають бути включені в маркер ідентифікації.
                            UserClaims = new[] { "name", "email", "status" }
                        }
                   };

        /// <summary>
        /// Тут зберігаються так звані "Scope" які собою явдяють різновиди прав доступу до тих чи інших полів чи даних
        /// </summary>
        /// <remarks>
        /// Наприклад scope1 буде містити доступ до полів повязаних з авторизацією, але не міститиме доступ до файлів користувача і тд...
        /// </remarks>
        /// <example>
        /// Потім ви можете призначити області різним клієнтам
        /// <code>
        /// var webViewer = new Client
        ///{
        ///    ClientId = "mobile_app",
        ///    AllowedScopes = { "openid", "profile", "read", "write", "delete"  }
        ///};
        /// </code>
        /// </example>
        public static IEnumerable<ApiScope> ApiScopes =>
            new ApiScope[]
            {
                new ApiScope(IdentityConstants.ApiScope_Level1),//scope1
                new ApiScope(IdentityConstants.ApiScope_Level2),//scope2

                new ApiScope(name: IdentityConstants.ApiScope_Read,   displayName: "Read your data."),
                new ApiScope(name: IdentityConstants.ApiScope_Write,  displayName: "Write your data."),
                new ApiScope(name: IdentityConstants.ApiScope_Delete, displayName: "Delete your data.")
            };

        /// <summary>
        /// Представляють функціональні можливості, до яких клієнт хоче отримати доступ або іншими словами,
        /// щоб дозволити клієнтам запитувати маркери доступу для API
        /// </summary>
        /// <remarks>
        /// Як правило, це кінцеві точки на основі HTTP (відомі також як API), але також можуть бути кінцеві точки черги повідомлень або подібні.
        /// </remarks>
        /// <example>
        /// Деякий приклад маркеру для ресурсів
        /// <code>
        /// {
        ///    "typ": "at+jwt"
        ///}.
        ///{
        ///    "client_id": "client",
        ///    "sub": "123",
        ///
        ///    "aud": "invoice",
        ///    "scope": "read write delete"
        ///}
        /// </code>
        /// </example>
        public static IEnumerable<ApiResource> APIResource => 
            new ApiResource[]
            {
                new ApiResource("invoice", "Invoice API")
                {
                    Scopes = { 
                        IdentityConstants.ApiScope_Read, 
                        IdentityConstants.ApiScope_Write, 
                        IdentityConstants.ApiScope_Delete }
                },

                new ApiResource("customer", "Customer API")
                {
                    Scopes = { 
                        IdentityConstants.ApiScope_Level2 }
                },

                new ApiResource
                {
                    //Вказує, чи цей ресурс увімкнено та чи можна його запитувати. За замовчуванням значення true.
                    Enabled = false,

                    //Унікальна назва API. Це значення використовується для автентифікації з самоаналізом і буде додано до аудиторії вихідного маркера доступу.
                    Name = "api1",

                    //Це значення можна використовувати, наприклад, на екрані згоди.
                    DisplayName = "test api 1",


                    //Це значення можна використовувати, наприклад, на екрані згоди.
                    Description = "It`s a test API resource at API 1",

                    //Секрет API використовується для кінцевої точки самоаналізу. API може автентифікуватися за допомогою інтроспекції за допомогою імені та секрету API.
                    ApiSecrets =
                    {
                        new Secret("secret".Sha256())
                    },

                    //Список пов’язаних типів претензій користувачів, які слід включити в маркер доступу.
                    UserClaims = { JwtClaimTypes.Name, JwtClaimTypes.Email },
                    
                    //API повинен мати принаймні одну область дії. Кожен діапазон може мати різні налаштування.
                    Scopes = new[] { "api1.full_access", "api1.read_only" },
                }
            };


        /// <summary>
        /// Тут перераховані клієнти які будуть мати доступ певних рівнів з певним видом шифрування даних 
        /// а також з певним видом грантів дозволів 
        /// </summary>
        /// <remarks>
        /// Клієнти представляють програми, які можуть запитувати маркери від вашого сервера ідентифікації.
        /// </remarks>
        /// <example>
        /// 
        /// <code>
        /// 
        /// </code>
        /// </example>
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

                ///<summary>
                ///Інтерактивний клієнт із використанням потоку коду + pkce
                /// </summary> 
                /// <remarks>
                /// Інтерактивні програми (наприклад, веб-програми або рідні настільні/мобільні програми) 
                /// використовують потік коду авторизації. Цей потік забезпечує найкращу безпеку, 
                /// оскільки маркери доступу передаються лише через виклики зворотного каналу 
                /// (і дає вам доступ до маркерів оновлення)
                /// </remarks>
                /// <example>
                /// Визначення клієнтів у appsettings.json
                /// <code>
                /// "IdentityServer": {
                ///  "IssuerUri": "urn:sso.company.com",
                ///  "Clients": [
                ///    {
                ///      "Enabled": true,
                ///      "ClientId": "local-dev",
                ///      "ClientName": "Local Development",
                ///      "ClientSecrets": [ { "Value": "<Insert Sha256 hash of the secret encoded as Base64 
                ///      string>" } ],
                ///      "AllowedGrantTypes": [ "client_credentials" ],
                ///      "AllowedScopes": [ "api1" ],
                ///    }
                ///  ]
                ///}
                /// </code>
                /// Потім передайте розділ конфігурації AddInMemoryClientsметоду:
                /// <code>
                /// AddInMemoryClients(configuration.GetSection("IdentityServer:Clients"))
                /// </code>
                /// </example>
                new Client
                {
                    ClientId = "interactive",
                    ClientSecrets = { new Secret("49C1A7E1-0C79-4A89-A3D6-A37998FB86B0".Sha256()) },

                    AllowedGrantTypes = GrantTypes.Code,

                    RedirectUris = { "https://localhost:44300/signin-oidc" },
                    FrontChannelLogoutUri = "https://localhost:44300/signout-oidc",
                    PostLogoutRedirectUris = { "https://localhost:44300/signout-callback-oidc" },

                    AllowOfflineAccess = true,
                    AllowedScopes = { 
                        "openid", 
                        "profile", 
                        IdentityConstants.ApiScope_Level2 }
                },
                
                new Client
                {
                    //Імя клієнта який буде отримувати доступ до даних АРІ
                    ClientId = "test.client",

                    ///<summary>
                    ///Типи гарантів дозволяють заблокувати взаємодію протоколу, дозволену для даного клієнту
                    ///</summary>
                    ///<remarks>
                    ///Клієнт може бути налаштований на використання більш ніж одного типу дозволу 
                    ///(наприклад, потік коду авторизації для операцій, орієнтованих на користувача, 
                    ///і облікових даних клієнта для зв’язку між серверами)
                    /// </remarks>
                    /// <example>
                    /// Ви також можете вказати список типів грантів вручну
                    /// <code>
                    /// Client.AllowedGrantTypes =
                    ///    {
                    ///        GrantType.Code,
                    ///        GrantType.ClientCredentials,
                    ///        "my_custom_grant_type"
                    ///    };
                    /// </code>
                    /// </example>
                    AllowedGrantTypes = GrantTypes.Code,

                    //Секрет для аутентифікації
                    ClientSecrets =
                    {
                        new Secret("secret".Sha256())
                    },

                    //Області, до яких клієнт має доступ
                    AllowedScopes = {
                        IdentityConstants.ApiScope_Read,
                        IdentityConstants.ApiScope_Write,
                        IdentityConstants.ApiScope_Delete}
                }
            };

        
    }
}