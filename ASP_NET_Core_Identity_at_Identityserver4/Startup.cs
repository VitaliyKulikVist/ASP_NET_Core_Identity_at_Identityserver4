using ASP_NET_Core_Identity_at_Identityserver4.Data;
using ASP_NET_Core_Identity_at_Identityserver4.Models;
using IdentityServer4;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.Facebook;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.FileSystemGlobbing.Internal;
using Microsoft.Extensions.Hosting;
using Microsoft.IdentityModel.Tokens;
using Serilog;
using System.Diagnostics;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Threading.Tasks;

namespace ASP_NET_Core_Identity_at_Identityserver4
{
    /// <summary>
    /// Головний клас в якому відбувається підключення сервісів конфігурування налаштувань для роботи арі
    /// </summary>
    public class Startup
    {
        /// <summary>
        /// Містить інформацію про середовище веб-хостингу у якому працює програма
        /// </summary>
        /// <remarks>
        /// ApplicationName або шляхи до програми або "стани" програми
        /// </remarks>
        public IWebHostEnvironment Environment { get; }

        /// <summary>
        /// Представляє набір властивостей конфігурації програми ключ/значення
        /// </summary>
        /// <remarks>
        /// Містяться збережені та необхідні налаштування конфігурацій необхідних для сервісів\пакетів(бібліотек)
        /// </remarks>
        public IConfiguration Configuration { get; }

        public Startup(IWebHostEnvironment environment, IConfiguration configuration)
        {
            Environment = environment;
            Configuration = configuration;
        }

        public void ConfigureServices(IServiceCollection services)
        {
            /// <summary>
            /// Додає в колекцію сервісів сервіси, які необхідні роботи контролерів MVC
            /// </summary>
            services.AddControllersWithViews();

            ///<summary>
            ///Hреєструється підклас DbContext з ім'ям ApplicationDbContext як служба із заданою областю 
            ///в постачальнику служби додатків ASP.NET Core (тобто в контейнері впровадження залежностей). 
            ///Контекст при цьому налаштовується для використання постачальника бази даних SQL Server 
            ///та зчитування рядка підключення з конфігурації ASP.NET Core. 
            ///Зазвичай немає значення, де в ConfigureServices виконується виклик до AddDbContext.
            /// </summary>
            /// <remarks>
            /// DefaultConnection береться з appsettings.json з поля ConnectionStrings і рядка DefaultConnection
            /// </remarks>
            services.AddDbContext<ApplicationDbContext>(options =>
            {
                options.UseSqlite(Configuration.GetConnectionString("DefaultConnection"));
            });

            //Підключення сервісів необхідних для роботи AspNetCore.Identity
            /// <summary>
            /// Додає стандартну конфігурацію системи ідентифікації для вказаних типів користувачів і ролей
            /// </summary>
            services.AddIdentity<ApplicationUser, IdentityRole>()
                /// <summary>
                /// Додає реалізацію Entity Framework сховищ ідентифікаційної інформації
                /// </summary>
                .AddEntityFrameworkStores<ApplicationDbContext>()
                /// <summary>
                /// Додає постачальників токенів за замовчуванням, які використовуються для створення 
                /// токенів для скидання паролів, зміни електронної пошти та номерів телефону, 
                /// а також для генерації токенів двофакторної автентифікації
                /// </summary>
                .AddDefaultTokenProviders();

            /// <summary>
            /// Реєстрація IdentityServer у DI
            /// </summary>
            var builder = services.AddIdentityServer(options =>
            {
                #region  Події представляють інформацію вищого рівня про певні операції в IdentityServer.
                //Події – це структуровані дані, які включають ідентифікатори подій, інформацію про успіх/невдачу, категорії та деталі. Це полегшує запити й аналіз їх, а також вилучення корисної інформації, яку можна використовувати для подальшої обробки.

                //Чи викликати події помилки.
                options.Events.RaiseErrorEvents = true;

                //Чи потрібно викликати інформаційні події.
                options.Events.RaiseInformationEvents = true;

                //Чи потрібно викликати події збою.
                options.Events.RaiseFailureEvents = true;

                //Чи потрібно викликати події успіху.
                options.Events.RaiseSuccessEvents = true;
                #endregion

                /// <summary>
                /// Це потрібно для деяких старих систем перевірки маркерів доступу. За замовчуванням значення false.
                /// </summary>
                options.EmitStaticAudienceClaim = true;
            })
                // Все що пов'язано з ресурсами https://identityserver4.readthedocs.io/en/latest/topics/resources.html
                ///<summary>
                ///Додає ресурси ідентифікації
                /// </summary>
                /// <remarks>
                /// Тут зберігаються типи ідентифікації користувача будь то OpenId(), Profile(), Phone(), ... .
                /// </remarks>
                .AddInMemoryIdentityResources(Config.IdentityResources)
                ///<summary>
                ///Додає області API
                /// </summary>
                /// <remarks>
                /// Які слугують дозволами доступу до тих чи інших полів
                /// </remarks>
                .AddInMemoryApiScopes(Config.ApiScopes)
                ///<summary>
                ///Додає клієнтів в память IdentityServer
                /// </summary>
                .AddInMemoryClients(Config.Clients)
                ///<summary>
                ///Налаштовує IdentityServer для використання реалізацій ASP.NET Identity IUserClaimsPrincipalFactory, IResourceOwnerPasswordValidator і IProfileService. Також налаштовує деякі параметри ASP.NET Identity для використання з IdentityServer (наприклад, типи претензій для використання та налаштування файлів cookie автентифікації).
                /// </summary>
                /// <remarks>
                /// Це підключення необхідне для використанні AspNetIdentity в середині IdentityServer
                /// </remarks>
                .AddAspNetIdentity<ApplicationUser>();

            /// <summary>
            /// Встановлює тимчасові облікові дані для підпису.
            /// </summary>
            /// <remarks>
            /// не рекомендується для виробництва - вам потрібно зберігати ключові матеріали десь у надійному місці
            /// </remarks>
            builder.AddDeveloperSigningCredential();

            /// <summary>
            /// Налаштування аудентифікації
            /// </summary>
            services.AddAuthentication()
                /// <summary>
                /// Авторизація за допомогою Google
                /// </summary>
                /// <remarks>
                /// Для коректної роботи і можливості авторизації через Google необхідно зареєструвати свій додаток
                /// на сайті Google і потім копірнути з нього client ID та client secret 
                /// (це щось типу логіна і пароля для авторизації)
                /// </remarks>
                .AddGoogle(options =>
                {
                    options.SignInScheme = IdentityServerConstants.ExternalCookieAuthenticationScheme;

                    /// <summary>
                    /// зареєструйте свій IdentityServer у Google за адресою https://console.developers.google.com
                    /// </summary>
                    /// <remarks>
                    /// встановити URI перенаправлення на https://localhost:5001/signin-google
                    /// </remarks>
                    options.ClientId = "Сюди потрібно зкопіювати [client ID] який буде висвітлено на сторінці https://console.developers.google.com після реєстрації всланого додатку там";
                    options.ClientSecret = "Сюди потрібно зкопіювати [client secret] який буде висвітлено на сторінці https://console.developers.google.com після реєстрації всланого додатку там";
                })
                /// <summary>
                /// Додав також можливість авторизації через Facebook, лише за для того, щоб перевірити,
                /// чи в файлі Login.cshtml через форіч буде автоматично підтягнутий новий вид авторизації 
                /// і відображений додатковою кнопкою(як виявилось так)
                /// </summary>
                .AddFacebook(options =>
                {
                    options.AppId = "Рядок в якому міститься Facebook:AppId який необхідно зкопіювати після реєстрації на сервісі фейсбук власного додатку";
                    options.AppSecret = "Рядок в якому міститься Facebook:AppSecret який необхідно зкопіювати після реєстрації на сервісі фейсбук власного додатку";
                    options.AccessDeniedPath = "/AccessDeniedPathInfo";
                });

            /// <summary>
            /// Авторизація за допомогою JSON Web Token
            /// </summary>
            services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
                .AddJwtBearer(options =>
                {
                    /* Authority
                    /// <summary>
                    /// базова адреса вашого сервера ідентифікації
                    /// </summary>
                    /// <remarks>
                    /// Отримує або встановлює Authority для використання під час здійснення викликів OpenIdConnect.
                    /// </remarks>
                    options.Authority = "https://demo.identityserver.io";
                    */
                    /* Audience
                    /// <summary>
                    /// якщо ви використовуєте ресурси API, ви можете вказати назву тут
                    /// </summary>
                    /// <remarks>
                    /// Отримує або встановлює одне дійсне значення аудиторії для 
                    /// будь-якого отриманого маркера OpenIdConnect. 
                    /// Це значення передається в TokenValidationParameters.ValidAudience, якщо ця властивість порожня.
                    /// </remarks>
                    options.Audience = IdentityConstants.ApiScope_Level1;
                    */

                    options.Authority = Configuration["Authority"];
                    options.Events = new Microsoft.AspNetCore.Authentication.JwtBearer.JwtBearerEvents
                    {
                        OnMessageReceived = context =>
                        {

                            var accessToken = context.Request.Query["access_token"];

                            var path = context.HttpContext.Request.Path;
                            if (!string.IsNullOrEmpty(accessToken) && (path.StartsWithSegments("/chathub")))
                            {
                                context.Token = accessToken;
                            }

                            //тільки для дебагу просто щоб подивитись як працює
                            Log.Information("Message Received, AccessToken = {AccessToken}", accessToken);

                            return Task.CompletedTask;
                        },
                        OnTokenValidated = context =>
                        {
                            var token = context.SecurityToken as JwtSecurityToken;
                            if (token != null)
                            {
                                ClaimsIdentity identity = context.Principal.Identity as ClaimsIdentity;
                                if (identity != null)
                                {
                                    identity.AddClaim(new Claim("access_token", token.RawData));
                                }
                            }

                            //тільки для дебагу просто щоб подивитись як працює
                            Log.Information("Token Validated {rawData}", token.RawData);

                            return Task.CompletedTask;
                        },
                        OnAuthenticationFailed = context =>
                        {
                            var textEror = context.Exception.Message;

                            //тільки для дебагу просто щоб подивитись як працює
                            Log.Error("Authentication Failed, becouse \t{failed}", textEror);

                            return Task.CompletedTask;
                        }
                    };

                    options.TokenValidationParameters = new TokenValidationParameters
                    {
                        ValidateAudience = false,
                        NameClaimType = "name",
                        RoleClaimType = "role"
                    };

                    /// <summary>
                    /// IdentityServer видає заголовок typ за замовчуванням, рекомендована додаткова перевірка
                    /// </summary>
                    /// <remarks>
                    /// Отримує або встановлює System.Collections.Generic.IEnumerable`1, який містить дійсні типи, 
                    /// які використовуватимуться для перевірки відповідності вимогам 'typ' заголовка JWT. 
                    /// Якщо цю властивість не встановлено, вимога заголовка "typ" не буде перевірено, 
                    /// і всі типи будуть прийняті. У випадку JWE ця властивість застосовуватиметься 
                    /// ЛИШЕ до внутрішнього заголовка маркера.
                    /// </remarks>
                    options.TokenValidationParameters.ValidTypes = new[] { "at+jwt" };
                });

            /// <summary>
            /// Авторизація за допомогою Кукі (Cookie)
            /// </summary>
            /// <remarks>
            /// 
            /// </remarks>
            services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
                .AddCookie(options =>
                {
                    options.LoginPath = new Microsoft.AspNetCore.Http.PathString("/Account/Login");
                });
        }

        public void Configure(IApplicationBuilder app)
        {
            /// <summary>
            /// Перевірка, якщо проект запускається в режимі розробки
            /// </summary>
            if (Environment.IsDevelopment())
            {
                /// <summary>
                /// Якщо програма знаходиться в стані розробки, то за допомогою middleware
                /// app.UseDeveloperExceptionPage() програма перехоплює винятки 
                /// і виводить інформацію про них розробнику.
                /// </summary>
                /// <remarks>
                /// Захоплює синхронні та асинхронні екземпляри System.Exception із конвеєра 
                /// та генерує відповіді на помилки HTML.
                /// <para>
                /// Під HTML мається на увазі що суть помилкі буде відображена у вигляді сторінки в браузері,
                /// а не в середовищі розробки
                /// </para>
                /// </remarks>
                app.UseDeveloperExceptionPage();
                /// <summary>
                /// Це підключення працює у випадку якщо проект в стані розробки, 
                /// воно необхідне для відображення помилок з читанням записом і взагалі 
                /// доступом до Баз даних за допомогою Entity Framework.
                /// Для його коректної роботи потрібно, щоб був встановлений пакет 
                /// Microsoft.AspNetCore.Diagnostics.EntityFrameworkCore
                /// </summary>
                /// <remarks>
                /// Фіксує синхронні та асинхронні винятки, пов’язані з базою даних, із конвеєра, 
                /// які можна вирішити за допомогою міграцій Entity Framework. Коли виникають ці винятки, 
                /// генерується відповідь у форматі HTML із детальною інформацією про можливі дії 
                /// для вирішення проблеми.
                /// <para>
                /// Під HTML мається на увазі що суть помилкі буде відображена у вигляді сторінки в браузері,
                /// а не в середовищі розробки
                /// </para>
                /// </remarks>
                app.UseDatabaseErrorPage();
            }

            /// <summary>
            /// Цей метод вказує, що всі статичні файли будуть зберігатись в папці "wwwroot", 
            /// яка в свою чергу повинна знаходитись у поточному проекті. 
            /// </summary>
            /// <remarks>
            /// Вмикає обслуговування статичних файлів для поточного шляху запиту
            /// <para>
            /// Це перевантаження методу UseStaticFiles не приймає параметрів, 
            /// вона позначає файли в кореневому каталозі документів як обслуговуються.
            /// </para>
            /// </remarks>
            app.UseStaticFiles();

            /// <summary>
            /// Дає можливість користуватись ендпойнтами для відправки реквестів між сервісами або між додатками
            /// <para>
            /// Додає в конвеєр обробки запиту компонент EndpointRoutingMiddleware. 
            /// Система маршрутизації використовує кінцеві точки (endpoints) для обробки запитів за певними маршрутами.
            /// І компонент EndpointRoutingMiddleware дає змогу визначити маршрут, який відповідає запрошеній адресі,
            /// і встановити для його обробки кінцеву точку у вигляді об'єкта Microsoft.AspNetCore.Http.Endpoint ,
            /// а також визначити дані маршруту.
            /// </para>
            /// </summary>
            /// <remarks>
            /// Додає проміжне програмне забезпечення Microsoft.AspNetCore.Routing.EndpointRoutingMiddleware 
            /// до зазначеного Microsoft.AspNetCore.Builder.IApplicationBuilder.
            /// </remarks>
            app.UseRouting();

            ///<summary>
            ///Цей метод для маршутизації і контролем за кінцевими точками, створено виключно, 
            ///для спроби розуміння як це працює
            /// </summary>
            /// <remarks>
            /// Додає делегат проміжного програмного забезпечення, визначений у рядку до конвеєра запитів програми.
            /// </remarks>
            app.Use(async (context, next) =>
            {
                // Отримуємо кінцеву точку
                Endpoint endpoint = context.GetEndpoint();

                if (endpoint != null)
                {
                    // Отримуємо шаблон маршруту, який асоційований з кінцевою точкою
                    var routePattern = (endpoint as Microsoft.AspNetCore.Routing.RouteEndpoint)?.RoutePattern?.RawText;

                    Log.Debug("Endpoint Name:{Name}", endpoint.DisplayName);
                    Log.Debug("Route Pattern: {Pattern}", routePattern);

                    // якщо кінцева точка визначена, передаємо обробку далі
                    await next();
                }
                else
                {
                    Log.Debug("Endpoint: null");
                    // якщо кінцева точка не визначена, завершуємо обробку
                    await context.Response.WriteAsync("Endpoint is not defined");
                }
            });

            /// <summary>
            /// Цей метод дає змогу використовувати IdentityServer в нашому додатку
            /// </summary>
            /// <remarks>
            /// Додає IdentityServer до конвеєра.
            /// </remarks>
            app.UseIdentityServer();

            /// <summary>
            /// Цей метод дає можливість авторизовуватись, за допомогою AspNetCore реалізацій
            /// </summary>
            /// <remarks>
            /// Додає Microsoft.AspNetCore.Authorization.AuthorizationMiddleware до 
            /// зазначеного IApplicationBuilder, що вмикає можливості авторизації.
            /// </remarks>
            app.UseAuthorization();

            /// <summary>
            /// 
            /// </summary>
            /// <remarks>
            /// Додає Microsoft.AspNetCore.Authentication.AuthenticationMiddleware до
            /// зазначеного Microsoft.AspNetCore.Builder.IApplicationBuilder, 
            /// що вмикає можливості автентифікації.
            /// </remarks>
            app.UseAuthentication();

            /// <summary>
            /// Метод app.UseEndpoints() вбудовує конвеєр обробки компонент EndpointMiddleware. 
            /// Він приймає делегат з одним параметром типу Microsoft.AspNetCore.Routing.IEndpointRouteBuilder,
            /// у якого можна викликати низку методів для встановлення обробника певних маршрутів. 
            /// Зокрема, метод MapGet() додає кінцеву точку для певного маршруту на запит типу GET та її обробник.
            /// </summary>
            /// <remarks>
            /// Додає проміжне програмне забезпечення Microsoft.AspNetCore.Routing.EndpointMiddleware до
            /// вказаного IApplicationBuilder з примірниками Microsoft.AspNetCore.Routing.EndpointDataSource,
            /// створеними з налаштованого Microsoft.AspNetCore.Routing.IEndpointRouteBuilder. 
            /// Програма Microsoft.AspNetCore.Routing.EndpointMiddleware виконає 
            /// Microsoft.AspNetCore.Http.Endpoint, пов’язану з поточним запитом.
            /// </remarks>
            app.UseEndpoints(endpoints =>
            {
                /// <summary>
                /// Використовувати стандартну дорожну карту маршутизації
                /// </summary>
                /// <remarks>
                /// Додає кінцеві точки для дій контролера до Microsoft.AspNetCore.Routing.IEndpointRouteBuilder
                /// і додає маршрут за замовчуванням {controller=Home}/{action=Index}/{id?}.
                /// </remarks>
                endpoints.MapDefaultControllerRoute();

                ///<summary>
                /// Визначено кінцеву точку, яка зіставляється з маршрутом "/Hello" (https://localhost:5001/Hello)
                /// і у відповідь на запит надсилає рядок "Hello World".
                /// </summary>
                endpoints.MapGet("/Hello", async context =>
                {
                    await context.Response.WriteAsync("Hello World!");
                });
            });
        }
    }
}