using ASP_NET_Core_Identity_at_Identityserver4.Data;
using ASP_NET_Core_Identity_at_Identityserver4.Models;
using IdentityServer4;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;

namespace ASP_NET_Core_Identity_at_Identityserver4
{
    /// <summary>
    /// Головний клас в якому відбувається підключення сервісів конфігурування налаштувань для роботи арі
    /// </summary>
    /// <remarks>
    /// 
    /// </remarks>
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
            //додає в колекцію сервісів сервіси, які необхідні роботи контролерів MVC
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
            services.AddIdentity<ApplicationUser, IdentityRole>()//Додає стандартну конфігурацію системи ідентифікації для вказаних типів користувачів і ролей
                .AddEntityFrameworkStores<ApplicationDbContext>()//Додає реалізацію Entity Framework сховищ ідентифікаційної інформації
                .AddDefaultTokenProviders();//Додає постачальників токенів за замовчуванням, які використовуються для створення токенів для скидання паролів, зміни електронної пошти та номерів телефону, а також для генерації токенів двофакторної автентифікації

            var builder = services.AddIdentityServer(options =>
            {
                options.Events.RaiseErrorEvents = true;
                options.Events.RaiseInformationEvents = true;
                options.Events.RaiseFailureEvents = true;
                options.Events.RaiseSuccessEvents = true;

                // see https://identityserver4.readthedocs.io/en/latest/topics/resources.html
                options.EmitStaticAudienceClaim = true;
            })
                .AddInMemoryIdentityResources(Config.IdentityResources)
                .AddInMemoryApiScopes(Config.ApiScopes)
                .AddInMemoryClients(Config.Clients)
                .AddAspNetIdentity<ApplicationUser>();

            // not recommended for production - you need to store your key material somewhere secure
            builder.AddDeveloperSigningCredential();

            services.AddAuthentication()
                .AddGoogle(options =>
                {
                    options.SignInScheme = IdentityServerConstants.ExternalCookieAuthenticationScheme;

                    // register your IdentityServer with Google at https://console.developers.google.com
                    // enable the Google+ API
                    // set the redirect URI to https://localhost:5001/signin-google
                    options.ClientId = "copy client ID from Google here";
                    options.ClientSecret = "copy client secret from Google here";
                });
        }

        public void Configure(IApplicationBuilder app)
        {
            if (Environment.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
                app.UseDatabaseErrorPage();
            }

            app.UseStaticFiles();

            app.UseRouting();
            app.UseIdentityServer();
            app.UseAuthorization();
            app.UseEndpoints(endpoints =>
            {
                endpoints.MapDefaultControllerRoute();
            });
        }
    }
}