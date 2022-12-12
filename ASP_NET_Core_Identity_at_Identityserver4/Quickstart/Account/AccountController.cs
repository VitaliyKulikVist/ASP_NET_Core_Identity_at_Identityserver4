using ASP_NET_Core_Identity_at_Identityserver4.Models;
using IdentityModel;
using IdentityServer4.Events;
using IdentityServer4.Extensions;
using IdentityServer4.Models;
using IdentityServer4.Services;
using IdentityServer4.Stores;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using System;
using System.Linq;
using System.Threading.Tasks;

namespace IdentityServerHost.Quickstart.UI
{
    /// <summary>
    /// Цей клас є основною точкою входу в інтерфейс користувача
    /// </summary>
    [SecurityHeaders]
    [AllowAnonymous] //Атрибут вказує, що клас або метод, до якого застосовано цей атрибут, не потребують авторизації
    public class AccountController : Controller
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly SignInManager<ApplicationUser> _signInManager;
        private readonly IIdentityServerInteractionService _interaction;
        private readonly IClientStore _clientStore;
        private readonly IAuthenticationSchemeProvider _schemeProvider;
        private readonly IEventService _events;

        public AccountController(
            UserManager<ApplicationUser> userManager,
            SignInManager<ApplicationUser> signInManager,
            IIdentityServerInteractionService interaction,
            IClientStore clientStore,
            IAuthenticationSchemeProvider schemeProvider,
            IEventService events)
        {
            _userManager = userManager;
            _signInManager = signInManager;
            _interaction = interaction;
            _clientStore = clientStore;
            _schemeProvider = schemeProvider;
            _events = events;
        }

        /// <summary>
        /// Точка входу в робочий процес входу
        /// </summary>
        [HttpGet]
        public async Task<IActionResult> Login(string returnUrl)
        {
            // build a model so we know what to show on the login page
            var vm = await BuildLoginViewModelAsync(returnUrl);

            if (vm.IsExternalLoginOnly)
            {
                // we only have one option for logging in and it's an external provider
                return RedirectToAction("Challenge", "External", new { scheme = vm.ExternalLoginScheme, returnUrl });
            }

            return View(vm);
        }

        /// <summary>
        /// Обробка зворотного зв’язку від імені користувача/паролю
        /// </summary>
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Login(LoginInputModel model, string button)
        {
            // перевірити, чи ми знаходимося в контексті запиту авторизації
            var context = await _interaction.GetAuthorizationContextAsync(model.ReturnUrl);

            // користувач натиснув кнопку «скасувати».
            if (button != "login")
            {
                if (context != null)
                {
                    // якщо користувач скасовує, надішліть результат назад на IdentityServer,
                    // ніби він відмовив у згоді (навіть якщо цей клієнт не вимагає згоди).
                    // це надішле клієнту відповідь про помилку OIDC заборонено доступ
                    await _interaction.DenyAuthorizationAsync(context, AuthorizationError.AccessDenied);

                    // ми можемо довіряти model.ReturnUrl, оскільки GetAuthorizationContextAsync повернув ненульове значення
                    if (context.IsNativeClient())
                    {
                        // Клієнт є нативним, тому ця зміна способу повернення відповіді призначена
                        // для кращого UX для кінцевого користувача.
                        return this.LoadingPage("Redirect", model.ReturnUrl);
                    }

                    return Redirect(model.ReturnUrl);
                }
                else
                {
                    // оскільки ми не маємо дійсного контексту, ми просто повертаємося на домашню сторінку
                    return Redirect("~/");
                }
            }

            if (ModelState.IsValid)
            {
                var result = await _signInManager.PasswordSignInAsync(model.Username, model.Password, model.RememberLogin, lockoutOnFailure: true);
                if (result.Succeeded)
                {
                    var user = await _userManager.FindByNameAsync(model.Username);
                    await _events.RaiseAsync(new UserLoginSuccessEvent(user.UserName, user.Id, user.UserName, clientId: context?.Client.ClientId));

                    if (context != null)
                    {
                        if (context.IsNativeClient())
                        {
                            // Клієнт є нативним, тому ця зміна способу
                            // повернення відповіді призначена для кращого UX для кінцевого користувача.
                            return this.LoadingPage("Redirect", model.ReturnUrl);
                        }

                        // ми можемо довіряти model.ReturnUrl, оскільки GetAuthorizationContextAsync повернув ненульове значення
                        return Redirect(model.ReturnUrl);
                    }

                    // запит на локальну сторінку
                    if (Url.IsLocalUrl(model.ReturnUrl))
                    {
                        return Redirect(model.ReturnUrl);
                    }
                    else if (string.IsNullOrEmpty(model.ReturnUrl))
                    {
                        return Redirect("~/");
                    }
                    else
                    {
                        // користувач міг натиснути на зловмисне посилання - слід зареєструватися
                        throw new Exception("invalid return URL");
                    }
                }

                await _events.RaiseAsync(new UserLoginFailureEvent(model.Username, "invalid credentials", clientId: context?.Client.ClientId));
                ModelState.AddModelError(string.Empty, AccountOptions.InvalidCredentialsErrorMessage);
            }

            // Якщо все добре зібрати інформамцію яка необхідна для вікна авторизації і відобразити разом
            // з способом авторизації відмінним від звичайного логіна і пароля(в даному прикладі гугл)
            var vm = await BuildLoginViewModelAsync(model);
            return View(vm);
        }


        /// <summary>
        /// Показати сторінку виходу
        /// </summary>
        [HttpGet]
        public async Task<IActionResult> Logout(string logoutId)
        {
            // створити модель, щоб сторінка виходу знала, що відображати
            var vm = await BuildLogoutViewModelAsync(logoutId);

            if (vm.ShowLogoutPrompt == false)
            {
                // якщо запит на вихід було належним чином автентифіковано на IdentityServer,
                // тоді нам не потрібно показувати підказку, і ми можемо просто вийти з системи безпосередньо.
                return await Logout(vm);
            }

            return View(vm);
        }

        /// <summary>
        /// Обробляти зворотне повідомлення сторінки виходу
        /// </summary>
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Logout(LogoutInputModel model)
        {
            // створити модель, щоб сторінка, яка вийшла з системи, знала, що відображати
            var vm = await BuildLoggedOutViewModelAsync(model.LogoutId);

            if (User?.Identity.IsAuthenticated == true)
            {
                // видалити файл cookie локальної автентифікації
                await _signInManager.SignOutAsync();

                // викликати подію виходу
                await _events.RaiseAsync(new UserLogoutSuccessEvent(User.GetSubjectId(), User.GetDisplayName()));
            }

            // перевірити, чи потрібно нам ініціювати вихід із облікового запису
            // у вищестоящого постачальника ідентифікаційної інформації
            if (vm.TriggerExternalSignout)
            {
                // створіть зворотну URL-адресу, щоб вихідний постачальник перенаправляв
                // назад до нас після того, як користувач вийшов із системи.
                // це дозволяє нам завершити обробку єдиного виходу.
                string url = Url.Action("Logout", new { logoutId = vm.LogoutId });

                // це запускає переспрямування до зовнішнього постачальника для виходу
                return SignOut(new AuthenticationProperties { RedirectUri = url }, vm.ExternalAuthenticationScheme);
            }

            return View("LoggedOut", vm);
        }

        [HttpGet]
        public IActionResult AccessDenied()
        {
            return View();
        }


        /*****************************************/
        /* допоміжні API для AccountController */
        /*****************************************/
        private async Task<LoginViewModel> BuildLoginViewModelAsync(string returnUrl)
        {
            var context = await _interaction.GetAuthorizationContextAsync(returnUrl);
            if (context?.IdP != null && await _schemeProvider.GetSchemeAsync(context.IdP) != null)
            {
                var local = context.IdP == IdentityServer4.IdentityServerConstants.LocalIdentityProvider;

                // це призначено для короткого замикання інтерфейсу користувача та запуску лише одного зовнішнього IdP
                var vm = new LoginViewModel
                {
                    EnableLocalLogin = local,
                    ReturnUrl = returnUrl,
                    Username = context?.LoginHint,
                };

                if (!local)
                {
                    vm.ExternalProviders = new[] { new ExternalProvider { AuthenticationScheme = context.IdP } };
                }

                return vm;
            }

            var schemes = await _schemeProvider.GetAllSchemesAsync();

            var providers = schemes
                .Where(x => x.DisplayName != null)
                .Select(x => new ExternalProvider
                {
                    DisplayName = x.DisplayName ?? x.Name,
                    AuthenticationScheme = x.Name
                }).ToList();

            var allowLocal = true;
            if (context?.Client.ClientId != null)
            {
                var client = await _clientStore.FindEnabledClientByIdAsync(context.Client.ClientId);
                if (client != null)
                {
                    allowLocal = client.EnableLocalLogin;

                    if (client.IdentityProviderRestrictions != null && client.IdentityProviderRestrictions.Any())
                    {
                        providers = providers.Where(provider => client.IdentityProviderRestrictions.Contains(provider.AuthenticationScheme)).ToList();
                    }
                }
            }

            return new LoginViewModel
            {
                AllowRememberLogin = AccountOptions.AllowRememberLogin,
                EnableLocalLogin = allowLocal && AccountOptions.AllowLocalLogin,
                ReturnUrl = returnUrl,
                Username = context?.LoginHint,
                ExternalProviders = providers.ToArray()
            };
        }

        private async Task<LoginViewModel> BuildLoginViewModelAsync(LoginInputModel model)
        {
            var vm = await BuildLoginViewModelAsync(model.ReturnUrl);
            vm.Username = model.Username;
            vm.RememberLogin = model.RememberLogin;
            return vm;
        }

        private async Task<LogoutViewModel> BuildLogoutViewModelAsync(string logoutId)
        {
            var vm = new LogoutViewModel { LogoutId = logoutId, ShowLogoutPrompt = AccountOptions.ShowLogoutPrompt };

            if (User?.Identity.IsAuthenticated != true)
            {
                // якщо користувач не автентифікований, то просто показати сторінку виходу з системи
                vm.ShowLogoutPrompt = false;
                return vm;
            }

            var context = await _interaction.GetLogoutContextAsync(logoutId);
            if (context?.ShowSignoutPrompt == false)
            {
                // це безпечно для автоматичного виходу
                vm.ShowLogoutPrompt = false;
                return vm;
            }

            // показати підказку виходу. це запобігає атакам, коли користувач автоматично
            // виходить із системи на іншій шкідливій веб-сторінці
            return vm;
        }

        private async Task<LoggedOutViewModel> BuildLoggedOutViewModelAsync(string logoutId)
        {
            // отримати контекстну інформацію (ім’я клієнта,
            // URI перенаправлення після виходу з системи та iframe для об’єднаного виходу)
            var logout = await _interaction.GetLogoutContextAsync(logoutId);

            var vm = new LoggedOutViewModel
            {
                AutomaticRedirectAfterSignOut = AccountOptions.AutomaticRedirectAfterSignOut,
                PostLogoutRedirectUri = logout?.PostLogoutRedirectUri,
                ClientName = string.IsNullOrEmpty(logout?.ClientName) ? logout?.ClientId : logout?.ClientName,
                SignOutIframeUrl = logout?.SignOutIFrameUrl,
                LogoutId = logoutId
            };

            if (User?.Identity.IsAuthenticated == true)
            {
                var idp = User.FindFirst(JwtClaimTypes.IdentityProvider)?.Value;
                if (idp != null && idp != IdentityServer4.IdentityServerConstants.LocalIdentityProvider)
                {
                    var providerSupportsSignout = await HttpContext.GetSchemeSupportsSignOutAsync(idp);
                    if (providerSupportsSignout)
                    {
                        if (vm.LogoutId == null)
                        {
                            // якщо немає поточного контексту виходу, нам потрібно створити такий,
                            // який фіксуватиме необхідну інформацію від поточного користувача,
                            // який увійшов у систему, перш ніж вийти з системи та переспрямувати його
                            // до зовнішнього IdP для виходу
                            vm.LogoutId = await _interaction.CreateLogoutContextAsync();
                        }

                        vm.ExternalAuthenticationScheme = idp;
                    }
                }
            }

            return vm;
        }
    }
}