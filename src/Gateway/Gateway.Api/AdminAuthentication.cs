using System.Security.Claims;
using System.Net;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.HttpOverrides;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;
using SecureIntegration.Gateway.Application;

namespace SecureIntegration.Gateway.Api;

/// <summary>Provider-neutral Admin authentication composition.</summary>
public static class AdminAuthentication
{
    /// <summary>Configures secure cookies and optional server-side OIDC.</summary>
    public static void AddGatewayAdminAuthentication(this WebApplicationBuilder builder, GatewayAdminOptions options)
    {
        bool production = builder.Environment.IsProduction();
        if (production && !string.Equals(options.Mode, "Oidc", StringComparison.Ordinal))
            throw new InvalidOperationException("Production Admin authentication must use OIDC.");
        if (string.Equals(options.Mode, "DevelopmentAuth", StringComparison.Ordinal) && !builder.Environment.IsDevelopment() && !builder.Environment.IsEnvironment("Testing") && !builder.Environment.IsEnvironment("M5Testing"))
            throw new InvalidOperationException("DevelopmentAuth is allowed only in Development or explicit test environments.");
        if (string.Equals(options.Mode, "DevelopmentApiKey", StringComparison.Ordinal) && !builder.Environment.IsEnvironment("M4Testing") && !builder.Environment.IsEnvironment("Testing"))
            throw new InvalidOperationException("DevelopmentApiKey is allowed only in compatibility tests.");

        AuthenticationBuilder authentication = builder.Services
            .AddAuthentication(authenticationOptions =>
            {
                authenticationOptions.DefaultScheme = CookieAuthenticationDefaults.AuthenticationScheme;
                authenticationOptions.DefaultAuthenticateScheme = CookieAuthenticationDefaults.AuthenticationScheme;
                authenticationOptions.DefaultSignInScheme = CookieAuthenticationDefaults.AuthenticationScheme;
                authenticationOptions.DefaultChallengeScheme = string.Equals(options.Mode, "Oidc", StringComparison.Ordinal) ? OpenIdConnectDefaults.AuthenticationScheme : CookieAuthenticationDefaults.AuthenticationScheme;
            })
            .AddCookie(cookie =>
            {
                cookie.Cookie.Name = "__Host-SecureIntegration.Admin";
                cookie.Cookie.HttpOnly = true;
                cookie.Cookie.SecurePolicy = CookieSecurePolicy.Always;
                cookie.Cookie.SameSite = SameSiteMode.Lax;
                cookie.Cookie.Path = "/";
                cookie.SlidingExpiration = true;
                cookie.ExpireTimeSpan = TimeSpan.FromMinutes(20);
                cookie.LoginPath = "/admin/auth/login";
                cookie.AccessDeniedPath = "/admin/access-denied";
                cookie.Events.OnRedirectToLogin = context => ApiAwareRedirect(context, StatusCodes.Status401Unauthorized);
                cookie.Events.OnRedirectToAccessDenied = context => ApiAwareRedirect(context, StatusCodes.Status403Forbidden);
                cookie.Events.OnSigningIn = async context =>
                {
                    if (context.Principal?.FindFirst("sid") is not null) return;
                    AdminExternalIdentity identity = ExternalIdentity(context.Principal ?? throw new InvalidOperationException("Administrative principal missing."));
                    IGatewayClock clock = context.HttpContext.RequestServices.GetRequiredService<IGatewayClock>();
                    IAdminSessionStore store = context.HttpContext.RequestServices.GetRequiredService<IAdminSessionStore>();
                    string? previousHandle = context.HttpContext.User.FindFirst("sid")?.Value;
                    if (!string.IsNullOrWhiteSpace(previousHandle))
                        await store.RevokeAsync(previousHandle, clock.UtcNow, context.HttpContext.RequestAborted).ConfigureAwait(false);
                    (string handle, AdminSessionRecord session) = await store.CreateAsync(identity, clock.UtcNow, TimeSpan.FromHours(8), TimeSpan.FromMinutes(20), context.HttpContext.RequestAborted).ConfigureAwait(false);
                    context.Principal = new ClaimsPrincipal(new ClaimsIdentity([new Claim("sid", handle)], CookieAuthenticationDefaults.AuthenticationScheme, "sid", ClaimTypes.Role));
                    context.Properties.ExpiresUtc = session.IdleExpiresAt;
                    context.Properties.IsPersistent = false;
                };
                cookie.Events.OnValidatePrincipal = async context =>
                {
                    string? handle = context.Principal?.FindFirst("sid")?.Value;
                    IAdminSessionStore store = context.HttpContext.RequestServices.GetRequiredService<IAdminSessionStore>();
                    IGatewayClock clock = context.HttpContext.RequestServices.GetRequiredService<IGatewayClock>();
                    AdminSessionRecord? session = string.IsNullOrWhiteSpace(handle)
                        ? null
                        : await store.ValidateAsync(handle, clock.UtcNow, TimeSpan.FromMinutes(20), context.HttpContext.RequestAborted).ConfigureAwait(false);
                    if (session is null)
                    {
                        context.RejectPrincipal();
                        await context.HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme).ConfigureAwait(false);
                        return;
                    }

                    context.ReplacePrincipal(new ClaimsPrincipal(new ClaimsIdentity(
                    [
                        new Claim("sid", handle!),
                        new Claim("sub", session.Principal.Subject, ClaimValueTypes.String, session.Principal.Issuer),
                        new Claim("iss", session.Principal.Issuer, ClaimValueTypes.String, session.Principal.Issuer),
                        new Claim(ClaimTypes.NameIdentifier, session.Principal.Subject, ClaimValueTypes.String, session.Principal.Issuer)
                    ], CookieAuthenticationDefaults.AuthenticationScheme, "sub", ClaimTypes.Role)));
                };
            });

        if (string.Equals(options.Mode, "Oidc", StringComparison.Ordinal))
        {
            if (!Uri.TryCreate(options.Oidc.Authority, UriKind.Absolute, out Uri? authority) || authority.Scheme != Uri.UriSchemeHttps || string.IsNullOrWhiteSpace(options.Oidc.ClientId) || !options.Oidc.CallbackPath.StartsWith('/'))
                throw new InvalidOperationException("OIDC configuration is incomplete or not HTTPS.");
            string? clientSecret = Environment.GetEnvironmentVariable(options.Oidc.ClientSecretEnvironmentVariable, EnvironmentVariableTarget.Process);
            if (string.IsNullOrWhiteSpace(clientSecret)) throw new InvalidOperationException("OIDC confidential client secret is missing.");
            authentication.AddOpenIdConnect(oidc =>
            {
                oidc.Authority = authority.AbsoluteUri;
                oidc.ClientId = options.Oidc.ClientId;
                oidc.ClientSecret = clientSecret;
                oidc.CallbackPath = options.Oidc.CallbackPath;
                oidc.ResponseType = OpenIdConnectResponseType.Code;
                oidc.ResponseMode = OpenIdConnectResponseMode.FormPost;
                oidc.UsePkce = true;
                oidc.SaveTokens = false;
                oidc.GetClaimsFromUserInfoEndpoint = false;
                oidc.MapInboundClaims = false;
                oidc.Scope.Clear();
                oidc.Scope.Add("openid");
                oidc.Scope.Add("profile");
                oidc.Scope.Add("email");
                oidc.TokenValidationParameters = new TokenValidationParameters
                {
                    ValidateIssuer = true,
                    ValidateAudience = true,
                    ValidateLifetime = true,
                    RequireSignedTokens = true,
                    NameClaimType = "name"
                };
                oidc.Events.OnTokenValidated = context =>
                {
                    ClaimsIdentity identity = (ClaimsIdentity)(context.Principal?.Identity ?? throw new SecurityTokenValidationException("OIDC principal missing."));
                    string issuer = context.SecurityToken.Issuer;
                    string subject = identity.FindFirst("sub")?.Value ?? throw new SecurityTokenValidationException("OIDC subject missing.");
                    if (identity.FindFirst("iss") is null) identity.AddClaim(new Claim("iss", issuer, ClaimValueTypes.String, issuer));
                    if (identity.FindFirst(ClaimTypes.NameIdentifier) is null) identity.AddClaim(new Claim(ClaimTypes.NameIdentifier, subject, ClaimValueTypes.String, issuer));
                    return Task.CompletedTask;
                };
            });
        }

        builder.Services.AddAuthorization();
        builder.Services.AddAntiforgery(antiforgery =>
        {
            antiforgery.Cookie.Name = "__Host-SecureIntegration.Csrf";
            antiforgery.Cookie.HttpOnly = true;
            antiforgery.Cookie.SecurePolicy = CookieSecurePolicy.Always;
            antiforgery.Cookie.SameSite = SameSiteMode.Strict;
            antiforgery.Cookie.Path = "/";
            antiforgery.HeaderName = "X-CSRF-TOKEN";
        });
    }

    private static Task ApiAwareRedirect(RedirectContext<CookieAuthenticationOptions> context, int apiStatus)
    {
        if (context.Request.Path.StartsWithSegments("/admin/api") || context.Request.Headers.Accept.Any(value => value?.Contains("application/json", StringComparison.OrdinalIgnoreCase) == true))
        {
            context.Response.StatusCode = apiStatus;
            return Task.CompletedTask;
        }
        context.Response.Redirect(context.RedirectUri);
        return Task.CompletedTask;
    }

    private static AdminExternalIdentity ExternalIdentity(ClaimsPrincipal principal)
    {
        string issuer = principal.FindFirst("iss")?.Value ?? principal.FindFirst(ClaimTypes.NameIdentifier)?.Issuer ?? string.Empty;
        string subject = principal.FindFirst("sub")?.Value ?? principal.FindFirst(ClaimTypes.NameIdentifier)?.Value ?? string.Empty;
        if (!Uri.TryCreate(issuer, UriKind.Absolute, out Uri? issuerUri) || issuerUri.Scheme != Uri.UriSchemeHttps || string.IsNullOrWhiteSpace(subject) || subject.Length > 256)
            throw new InvalidOperationException("Administrative identity is invalid.");
        string displayName = principal.FindFirst("name")?.Value ?? subject;
        if (displayName.Length > 256) displayName = displayName[..256];
        string? email = principal.FindFirst("email")?.Value;
        if (email?.Length > 320) email = null;
        return new(issuer, subject, displayName, email);
    }
}

/// <summary>Socket-level boundary for synthetic development authentication.</summary>
public static class DevelopmentAuthenticationBoundary
{
    /// <summary>Returns true only for an actual loopback peer; HTTP headers are deliberately irrelevant.</summary>
    public static bool IsLoopbackPeer(IPAddress? remoteAddress) => remoteAddress is not null && IPAddress.IsLoopback(remoteAddress);
}
