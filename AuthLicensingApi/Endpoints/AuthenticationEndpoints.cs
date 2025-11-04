using AuthLicensingApi.DTOs;
using AuthLicensingApi.Models;
using Microsoft.IdentityModel.Tokens;
using Microsoft.OpenApi.Models;
using MongoDB.Bson;
using MongoDB.Driver;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace AuthLicensingApi.Endpoints;

public static class AuthenticationEndpoints
{
    public static void MapAuthenticationEndpoints(
        this WebApplication app,
        IMongoCollection<User> users,
        IMongoCollection<License> licenses,
        int bcryptWorkFactor,
        string jwtKey,
        string jwtIssuer,
        string jwtAudience)
    {
        app.MapPost("/register", async (RegisterRequest req, ILogger<Program> logger) =>
        {
            try
            {
                if (string.IsNullOrWhiteSpace(req.Username) || string.IsNullOrWhiteSpace(req.Password))
                    return Results.BadRequest("Username and password required.");

                var exists = await users.Find(u => u.Username == req.Username).AnyAsync();
                if (exists) return Results.Conflict("Username already exists.");

                // Create the user first
                var hash = BCrypt.Net.BCrypt.HashPassword(req.Password, workFactor: bcryptWorkFactor);
                var user = new User { Username = req.Username, PasswordHash = hash };
                await users.InsertOneAsync(user);
                logger.LogInformation("User created: {Username}, Id: {UserId}", user.Username, user.Id);

                // If no license key provided, we are done
                if (string.IsNullOrWhiteSpace(req.LicenseKey))
                {
                    logger.LogInformation("User registered successfully without license: {Username}", user.Username);
                    return Results.Created($"/users/{user.Id}", new { id = user.Id.ToString(), user.Username });
                }

                // Verify license exists
                logger.LogInformation("Attempting to claim license: {LicenseKey}", req.LicenseKey);
                var existingLicense = await licenses.Find(l => l.Key == req.LicenseKey).FirstOrDefaultAsync();
                if (existingLicense is null)
                {
                    logger.LogWarning("License key not found: {LicenseKey}, rolling back user", req.LicenseKey);
                    // rollback user to keep data clean
                    await users.DeleteOneAsync(u => u.Id == user.Id);
                    return Results.BadRequest("License key is invalid.");
                }

                //claim the license only if itss NOT already assigned
                var claimFilter = Builders<License>.Filter.And(
                    Builders<License>.Filter.Eq(l => l.Key, req.LicenseKey),
                    Builders<License>.Filter.Or(
                        Builders<License>.Filter.Exists(l => l.UserId, false),
                        Builders<License>.Filter.Eq(l => l.UserId, ObjectId.Empty),
                        Builders<License>.Filter.Eq(l => l.UserId, default(ObjectId))
                    )
                );

                var claimUpdate = Builders<License>.Update
                    .Set(l => l.UserId, user.Id)
                    .Set(l => l.Status, "active");

                var claimResult = await licenses.UpdateOneAsync(claimFilter, claimUpdate);
                logger.LogInformation("License claim result - Matched: {Matched}, Modified: {Modified}",
                    claimResult.MatchedCount, claimResult.ModifiedCount);

                if (claimResult.ModifiedCount == 0)
                {
                    logger.LogWarning("License already claimed: {LicenseKey}, rolling back user", req.LicenseKey);
                    await users.DeleteOneAsync(u => u.Id == user.Id);
                    return Results.Conflict("License key is already claimed.");
                }

                logger.LogInformation("User registered with license successfully: {Username}, License: {LicenseKey}",
                    user.Username, req.LicenseKey);

                return Results.Created($"/users/{user.Id}", new
                {
                    id = user.Id.ToString(),
                    user.Username,
                    claimedKey = req.LicenseKey
                });
            }
            catch (Exception ex)
            {
                logger.LogError(ex, "Error during registration for username: {Username}", req.Username);
                return Results.Problem(
                    title: "Registration failed",
                    detail: "An unexpected error occurred. Please try again",
                    statusCode: 500
                );
            }
        })
        .RequireRateLimiting("authPolicy")
        .WithTags("Authentication")
        .WithOpenApi(op =>
        {
            op.Summary = "Register a new user (optionally claim a license key)";
            op.Description = """
                Creates a new user with hashed password.
                Optionally accepts a license key to atomically claim an unassigned license.
                Rate limited to mitigate abuse.
                """;
            op.Responses["201"] = new OpenApiResponse { Description = "User successfully registered." };
            op.Responses["400"] = new OpenApiResponse { Description = "Invalid input or license key." };
            op.Responses["409"] = new OpenApiResponse { Description = "Username or license already taken." };
            op.Responses["429"] = new OpenApiResponse { Description = "Too many requests (rate limit hit)." };
            return op;
        });

        app.MapPost("/auth/check", async (AuthRequest req, ILogger<Program> logger) =>
        {
            logger.LogInformation("Authentication attempt for username: {Username}", req.Username);

            var user = await users.Find(u => u.Username == req.Username).FirstOrDefaultAsync();
            if (user is null)
            {
                logger.LogWarning("Authentication failed: User not found - {Username}", req.Username);
                return Results.Unauthorized();
            }

            if (string.IsNullOrWhiteSpace(user.PasswordHash) || user.PasswordHash.Length < 59 || !user.PasswordHash.StartsWith("$2"))
            {
                logger.LogError("Authentication failed: Malformed password hash for user - {Username}", req.Username);
                return Results.Unauthorized(); // malformed or missing hash
            }

            bool ok;
            try { ok = BCrypt.Net.BCrypt.Verify(req.Password, user.PasswordHash); }
            catch (Exception ex)
            {
                logger.LogError(ex, "Password verification failed for user: {Username}", req.Username);
                return Results.Unauthorized();
            }

            if (!ok)
            {
                logger.LogWarning("Authentication failed: Invalid password for user - {Username}", req.Username);
                return Results.Unauthorized();
            }

            var license = await licenses.Find(l => l.UserId == user.Id && l.Key == req.Key && l.Status == "active").FirstOrDefaultAsync();
            if (license is null)
            {
                logger.LogWarning("Authentication failed: License not found or inactive for user - {Username}, License: {LicenseKey}", req.Username, req.Key);
                return Results.Forbid();
            }

            if (license.Subscription is null)
            {
                logger.LogError("License has no subscription data for user: {Username}, License: {LicenseKey}", req.Username, req.Key);
                return Results.Problem("License has no subscription data", statusCode: 500);
            }

            if (license.Subscription.ExpiresAt <= DateTime.UtcNow)
            {
                logger.LogWarning("Authentication failed: License expired for user - {Username}, License: {LicenseKey}, Expired: {ExpiresAt}",
                    req.Username, req.Key, license.Subscription.ExpiresAt);
                return Results.Forbid();
            }

            // Build JWT
            var claims = new[]
            {
                new Claim(ClaimTypes.Name, user.Username),
                new Claim("level", license.Subscription.Level),
                new Claim("licenseKey", license.Key)
            };

            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtKey));
            var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

            var token = new JwtSecurityToken(
                issuer: jwtIssuer,
                audience: jwtAudience,
                claims: claims,
                expires: DateTime.UtcNow.AddMinutes(15),
                signingCredentials: creds);

            var jwtHandler = new JwtSecurityTokenHandler();
            var jwt = jwtHandler.WriteToken(token);

            logger.LogInformation("Authentication successful for user: {Username}, Level: {Level}, License: {LicenseKey}",
                user.Username, license.Subscription.Level, license.Key);

            return Results.Ok(new
            {
                username = user.Username,
                licenseKey = license.Key,
                level = license.Subscription.Level,
                subscriptionExpiresAt = license.Subscription.ExpiresAt,
                accessToken = jwt,
                tokenType = "Bearer",
                tokenIssuedAtUtc = token.IssuedAt.ToUniversalTime(),
                tokenExpiresAtUtc = token.ValidTo.ToUniversalTime(),
                tokenExpiresInSeconds = (int)(token.ValidTo - DateTime.UtcNow).TotalSeconds
            });
        })
        .RequireRateLimiting("authPolicy")
        .WithTags("Authentication")
        .WithOpenApi(op =>
        {
            op.Summary = "Authenticate and validate license";
            op.Description = "Validates username/password and license key. Returns a short-lived JWT on success.";
            op.Responses["200"] = new OpenApiResponse { Description = "Authenticated. JWT returned." };
            op.Responses["401"] = new OpenApiResponse { Description = "Invalid username/password or bad password hash." };
            op.Responses["403"] = new OpenApiResponse { Description = "License missing, inactive, or expired." };
            op.Responses["429"] = new OpenApiResponse { Description = "Too many requests (rate limit hit)." };
            return op;
        });
    }
}
