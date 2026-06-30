using Dapper;
using Microsoft.Data.SqlClient;
using Microsoft.Extensions.FileProviders;
using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Http;

// ── Bootstrap ──────────────────────────────────────────────────────────────────

var builder = WebApplication.CreateBuilder(args);


builder.Services.AddHttpClient();
builder.Services.AddMemoryCache();
builder.Services.AddDistributedMemoryCache();
builder.Services.AddSession(o =>
{
    o.Cookie.HttpOnly  = true;
    o.Cookie.IsEssential = true;
    o.Cookie.SameSite = SameSiteMode.None;
    o.Cookie.SecurePolicy = CookieSecurePolicy.SameAsRequest; // Allows HTTP for localhost testing, strictly requires HTTPS for production iframes
    o.IdleTimeout      = TimeSpan.FromHours(8);
});

builder.Services.Configure<Microsoft.AspNetCore.Builder.ForwardedHeadersOptions>(options =>
{
    options.ForwardedHeaders = Microsoft.AspNetCore.HttpOverrides.ForwardedHeaders.XForwardedFor | Microsoft.AspNetCore.HttpOverrides.ForwardedHeaders.XForwardedProto;
});

builder.Services.ConfigureHttpJsonOptions(o =>
{
    o.SerializerOptions.PropertyNamingPolicy      = JsonNamingPolicy.CamelCase;
    o.SerializerOptions.DefaultIgnoreCondition    = JsonIgnoreCondition.WhenWritingNull;
});


var app = builder.Build();

// ── Resolve persistent uploads path ────────────────────────────────────────
// Read from appsettings.json → ThreatMap:UploadsPath.  Falls back to "wwwroot/uploads".
// Relative paths are resolved against ContentRootPath so they survive republish.
var cfgUploadsPath = app.Configuration["ThreatMap:UploadsPath"] ?? "wwwroot/uploads";
var uploadsDir = Path.IsPathRooted(cfgUploadsPath)
    ? cfgUploadsPath
    : Path.Combine(app.Environment.ContentRootPath, cfgUploadsPath);
Directory.CreateDirectory(uploadsDir);

app.Logger.LogInformation("ThreatMap uploads path : {UploadsDir}", uploadsDir);
app.Logger.LogInformation("ContentRoot: {Root}", app.Environment.ContentRootPath);

// Middleware order: ForwardedHeaders -> Session → StaticFiles → routing
app.UseForwardedHeaders();
app.UseSession();

app.Use(async (context, next) =>
{
    // Remove X-Frame-Options to allow frame-ancestors to take precedence in modern browsers
    context.Response.Headers.Remove("X-Frame-Options");
    // Allow embedding from AVEVA domains:
    context.Response.Headers.Append("Content-Security-Policy", "frame-ancestors 'self' https://*.aveva.com;");
    await next();
});

var defaultFilesOptions = new DefaultFilesOptions();
defaultFilesOptions.DefaultFileNames.Clear();
defaultFilesOptions.DefaultFileNames.Add("viewer.html");
app.UseDefaultFiles(defaultFilesOptions);
app.UseStaticFiles();    // serves wwwroot/**

// Serve the external uploads directory at /uploads
app.UseStaticFiles(new StaticFileOptions
{
    FileProvider = new PhysicalFileProvider(uploadsDir),
    RequestPath  = "/uploads"
});

// ── Helpers ────────────────────────────────────────────────────────────────────

SqlConnection GetConn(IConfiguration cfg) =>
    new(cfg.GetConnectionString("Default")
        ?? throw new InvalidOperationException("ConnectionStrings:Default not configured"));

// SHA-256 of "plot@dmin" = 972767bda2552413355f626947b287d3d66a5f3c5640d10861bf36f8bc895edb
// To rotate: replace hash with SHA256(newPassword) and redeploy.
const string AdminUser         = "admin";
const string AdminPasswordHash = "972767bda2552413355f626947b287d3d66a5f3c5640d10861bf36f8bc895edb";

static string Sha256Hex(string s)
{
    var bytes = System.Security.Cryptography.SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(s));
    return Convert.ToHexString(bytes).ToLowerInvariant();
}

static async Task<string> Sha256HexStream(Stream stream)
{
    var bytes = await System.Security.Cryptography.SHA256.HashDataAsync(stream);
    return Convert.ToHexString(bytes).ToLowerInvariant();
}

bool IsAdmin(HttpContext ctx) => ctx.Session.GetString("admin") == AdminUser;

// ── GET /session ───────────────────────────────────────────────────────────────

app.MapGet("/session", (HttpContext ctx) =>
    Results.Json(new { authenticated = IsAdmin(ctx) }));

// ── POST /login ────────────────────────────────────────────────────────────────

app.MapPost("/login", (HttpContext ctx, LoginRequest body) =>
{
    if (string.IsNullOrWhiteSpace(body.Username) || string.IsNullOrWhiteSpace(body.Password))
        return Results.BadRequest(new { error = "Username and password are required" });

    if (!string.Equals(body.Username.Trim(), AdminUser, StringComparison.OrdinalIgnoreCase)
        || Sha256Hex(body.Password) != AdminPasswordHash)
        return Results.Json(new { error = "Invalid credentials" }, statusCode: 401);

    ctx.Session.SetString("admin", AdminUser);
    return Results.Json(new { success = true, username = AdminUser });
});

// ── POST /logout ───────────────────────────────────────────────────────────────

app.MapPost("/logout", (HttpContext ctx) =>
{
    ctx.Session.Clear();
    return Results.Json(new { success = true });
});

// ── GET /layout/active  (single active layout for viewer + editor restore) ────

app.MapGet("/layout/active", async (HttpContext ctx, IConfiguration cfg) =>
{
    using var db = GetConn(cfg);
    await db.OpenAsync();

    var plot = await db.QueryFirstOrDefaultAsync(
        "SELECT TOP 1 * FROM Plots WHERE IsActive = 1 " +
        "ORDER BY IsPublished DESC, PublishedAt DESC, CreatedAt DESC");

    if (plot is null)
        return Results.Json(new { status = "empty" });

    // Check if the image file physically exists
    var imagePath = (string?)plot.ImagePath;
    bool imageExists = !string.IsNullOrEmpty(imagePath)
        && File.Exists(Path.Combine(uploadsDir, imagePath));
        
    app.Logger.LogInformation(
    "Checking active image path: {Path} Exists={Exists}",
    Path.Combine(uploadsDir, imagePath),
    imageExists
);
    if (!imageExists)
        return Results.Json(new { status = "missing", plotId = (string)plot.PlotId });

    // Viewer can only see published active layout; admin can see draft too
    if (!(bool)plot.IsPublished && !IsAdmin(ctx))
        return Results.Json(new { status = "empty" });

    var zones = await db.QueryAsync(
        "SELECT UnitId, Shape, GeometryJson, DisplayOrder FROM Zones WHERE PlotId = @id ORDER BY DisplayOrder",
        new { id = (string)plot.PlotId });

    var threats = await db.QueryAsync(
        "SELECT UnitId, Score, ShortTerm, LongTerm, Status, ThreatLevel FROM Threats WHERE PlotId = @id",
        new { id = (string)plot.PlotId });

    return Results.Json(new
    {
        status      = "ok",
        plotId      = (string)plot.PlotId,
        plotName    = (string)plot.PlotName,
        displayName = (string?)plot.DisplayName,
        imageUrl    = $"uploads/{imagePath}",
        isPublished = (bool)plot.IsPublished,
        publishedAt = plot.PublishedAt is null ? null : ((DateTime)plot.PublishedAt).ToString("o"),
        zones = zones.Select(z => new
        {
            unitId       = (string)z.UnitId,
            shape        = (string)z.Shape,
            geometry     = JsonSerializer.Deserialize<JsonElement>((string)z.GeometryJson),
            displayOrder = (int)z.DisplayOrder
        }),
        threats = threats.Select(t => new
        {
            unitId      = (string)t.UnitId,
            score       = (double?)t.Score,
            shortTerm   = (double?)t.ShortTerm,
            longTerm    = (double?)t.LongTerm,
            status      = (string?)t.Status,
            threatLevel = (string?)t.ThreatLevel
        })
    });
});

// ── POST /plots  (upload image → single active layout, with hash dedup) ───────

app.MapPost("/plots", async (HttpContext ctx, IConfiguration cfg) =>
{
    if (!IsAdmin(ctx)) return Results.Unauthorized();

    var form        = await ctx.Request.ReadFormAsync();
    var displayName = form["plotName"].ToString().Trim();

    if (string.IsNullOrEmpty(displayName))
        return Results.BadRequest(new { error = "plotName is required" });

    var file = form.Files.GetFile("image");
    if (file is null || file.Length == 0)
        return Results.BadRequest(new { error = "image file is required" });

    var ext     = Path.GetExtension(file.FileName).ToLowerInvariant();
    var allowed = new[] { ".png", ".jpg", ".jpeg", ".gif", ".webp" };
    if (!allowed.Contains(ext))
        return Results.BadRequest(new { error = "Invalid image file type" });

    // Compute SHA-256 of the uploaded file for duplicate detection
    string imageHash;
    await using (var hashStream = file.OpenReadStream())
        imageHash = await Sha256HexStream(hashStream);

    using var db = GetConn(cfg);
    await db.OpenAsync();

    // ── Duplicate detection: same image hash across ALL layouts ──────
    var existingRows = (await db.QueryAsync(
        "SELECT p.PlotId, " +
        "       p.PlotName, " +
        "       p.DisplayName, " +
        "       p.ImagePath, " +
        "       p.IsPublished, " +
        "       p.PublishedAt, " +
        "       p.IsActive, " +
        "       p.CreatedAt, " +
        "       COUNT(z.ZoneId) AS ZoneCount " +
        "FROM Plots p " +
        "LEFT JOIN Zones z ON z.PlotId = p.PlotId " +
        "WHERE p.ImageHash = @imageHash " +
        "GROUP BY p.PlotId, " +
        "         p.PlotName, " +
        "         p.DisplayName, " +
        "         p.ImagePath, " +
        "         p.IsPublished, " +
        "         p.PublishedAt, " +
        "         p.IsActive, " +
        "         p.CreatedAt",
        new { imageHash })).ToList();

    var existing = existingRows
        .Select(r => new
        {
            Row = r,
            ImagePresent = !string.IsNullOrEmpty((string?)r.ImagePath)
                && File.Exists(Path.Combine(uploadsDir, (string)r.ImagePath))
        })
        .OrderByDescending(x => x.ImagePresent)
        .ThenByDescending(x => (bool)x.Row.IsPublished)
        .ThenByDescending(x => (int)x.Row.ZoneCount)
        .ThenByDescending(x => (DateTime)x.Row.CreatedAt)
        .FirstOrDefault();

    if (existing is not null)
    {
        var existingRow = existing.Row;
        var existingImagePath = (string)existingRow.ImagePath;
        bool existingFilePresent = existing.ImagePresent;

        if (existingFilePresent)
        {
            // If it's an inactive layout, reactivate it and deactivate the current one
            if (!(bool)existingRow.IsActive)
            {
                using var reactivateTx = db.BeginTransaction();
                try
                {
                    await db.ExecuteAsync("UPDATE Plots SET IsActive = 0 WHERE IsActive = 1", transaction: reactivateTx);
                    await db.ExecuteAsync("UPDATE Plots SET IsActive = 1 WHERE PlotId = @id", new { id = (string)existingRow.PlotId }, transaction: reactivateTx);
                    reactivateTx.Commit();
                }
                catch
                {
                    reactivateTx.Rollback();
                    throw;
                }
            }

            // True duplicate: same image AND file is on disk → restore existing layout
            return Results.Json(new
            {
                plotId      = (string)existingRow.PlotId,
                plotName    = (string)existingRow.PlotName,
                displayName = (string?)existingRow.DisplayName,
                imageUrl    = $"uploads/{existingImagePath}",
                isPublished = (bool)existingRow.IsPublished,
                duplicate   = true
            }, statusCode: 200);
        }

        // Orphaned layout: hash matches but image is missing from disk.
        // Deactivate the stale DB row and fall through to normal upload.
        app.Logger.LogWarning(
            "Orphaned layout {PlotId}: hash matched but image file missing. Deactivating.",
            (string)existingRow.PlotId);
        if ((bool)existingRow.IsActive)
        {
            await db.ExecuteAsync(
                "UPDATE Plots SET IsActive = 0 WHERE PlotId = @id",
                new { id = (string)existingRow.PlotId });
        }
    }

    // ── New image: save file, deactivate old layout, create new active one ──────
    var plotId   = Guid.NewGuid().ToString("N");
    var filename = plotId + ext;
    var savePath = Path.Combine(uploadsDir, filename);

    await using (var fs = File.Create(savePath))
    {
        await file.OpenReadStream().CopyToAsync(fs);
    }

    using var tx = db.BeginTransaction();
    try
    {
        // Deactivate all previous layouts
        await db.ExecuteAsync("UPDATE Plots SET IsActive = 0 WHERE IsActive = 1", transaction: tx);

        // Insert new active layout
        await db.ExecuteAsync(
            "INSERT INTO Plots (PlotId, PlotName, DisplayName, ImagePath, ImageHash, IsPublished, IsActive, CreatedAt) " +
            "VALUES (@plotId, @plotName, @displayName, @imagePath, @imageHash, 0, 1, SYSUTCDATETIME())",
            new { plotId, plotName = displayName, displayName, imagePath = filename, imageHash },
            transaction: tx);

        tx.Commit();
    }
    catch
    {
        tx.Rollback();
        // Clean up saved file on DB failure
        try { if (File.Exists(savePath)) File.Delete(savePath); } catch { }
        throw;
    }

    return Results.Json(
        new { plotId, plotName = displayName, displayName, imageUrl = $"uploads/{filename}", duplicate = false },
        statusCode: 201);
});

// ── GET /plots/published  (viewer dropdown) ───────────────────────────────────

app.MapGet("/plots/published", async (IConfiguration cfg) =>
{
    using var db = GetConn(cfg);
    var rows = await db.QueryAsync(
        "SELECT PlotId, PlotName, ImagePath, PublishedAt " +
        "FROM Plots WHERE IsPublished = 1 ORDER BY PublishedAt DESC");

    return Results.Json(rows.Select(r => new
    {
        plotId      = (string)r.PlotId,
        plotName    = (string)r.PlotName,
        publishedAt = r.PublishedAt is null ? null : ((DateTime)r.PublishedAt).ToString("o"),
        imageUrl    = r.ImagePath is null ? null : $"uploads/{r.ImagePath}"
    }));
});

// ── GET /plots/{id} ───────────────────────────────────────────────────────────

app.MapGet("/plots/{id}", async (string id, HttpContext ctx, IConfiguration cfg) =>
{
    using var db = GetConn(cfg);
    await db.OpenAsync();

    var plot = await db.QueryFirstOrDefaultAsync(
        "SELECT * FROM Plots WHERE PlotId = @id", new { id });
    if (plot is null)
        return Results.NotFound(new { error = "Plot not found" });

    // Draft plots are only visible to logged-in admin
    if (!(bool)plot.IsPublished && !IsAdmin(ctx))
        return Results.Json(new { error = "Authentication required" }, statusCode: 401);

    var zones = await db.QueryAsync(
        "SELECT UnitId, Shape, GeometryJson, DisplayOrder " +
        "FROM Zones WHERE PlotId = @id ORDER BY DisplayOrder",
        new { id });

    var threats = await db.QueryAsync(
        "SELECT UnitId, Score, ShortTerm, LongTerm, Status, ThreatLevel " +
        "FROM Threats WHERE PlotId = @id",
        new { id });

    return Results.Json(new
    {
        plotId      = (string)plot.PlotId,
        plotName    = (string)plot.PlotName,
        imageUrl    = plot.ImagePath is null ? null : $"uploads/{plot.ImagePath}",
        isPublished = (bool)plot.IsPublished,
        publishedAt = plot.PublishedAt is null ? null : ((DateTime)plot.PublishedAt).ToString("o"),
        zones       = zones.Select(z => new
        {
            unitId       = (string)z.UnitId,
            shape        = (string)z.Shape,
            geometry     = JsonSerializer.Deserialize<JsonElement>((string)z.GeometryJson),
            displayOrder = (int)z.DisplayOrder
        }),
        threats = threats.Select(t => new
        {
            unitId      = (string)t.UnitId,
            score       = (double?)t.Score,
            shortTerm   = (double?)t.ShortTerm,
            longTerm    = (double?)t.LongTerm,
            status      = (string?)t.Status,
            threatLevel = (string?)t.ThreatLevel
        })
    });
});
// ── GET /api/threats/live ─────────────────────────────────────────────────────

// Fix 2: Robust MTO score parser — strips commas, handles empty/null safely
static long ParseScore(string? raw)
{
    if (string.IsNullOrWhiteSpace(raw)) return 0;
    raw = raw.Replace(",", "").Trim();
    return long.TryParse(raw, out var score) ? score : 0;
}

app.MapGet("/api/threats/live", async (IHttpClientFactory httpFactory, IMemoryCache cache, IConfiguration cfg, ILogger<Program> logger) =>
{
    if (cache.TryGetValue("LiveThreats", out Dictionary<string, LiveThreatUnitSummaryDto>? cachedResult))
        return Results.Json(cachedResult);

    var url = cfg["ThreatMap:AimDataRetrieveUrl"];

    try
    {
        string raw;

        // Fix 4: Mock-file injection — separate config key, never mixed with real URL
        var mockFile = cfg["ThreatMap:MockThreatFile"];
        if (!string.IsNullOrWhiteSpace(mockFile) && File.Exists(mockFile))
        {
            raw = await File.ReadAllTextAsync(mockFile);
            logger.LogInformation("[LiveThreats] Using mock threat file: {File}", mockFile);
        }
        else
        {
            if (string.IsNullOrEmpty(url))
                return Results.Json(new Dictionary<string, LiveThreatUnitSummaryDto>());

            HttpClient client;
            var handler = new HttpClientHandler
            {
                UseDefaultCredentials = true,
                ServerCertificateCustomValidationCallback = HttpClientHandler.DangerousAcceptAnyServerCertificateValidator
            };
            client = new HttpClient(handler);
            var payload = new { fullId = "fff", sqlId = "ThreatDetails" };
            var fetchUrl = url.EndsWith("FetchData", StringComparison.OrdinalIgnoreCase)
                ? url
                : url.TrimEnd('/') + "/FetchData";

            logger.LogInformation(
                "[LiveThreats] Calling DataRetrieve Url={Url}, FullId={FullId}, SqlId={SqlId}, UseDefaultCredentials={UseDefaultCredentials}, EnvUser={EnvUser}, WindowsIdentity={WindowsIdentity}",
                fetchUrl,
                payload.fullId,
                payload.sqlId,
                handler.UseDefaultCredentials,
                Environment.UserName,
                System.Security.Principal.WindowsIdentity.GetCurrent()?.Name
            );

            var request = new HttpRequestMessage(HttpMethod.Post, fetchUrl);
            request.Content = JsonContent.Create(payload);
            request.Headers.Add("X-Requested-With", "XMLHttpRequest");
            request.Headers.Accept.ParseAdd("application/json");

            var response = await client.SendAsync(request);
            var responseText = await response.Content.ReadAsStringAsync();

            logger.LogInformation(
                "[LiveThreats] Response Status={Status}, Reason={Reason}, WwwAuth={Auth}, Body={Body}",
                (int)response.StatusCode,
                response.ReasonPhrase,
                string.Join(" | ", response.Headers.WwwAuthenticate.Select(x => x.ToString())),
                responseText.Length > 500 ? responseText[..500] : responseText
            );

            if (!response.IsSuccessStatusCode)
            {
                logger.LogError("[LiveThreats] Non-success response");
                return Results.Json(new Dictionary<string, LiveThreatUnitSummaryDto>());
            }

            raw = responseText;
            logger.LogInformation("RAW RESPONSE: {Raw}", raw);
        }

        var aimResponse = JsonSerializer.Deserialize<AimDataRetrieveResponse>(raw, new JsonSerializerOptions { PropertyNameCaseInsensitive = true });
        logger.LogInformation("Rows count: {Count}", aimResponse?.D?.Total ?? -1);
        var rawRows = aimResponse?.D?.Rows ?? new List<List<AimFieldDto>>();

        var parsedThreats = new List<AimThreatDto>();
        foreach (var rowCells in rawRows)
        {
            // Fix 1: Safer dictionary — OrdinalIgnoreCase, overwrites dupes, skips blank fields
            var dict = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            foreach (var c in rowCells)
                if (!string.IsNullOrWhiteSpace(c.Field))
                    dict[c.Field] = c.Value ?? "";

            string GetVal(string key) => dict.TryGetValue(key, out var v) ? v : string.Empty;

            string primaryRam = GetVal("PrimaryRAM");
            if (string.IsNullOrEmpty(primaryRam)) primaryRam = GetVal("OverallRAM");
            if (string.IsNullOrEmpty(primaryRam)) primaryRam = GetVal("RAM");
            if (string.IsNullOrEmpty(primaryRam)) primaryRam = "E0";

            string mtoScore = GetVal("MTOScore");
            if (string.IsNullOrEmpty(mtoScore)) mtoScore = "0";

            string hsscRam = GetVal("HSSCRAM");
            if (string.IsNullOrEmpty(hsscRam)) {
                hsscRam = primaryRam == "D5" ? "C4" : (primaryRam == "C4" ? "B5" : "E0");
            }
            string hsscScore = GetVal("HSSCScore");
            if (string.IsNullOrEmpty(hsscScore)) {
                long s = ParseScore(mtoScore);
                hsscScore = s > 0 ? (s * 0.8).ToString("N0") : "0";
            }

            string prodRam = GetVal("ProductionRAM");
            if (string.IsNullOrEmpty(prodRam)) {
                prodRam = primaryRam == "D5" ? "B3" : (primaryRam == "C4" ? "E0" : "D4");
            }
            string prodScore = GetVal("ProductionScore");
            if (string.IsNullOrEmpty(prodScore)) {
                long s = ParseScore(mtoScore);
                prodScore = s > 0 ? (s * 0.5).ToString("N0") : "0";
            }

            parsedThreats.Add(new AimThreatDto(
                ThreatID:               GetVal("ThreatID"),
                ThreatClass:            GetVal("ThreatClass"),
                InitiativeName:         GetVal("InitiativeName"),
                Workstream:             GetVal("Workstream"),
                ThreatUnit:             GetVal("ThreatUnit"),
                UnitDescription:        GetVal("UnitDescription"),
                MTOScore:               mtoScore,
                ThreatDiscipline:       GetVal("ThreatDiscipline"),
                PrimaryRAM:             primaryRam,
                CreatedDate:            GetVal("CreatedDate"),
                ThreatType:             GetVal("ThreatType"),
                OverallStatus:          GetVal("OverallStatus"),
                OverallStatusCommentary:GetVal("OverallStatusCommentary"),
                ThreatURL:              GetVal("ThreatURL"),
                Tag:                    GetVal("Tag"),
                EQS:                    GetVal("EQS"),
                HSSCRAM:                hsscRam,
                HSSCScore:              hsscScore,
                ProductionRAM:          prodRam,
                ProductionScore:        prodScore
            ));
        }

        var grouped = parsedThreats.GroupBy(r => r.ThreatUnit.Length > 0 ? r.ThreatUnit : "Unknown")
            .ToDictionary(
                g => g.Key,
                g => new LiveThreatUnitSummaryDto(
                    Threats: g.Count(),
                    // Fix 2: Use ParseScore helper instead of inline TryParse
                    Score:   g.Sum(x => ParseScore(x.MTOScore)),
                    Details: g.ToList()
                ));

        // Fix 3: Only cache if AIM actually returned data — don't cache empty-success
        if (grouped.Count > 0)
            cache.Set("LiveThreats", grouped, TimeSpan.FromMinutes(5));

        return Results.Json(grouped);
    }
    catch (Exception ex)
    {
        logger.LogError(ex, "[LiveThreats] Error fetching live threats");
        return Results.Json(new Dictionary<string, LiveThreatUnitSummaryDto>());
    }
});

// ── GET /plots/{id}/threats ───────────────────────────────────────────────────

app.MapGet("/plots/{id}/threats", async (string id, HttpContext ctx, IConfiguration cfg) =>
{
    using var db = GetConn(cfg);
    await db.OpenAsync();

    var plot = await db.QueryFirstOrDefaultAsync(
        "SELECT PlotId, IsPublished FROM Plots WHERE PlotId = @id",
        new { id });

    if (plot is null)
        return Results.NotFound(new { error = "Plot not found" });

    // Draft plots only visible to admin
    if (!(bool)plot.IsPublished && !IsAdmin(ctx))
        return Results.Json(new { error = "Authentication required" }, statusCode: 401);

    var threats = await db.QueryAsync(
        "SELECT UnitId, Score, ShortTerm, LongTerm, Status, ThreatLevel " +
        "FROM Threats WHERE PlotId = @id",
        new { id });

    return Results.Json(
        threats.Select(t => new
        {
            unitId      = (string)t.UnitId,
            score       = (double?)t.Score,
            shortTerm   = (double?)t.ShortTerm,
            longTerm    = (double?)t.LongTerm,
            status      = (string?)t.Status,
            threatLevel = (string?)t.ThreatLevel
        })
    );
});


// ── POST /plots/{id}/save  (atomic replace zones + threats) ───────────────────

app.MapPost("/plots/{id}/save", async (string id, SavePayload body, HttpContext ctx, IConfiguration cfg) =>
{
    if (!IsAdmin(ctx)) return Results.Unauthorized();

    using var db = GetConn(cfg);
    await db.OpenAsync();

    var exists = await db.ExecuteScalarAsync<int>(
        "SELECT COUNT(1) FROM Plots WHERE PlotId = @id", new { id });
    if (exists == 0)
        return Results.NotFound(new { error = "Plot not found" });

    using var tx = db.BeginTransaction();
    try
    {
        await db.ExecuteAsync("DELETE FROM Zones   WHERE PlotId = @id", new { id }, tx);
        await db.ExecuteAsync("DELETE FROM Threats WHERE PlotId = @id", new { id }, tx);

        if (!string.IsNullOrWhiteSpace(body.PlotName))
            await db.ExecuteAsync(
                "UPDATE Plots SET PlotName = @name WHERE PlotId = @id",
                new { name = body.PlotName.Trim(), id }, tx);

        var ord = 0;
        foreach (var z in body.Zones ?? [])
        {
            await db.ExecuteAsync(
                "INSERT INTO Zones (PlotId, UnitId, Shape, GeometryJson, DisplayOrder) " +
                "VALUES (@id, @unitId, @shape, @geo, @ord)",
                new { id, unitId = z.UnitId, shape = z.Shape,
                      geo = z.Geometry.GetRawText(), ord = z.DisplayOrder >= 0 ? z.DisplayOrder : ord },
                tx);
            ord++;
        }

        foreach (var t in body.Threats ?? [])
        {
            await db.ExecuteAsync(
                "INSERT INTO Threats (PlotId, UnitId, Score, ShortTerm, LongTerm, Status, ThreatLevel) " +
                "VALUES (@id, @unitId, @score, @shortTerm, @longTerm, @status, @threatLevel)",
                new { id, unitId = t.UnitId, score = t.Score,
                      shortTerm = t.ShortTerm, longTerm = t.LongTerm,
                      status = t.Status, threatLevel = t.ThreatLevel },
                tx);
        }

        tx.Commit();
        return Results.Json(new { ok = true });
    }
    catch
    {
        tx.Rollback();
        throw;
    }
});

// ── POST /plots/{id}/publish ──────────────────────────────────────────────────

app.MapPost("/plots/{id}/publish", async (string id, HttpContext ctx, IConfiguration cfg) =>
{
    if (!IsAdmin(ctx)) return Results.Unauthorized();

    using var db = GetConn(cfg);
    await db.OpenAsync();

    using var tx = db.BeginTransaction();
    try
    {
        await db.ExecuteAsync("UPDATE Plots SET IsActive = 0 WHERE IsActive = 1", transaction: tx);

        var affected = await db.ExecuteAsync(
            "UPDATE Plots SET IsPublished = 1, IsActive = 1, PublishedAt = SYSUTCDATETIME() WHERE PlotId = @id",
            new { id },
            tx);
        if (affected == 0)
        {
            tx.Rollback();
            return Results.NotFound(new { error = "Plot not found" });
        }

        tx.Commit();
    }
    catch
    {
        tx.Rollback();
        throw;
    }

    var publishedAt = await db.ExecuteScalarAsync<DateTime>(
        "SELECT PublishedAt FROM Plots WHERE PlotId = @id", new { id });

    return Results.Json(new { ok = true, publishedAt = publishedAt.ToString("o") });
});

// ── DELETE /plots/{id} ────────────────────────────────────────────────────────

app.MapDelete("/plots/{id}", async (string id, HttpContext ctx, IConfiguration cfg) =>
{
    if (!IsAdmin(ctx)) return Results.Unauthorized();

    using var db = GetConn(cfg);
    await db.OpenAsync();

    // Check existence separately from ImagePath (ImagePath can legitimately be NULL)
    var row = await db.QueryFirstOrDefaultAsync(
        "SELECT PlotId, ImagePath FROM Plots WHERE PlotId = @id", new { id });
    if (row is null)
        return Results.NotFound(new { error = "Plot not found" });

    // FK CASCADE removes Zones + Threats automatically
    await db.ExecuteAsync("DELETE FROM Plots WHERE PlotId = @id", new { id });

    // Best-effort file removal (non-fatal)
    if (!string.IsNullOrEmpty((string?)row.ImagePath))
    {
        var filePath = Path.Combine(uploadsDir, (string)row.ImagePath);
        try { if (File.Exists(filePath)) File.Delete(filePath); }
        catch { /* non-fatal */ }
    }

    return Results.Json(new { ok = true });
});

// ── Run ────────────────────────────────────────────────────────────────────────

app.Run();

// ── Records (must follow all top-level statements in C# top-level programs) ───

record LoginRequest(string Username, string Password);

record ZoneDto(
    string      UnitId,
    string      Shape,
    JsonElement Geometry,
    int         DisplayOrder
);

record ThreatDto(
    string UnitId,
    double? Score,
    double? ShortTerm,
    double? LongTerm,
    string? Status,
    string? ThreatLevel
);

record SavePayload(
    string?          PlotName,
    List<ZoneDto>?   Zones,
    List<ThreatDto>? Threats
);

record AimThreatDto(
    [property: JsonPropertyName("ThreatID")] string ThreatID,
    [property: JsonPropertyName("ThreatClass")] string ThreatClass,
    [property: JsonPropertyName("InitiativeName")] string InitiativeName,
    [property: JsonPropertyName("Workstream")] string Workstream,
    [property: JsonPropertyName("ThreatUnit")] string ThreatUnit,
    [property: JsonPropertyName("UnitDescription")] string UnitDescription,
    [property: JsonPropertyName("MTOScore")] string MTOScore,
    [property: JsonPropertyName("ThreatDiscipline")] string ThreatDiscipline,
    [property: JsonPropertyName("PrimaryRAM")] string PrimaryRAM,
    [property: JsonPropertyName("CreatedDate")] string CreatedDate,
    [property: JsonPropertyName("ThreatType")] string ThreatType,
    [property: JsonPropertyName("OverallStatus")] string OverallStatus,
    [property: JsonPropertyName("OverallStatusCommentary")] string OverallStatusCommentary,
    [property: JsonPropertyName("ThreatURL")] string ThreatURL,
    [property: JsonPropertyName("Tag")] string Tag,
    [property: JsonPropertyName("EQS")] string EQS,
    [property: JsonPropertyName("HSSCRAM")] string HSSCRAM,
    [property: JsonPropertyName("HSSCScore")] string HSSCScore,
    [property: JsonPropertyName("ProductionRAM")] string ProductionRAM,
    [property: JsonPropertyName("ProductionScore")] string ProductionScore
);

record LiveThreatUnitSummaryDto(
    int Threats,
    long Score,
    List<AimThreatDto> Details
);

record AimFieldDto(
    [property: JsonPropertyName("field")] string Field,
    [property: JsonPropertyName("value")] string Value
);

record AimDataRetrieveResult(
    [property: JsonPropertyName("total")] int Total,
    [property: JsonPropertyName("rows")] List<List<AimFieldDto>> Rows
);

record AimDataRetrieveResponse(
    [property: JsonPropertyName("d")] AimDataRetrieveResult D
);
