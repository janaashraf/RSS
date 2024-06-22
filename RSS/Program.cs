using Microsoft.Data.Sqlite;
using Dapper;
using System.Data;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication;
using System.Security.Claims;
using System.ServiceModel.Syndication;
using System.Xml;
using static System.Runtime.InteropServices.JavaScript.JSType;
using System;

var builder = WebApplication.CreateBuilder(args);
var connectionString = "Data Source=./wwwroot/database.db;";
builder.Services.AddSingleton<IDbConnection>(_ => new SqliteConnection(connectionString));
builder.Services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
    .AddCookie(options =>
    {
        options.Cookie.Name = "RSSCookie";
        options.Cookie.HttpOnly = true;
        options.ExpireTimeSpan = TimeSpan.FromMinutes(30);
        options.LoginPath = "/";
        options.AccessDeniedPath = "/";
        options.Cookie.SecurePolicy = CookieSecurePolicy.None;
    });

builder.Services.AddAuthorization();
var app = builder.Build();
app.UseAuthentication();
app.UseAuthorization();
app.UseRouting();

using (var connection = new SqliteConnection(connectionString))
{
    connection.Open();
    connection.Execute(@"CREATE TABLE IF NOT EXISTS Users (
                        Id INTEGER PRIMARY KEY AUTOINCREMENT,
                        email TEXT NOT NULL UNIQUE,
                        password TEXT NOT NULL)");
    connection.Execute(@"CREATE TABLE IF NOT EXISTS Feeds (
                        Id INTEGER PRIMARY KEY AUTOINCREMENT,
                        UserId INTEGER NOT NULL,
                        Url TEXT NOT NULL,
                        FOREIGN KEY (UserId) REFERENCES Users(Id) ON DELETE CASCADE)");
}
app.UseStaticFiles();
app.MapGet("/", async (HttpContext context, IDbConnection db) =>
{
    if (context.User.Identity.IsAuthenticated)
    {
        var userId = context.User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
        var feeds = await db.QueryAsync<dynamic>("SELECT Id,  Url FROM Feeds WHERE UserId = @UserId", new { UserId = userId });
        var options = "";
        foreach (var feed in feeds)
        {
            options += $"""<option value='{feed.Id}'>{feed.Url}</option>""";
        }

        var feedsHtml = $"""
        <!doctype html>
        <html lang='en'>
        <head>
        <meta charset='utf-8'>
        <meta name='viewport' content='width=device-width, initial-scale=1'>
        <title>Feedify</title>
        <link rel='icon' type='image/svg' href='rss-svgrepo-com.svg'>
        <link href='style.css' rel='stylesheet'>
        <link href='https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css' rel='stylesheet'>
        </head>
        <body>
        <div class='container'>
        <div class='row mt-2'>
        <div class='col-12 d-flex justify-content-end'>
        <button type='button' class='btn btn-danger mt-2' hx-post='/logout'>Log out</button>
        </div>
        </div>
        <div class='row mt-5'>
            <div class='col-12'>
                <div class='mt-4 text-center'>
                    <div class='card mb-5'>
            <div class='card-header text-center'>
                Add Some Feeds
            </div>
        <div class='card-body'>
            <form id='addFeedForm'>
                <input type='hidden' name='userId' value='{userId}'>
                <div class='form-group'>
                    <label for='feedUrl' class='mb-1'>Feed URL</label>
                    <div class='row justify-content-center'>
                        <div class='col-6'>
                            <input type='url' class='form-control mb-2' id='feedUrl' placeholder='Enter RSS/ATOM feed URL' name='url' required>
                        </div>
                    </div>
                </div>
        <div class='text-center'>      
       <button type='button' class='btn btn-danger mt-2' hx-post='/add-feed' hx-target='#message-container' hx-swap='innerHTML'>Add Feed</button>
         <div id='message-container'></div>
        </div>
     </form>
            </div>
            </div>
        <div class='card mb-5'>
                    <div class='card-header text-center'>
                        Delete Feed
                    </div>
                    <div class='card-body'>
          <form id='deleteFeedForm'>
            <label class="form-label">Feed URL</label>
            <select required class="form-select" id="optionid" name='name'>
                <option disabled hidden selected>Select a URL to remove</option>
                {options}
            </select>           
        <button class="btn btn-danger mt-2" type="button" hx-delete='/remove-feed' hx-target='#removeFeedError' hx-swap='outerHTML'>Remove Feed</button>
    </form>     
    <div id='removeFeedError'></div>
                </div>
                </div> 
                <div id='feeds-container' class='mt-3'></div>                           
""";

        if (feeds.Any())
        {
            feedsHtml += $@" <h2 class='mt-5'>Your feeds</h2>";
            foreach (var feed in feeds)
            {
                var feedId = feed.Id;
                var feedUrl = feed.Url;
                var newsHtml = await FetchAndRenderNews(feedUrl);
                feedsHtml += $"""
                    <div class='card mb-3'>
                        <div class='card-body mb-5 mt-3 pb-5'>
                            <h5 class='card-title mt-3 mb-5 fs-4'>{feed.Url}</h5>
                        <hr class = 'my-3'>
                        <div class='news-list mb-5'>
                            {newsHtml}
                        </div>
                         </div>
                          </div>
                """;
            }
        }
        else
        {
            feedsHtml += """<p>No feeds available.</p>""";
        }

        feedsHtml += """
        </div> <!-- #feeds-container -->
        </div> <!-- .mt-4 -->
        </div> <!-- .col-12 -->
        </div> <!-- .row -->
        </div> <!-- .container -->
        <script src='https://unpkg.com/htmx.org@1.9.2'></script>
        <script src='https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js'></script>
        </body>
        </html>
        """;
        return Results.Content(feedsHtml, "text/html");
    }
    else
    {
        var htmlContent = await File.ReadAllTextAsync("wwwroot/index.html");
        return Results.Content(htmlContent, "text/html");
    }
});

app.MapDelete("/remove-feed", async (HttpContext context, IDbConnection db) =>
{
    var feedid = context.Request.Form["name"].ToString();
    await db.ExecuteAsync("DELETE FROM Feeds WHERE Id = @Id", new { Id = feedid });
    context.Response.Headers["HX-Redirect"] = "/";
    return Results.Ok();
});
app.MapPost("/get-user", async (IDbConnection db, HttpContext context) =>
{
    var email = context.Request.Form["email2"].ToString().Trim();
    var password = context.Request.Form["password2"].ToString();
    var user = await db.QuerySingleOrDefaultAsync<dynamic>(
        "SELECT Id FROM Users WHERE email = @Email AND password = @Password",
        new { Email = email, Password = password });

    if (user != null)
    {
        var claims = new List<Claim>
        {
            new Claim(ClaimTypes.NameIdentifier, user.Id.ToString())
        };
        var claimsIdentity = new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme);
        var authProperties = new AuthenticationProperties
        {
            IsPersistent = true,
            ExpiresUtc = DateTimeOffset.UtcNow.AddMinutes(30)
        };
        await context.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme, new ClaimsPrincipal(claimsIdentity), authProperties);

        context.Response.Headers["HX-Redirect"] = "/";
        return Results.Content("<div class='text-success'>Login successful!</div>", "text/html");
    }
    else
    {
        var loginFailedHtml = """
            <div class='col-md-2 error-login z text-danger d-block'>
                <h6>Incorrect email or password. Please try again.</h6>
            </div>
        """;
        return Results.Content(loginFailedHtml, "text/html");
    }
});


app.MapPost("/add-user", async (HttpContext context, IDbConnection db) =>
{
    var email = context.Request.Form["email"].ToString().Trim();
    var password = context.Request.Form["password"].ToString();
    if (string.IsNullOrEmpty(email) || string.IsNullOrEmpty(password))
    {
        return Results.Content("<div class='text-danger'>Fields cannot be empty</div>", "text/html");
    }
    if (password.Length < 8)
    {
        var errorHtml = """
                 <div class='err-message'>
                <div class='text-danger mt-2'>
                    <h6>Password must be at least 8 characters long.</h6>
                </div>
                 </div>
                <form id='regForm' hx-post='/add-user' hx-target='#regModal .modal-body' hx-swap='innerHTML'>
                <div class='form-group'>
                    <label for='email' class='mb-1'>Email</label>
                    <input type='email' class='form-control mb-2' id='email' placeholder='Enter email' name='email' required>
                </div>
                <div class='form-group'>
                    <label for='password' class='mb-1'>Password</label>
                    <input type='password' class='form-control mb-2' id='password' placeholder='Enter password' name='password' required>
                </div>
                <div class='row justify-content-center' id='errormsg'>
                    <div class='col-md-6'>
                        <button type='submit' class='btn btn-danger btn-block mt-2' id='rsumbit'>Register</button>
                    </div>
                </div>
                </form> 
                """;
        return Results.Content(errorHtml, "text/html");
    }
    try
    {
        var resultId = await db.QuerySingleOrDefaultAsync<int>("INSERT INTO Users (email, password) VALUES (@Email, @Password); SELECT last_insert_rowid();", new { Email = email, Password = password });
        var successHtml = @"
            <div class='success-message'>
                <p>Your registration was successful!</p></div>";
        return Results.Content(successHtml, "text/html");
    }
    catch (SqliteException ex) when (ex.SqliteErrorCode == 19)
    {
        var errorHtml = """
                 <div class='err-message'>
                <div class='text-danger mt-2'>
                    <h6>Email already exists! Please use a different email.</h6>
                </div>
                 </div>
                <form id='regForm' hx-post='/add-user' hx-target='#regModal .modal-body' hx-swap='innerHTML'>
                <div class='form-group'>
                    <label for='email' class='mb-1'>Email</label>
                    <input type='email' class='form-control mb-2' id='email' placeholder='Enter email' name='email' required>
                </div>
                <div class='form-group'>
                    <label for='password' class='mb-1'>Password</label>
                    <input type='password' class='form-control mb-2' id='password' placeholder='Enter password' name='password' required>
                </div>
                <div class='row justify-content-center' id='errormsg'>
                    <div class='col-md-6'>
                        <button type='submit' class='btn btn-danger btn-block mt-2' id='rsumbit'>Register</button>
                    </div>
                </div>
                </form> 
                """;
        return Results.Content(errorHtml, "text/html");
    }
});

app.MapPost("/add-feed", async (HttpContext context, IDbConnection db) =>
{
    var userId = context.User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
    var url = context.Request.Form["url"].ToString().Trim();
    string responseHtml;
    if (url.Length != 0 && await IsValidFeedUrl(url))
    {
        var existingFeed = await db.QueryFirstOrDefaultAsync<int>(
            "SELECT COUNT(*) FROM Feeds WHERE UserId = @UserId AND Url = @Url",
            new { UserId = userId, Url = url });
        if (existingFeed == 0)
        {
            await db.QuerySingleOrDefaultAsync<int>(
                "INSERT INTO Feeds (UserId, Url) VALUES (@UserId, @Url); SELECT last_insert_rowid();",
                new { UserId = userId, Url = url });
            responseHtml = "<div id='message' class='text-success'>Feed added successfully!</div>";
            context.Response.Headers["HX-Redirect"] = "/";
        }
        else
        {
            responseHtml = "<div id='message' class='text-danger'>Feed URL already exists!</div>";
        }
    }
    else
    {
        responseHtml = "<div id='message' class='text-danger'>Invalid feed URL!</div>";
    }
    return Results.Content(responseHtml, "text/html");
});
async Task<bool> IsValidFeedUrl(string url)
{
    try
    {
        using var httpClient = new HttpClient();
        var response = await httpClient.GetAsync(url);
        response.EnsureSuccessStatusCode();

        var stream = await response.Content.ReadAsStreamAsync();
        using var reader = XmlReader.Create(stream);
        var feed = SyndicationFeed.Load(reader);

        return feed != null;
    }
    catch
    {
        return false;
    }
}

app.MapPost("/logout", async (HttpContext context) =>
{
    await context.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
    context.Response.Headers["HX-Redirect"] = "/";
});
async Task<string> FetchAndRenderNews(string feedUrl)
{
    try
    {
        var settings = new XmlReaderSettings
        {
            DtdProcessing = DtdProcessing.Parse
        };
        using var reader = XmlReader.Create(feedUrl, settings);
        var syndicationFeed = SyndicationFeed.Load(reader);
        if (syndicationFeed != null)
        {
            var newsHtml = "<style> @media (max-width: 768px) {  .news-item img { max-width: 100%; height: auto;}}</style>";
            newsHtml += """
<style>
    /* CSS for responsive videos */
    .news-item video,
    .news-item iframe {
        max-width: 100%; /* Ensure videos and iframes are responsive */
        height: auto; /* Maintain aspect ratio */
    }

    @media (max-width: 768px) {
        .news-item video,
        .news-item iframe {
            max-width: 100%;
            height: auto;
        }
    }
</style>
""";
            foreach (var item in syndicationFeed.Items)
            {
                newsHtml += $"""
        <div class='news-item mb-5 mt-5'>
            <div class="row">
                <div class="col-12">
                    <p class='mb-3 mt-3 text-sm' style="max-width: 100%; overflow-wrap: break-word;">{item.Summary?.Text ?? "No summary available"}</p>
                </div>
            </div>
            <a class='mb-5' href='{item.Links[0].Uri}' target='_blank'>Read more</a>
            <hr class='mt-5 mb-5'>
        </div>
    """;
            }
            return newsHtml;
        }
    }

    catch (Exception ex)
    {
    }
    return "<div class='text-danger'>Error fetching news</div>";
}

app.Run();
public class user
{
    public long Id { get; set; }
    public string? email { get; set; }
    public string? password { get; set; }
}
