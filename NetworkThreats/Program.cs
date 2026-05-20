using FluentValidation;
using Microsoft.EntityFrameworkCore;
using NetworkThreats.Data;
using NetworkThreats.Models;
using NetworkThreats.Repositories;
using NetworkThreats.Services;
using NetworkThreats.Validators;

var builder = WebApplication.CreateBuilder(args);

// --- База данных: PostgreSQL в Docker, SQLite локально ---
var connectionString = builder.Configuration.GetConnectionString("DefaultConnection")!;
var usePostgres = connectionString.Contains("Host=", StringComparison.OrdinalIgnoreCase);

builder.Services.AddDbContext<AppDbContext>(options =>
{
    if (usePostgres)
        options.UseNpgsql(connectionString);
    else
        options.UseSqlite(connectionString);
});

// --- Кэш: Redis если задана строка подключения, иначе in-memory ---
var redisConnection = builder.Configuration.GetConnectionString("Redis");
if (!string.IsNullOrWhiteSpace(redisConnection))
    builder.Services.AddStackExchangeRedisCache(o => o.Configuration = redisConnection);
else
    builder.Services.AddDistributedMemoryCache();

// --- Репозитории ---
builder.Services.AddScoped<IThreatRepository, ThreatRepository>();
builder.Services.AddScoped<ICategoryRepository, CategoryRepository>();
builder.Services.AddScoped<IMitigationRepository, MitigationRepository>();
builder.Services.AddScoped<IIndicatorRepository, IndicatorRepository>();
builder.Services.AddScoped<IKnownHashRepository, KnownHashRepository>();
builder.Services.AddScoped<IFileHeuristicRepository, FileHeuristicRepository>();

// --- Сервисы ---
builder.Services.AddScoped<IThreatService, ThreatService>();
builder.Services.AddScoped<ICategoryService, CategoryService>();
builder.Services.AddScoped<IMitigationService, MitigationService>();
builder.Services.AddScoped<ISearchService, SearchService>();
builder.Services.AddScoped<IThreatAnalyzerService, ThreatAnalyzerService>();
builder.Services.AddScoped<IFileAnalyzerService, FileAnalyzerService>();

// --- Валидация (FluentValidation) ---
builder.Services.AddScoped<IValidator<Threat>, ThreatValidator>();
builder.Services.AddScoped<IValidator<ThreatCategory>, ThreatCategoryValidator>();

builder.Services.AddRazorPages();
builder.Services.AddServerSideBlazor();

var app = builder.Build();

// --- Инициализация БД ---
using (var scope = app.Services.CreateScope())
{
    var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();
    if (usePostgres)
        db.Database.EnsureCreated();
    else
        db.Database.Migrate();
}

if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Error");
    app.UseHsts();
}

app.UseHttpsRedirection();
app.UseStaticFiles();
app.UseRouting();

app.MapBlazorHub();
app.MapRazorPages();
app.MapFallbackToPage("/_Host");

app.Run();
