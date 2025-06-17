using MyDataSecurityApp.Services;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
// Learn more about configuring OpenAPI at https://aka.ms/aspnet/openapi
builder.Services.AddOpenApi();
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

builder.Services.AddControllers();

builder.Services.AddSingleton<ISymmetricEncryptionService, SymmetricEncryptionService>();
builder.Services.AddSingleton<IAsymmetricEncryptionService, AsymmetricEncryptionService>();
builder.Services.AddSingleton<IHashingService, HashingService>();

var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.MapOpenApi();
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.MapGet("/", () => Results.Redirect("/swagger"));

app.UseRouting();
app.UseHttpsRedirection();
app.MapControllers();

app.Run();