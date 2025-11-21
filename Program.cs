using Microsoft.AspNetCore.Builder;

WebApplicationBuilder builder = WebApplication.CreateBuilder(args);
builder.Configuration.Sources.Clear();

WebApplication app = builder.Build();

app.MapGet("/", () => "Hello World!");

app.Run();
