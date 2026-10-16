using APIAuditoria;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using System.Text;

namespace APIAuditoria
{
  public class Program
  {
    public static void Main(string[] args)
    {
      var builder = WebApplication.CreateBuilder(args);

      // Add services to the container.

      builder.Services.AddSingleton<TokenService>();

      builder.Services
          .AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
          .AddJwtBearer(options =>
          {
            options.TokenValidationParameters = new TokenValidationParameters
            {
              ValidateIssuer = true,
              ValidateAudience = true,
              ValidateLifetime = true,
              ValidateIssuerSigningKey = true,
              ValidIssuer = builder.Configuration["Jwt:Issuer"],
              ValidAudience = builder.Configuration["Jwt:Audience"],
              IssuerSigningKey = new SymmetricSecurityKey(
                    Encoding.UTF8.GetBytes(builder.Configuration["Jwt:Key"]!)),
              ClockSkew = TimeSpan.FromMinutes(1)
            };
          });

      builder.Services.AddAuthorization();

      builder.Services.AddControllers();

      // Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
      builder.Services.AddEndpointsApiExplorer();
      builder.Services.AddSwaggerGen();

      var app = builder.Build();

      app.UseAuthentication();
      app.UseAuthorization();


      // Configure the HTTP request pipeline.
      if (app.Environment.IsDevelopment())
      {
        app.UseSwagger();
        app.UseSwaggerUI();
      }

      app.UseHttpsRedirection();

      app.MapControllers();

      // Login (público)
      app.MapPost("/auth/login", (LoginRequest req, TokenService tokens) =>
      {
        // TODO: reemplazar por validación real contra tu base de datos
        // (con hash de contraseña: BCrypt, Argon2 o ASP.NET Identity)
        if (req.Username == "admin" && req.Password == "1234")
        {
          var token = tokens.GenerarToken("1", req.Username, "Admin");
          return Results.Ok(new { token });
        }
        return Results.Unauthorized();
      });


      // Cualquier usuario autenticado
      app.MapGet("/perfil", (HttpContext ctx) =>
          Results.Ok(new { usuario = ctx.User.Identity?.Name ?? ctx.User.FindFirst("unique_name")?.Value }))
         .RequireAuthorization();

      // Solo rol Admin
      app.MapGet("/admin", () => Results.Ok("Hola admin"))
         .RequireAuthorization(p => p.RequireRole("Admin"));

      app.Run();
    }
  }
}


record LoginRequest(string Username, string Password);