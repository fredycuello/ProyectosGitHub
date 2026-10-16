using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Microsoft.IdentityModel.Tokens;


namespace APIAuditoria
{
  public class TokenService(IConfiguration config)
  {
    public string GenerarToken(string userId, string username, string rol)
    {
      var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(config["Jwt:Key"]!));
      var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

      var claims = new[]
      {
            new Claim(JwtRegisteredClaimNames.Sub, userId),
            new Claim(JwtRegisteredClaimNames.UniqueName, username),
            new Claim(ClaimTypes.Role, rol),
            new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
        };

      var token = new JwtSecurityToken(
          issuer: config["Jwt:Issuer"],
          audience: config["Jwt:Audience"],
          claims: claims,
          expires: DateTime.UtcNow.AddMinutes(double.Parse(config["Jwt:ExpireMinutes"]!)),
          signingCredentials: creds);

      return new JwtSecurityTokenHandler().WriteToken(token);
    }
  }
}
