using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using Microsoft.OpenApi.Models;
using MySql.EntityFrameworkCore.Extensions;
using System.ComponentModel.DataAnnotations;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Cryptography;
using System.Text;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddAuthentication(o =>
{
    o.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
    o.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
    o.DefaultScheme = JwtBearerDefaults.AuthenticationScheme;
}).AddJwtBearer(o =>
{
    o.TokenValidationParameters = new TokenValidationParameters
    {
        IssuerSigningKey = new SymmetricSecurityKey
            (Encoding.UTF8.GetBytes(builder.Configuration["Jwt:Key"])),
        ValidateIssuer = false,
        ValidateAudience = false,
        ValidateLifetime = true,
        ValidateIssuerSigningKey = true
    };
});

builder.Services.AddAuthorization();

var securityScheme = new OpenApiSecurityScheme()
{
    Name = "Authorization",
    Type = SecuritySchemeType.ApiKey,
    Scheme = "Bearer",
    BearerFormat = "JWT",
    In = ParameterLocation.Header,
    Description = "JSON Web Token based security",
};

var securityReq = new OpenApiSecurityRequirement()
{
    {
        new OpenApiSecurityScheme
        {
            Reference = new OpenApiReference
            {
                Type = ReferenceType.SecurityScheme,
                Id = "Bearer"
            }
        },
        new string[] {}
    }
};

var info = new OpenApiInfo()
{
    Version = "v1",
    Title = "Smarthome REST",
    Description = "API REST para registro de sesores",
};

builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen(o =>
{
    o.SwaggerDoc("v1", info);
    o.AddSecurityDefinition("Bearer", securityScheme);
    o.AddSecurityRequirement(securityReq);
});


builder.Services.AddMySQLServer<SmarthomeContext>(builder.Configuration["ConnectionStrings:Mysql"]);

//builder.Services.AddDbContext<SmarthomeContext>(opt => opt.UseInMemoryDatabase("TodoList"));
var app = builder.Build();

if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();

    app.UseAuthentication();
    app.UseAuthorization();
}

app.MapGet("/", [AllowAnonymous] () => "Hello World!").WithName("Raiz");

app.MapPost("/login", [AllowAnonymous] async (User user, SmarthomeContext db) =>
{
    var userdb = await db.Users.FindAsync(user.Username);
    if (userdb is null) return Results.NotFound();
    if (userdb.Password != Sha1(user.Password)) return Results.Unauthorized();
    var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(builder.Configuration["Jwt:Key"]));
    var jwtTokenHandler = new JwtSecurityTokenHandler();
    var descriptor = new SecurityTokenDescriptor()
    {
        SigningCredentials = new SigningCredentials(key, SecurityAlgorithms.HmacSha256),
        Expires = DateTime.UtcNow.AddHours(1)
    };
    var token = jwtTokenHandler.CreateToken(descriptor);
    var jwtToken = jwtTokenHandler.WriteToken(token);
    return Results.Ok(jwtToken);
});

app.MapGet("/usuarios", [Authorize] async (SmarthomeContext db) =>
    await db.Users.ToListAsync());

app.MapPost("/usuarios", [Authorize] async (User user, SmarthomeContext db) =>
{
    user.Password = Sha1(user.Password);
    db.Users.Add(user);
    await db.SaveChangesAsync();
    return Results.Created($"/todoitems/{user.Username}", user);
});

app.MapPut("/usuarios/{username}", [Authorize] async (string username, User userUpdate, SmarthomeContext db) =>
{
    var user = await db.Users.FindAsync(username);
    if (user is null) return Results.NotFound();
    user.Password = Sha1(userUpdate.Password);
    await db.SaveChangesAsync();
    return Results.NoContent();
});

app.MapDelete("/usuarios/{username}", [Authorize] async (string username, SmarthomeContext db) =>
{
    if (await db.Users.FindAsync(username) is User user)
    {
        db.Users.Remove(user);
        await db.SaveChangesAsync();
        return Results.NoContent();
    }
    return Results.NotFound();
});

app.MapGet("/sensores", [Authorize] async (SmarthomeContext db) =>
    await db.Sensors.ToListAsync());

app.MapGet("/sensores/{id}", [Authorize] async (int id, SmarthomeContext db) =>
    await db.Sensors.FindAsync(id)
        is Sensor sensor
            ? Results.Ok(sensor)
            : Results.NotFound());

app.MapPost("/sensores", [Authorize] async (Sensor sensor, SmarthomeContext db) =>
{
    sensor.Date = DateTime.Now;
    db.Sensors.Add(sensor);
    await db.SaveChangesAsync();
    return Results.Created($"/todoitems/{sensor.Id}", sensor);
});

app.MapPut("/sensores/{id}", [Authorize] async (int id, Sensor sensorUpdate, SmarthomeContext db) =>
{
    var sensor = await db.Sensors.FindAsync(id);
    if (sensor is null) return Results.NotFound();
    sensor.Name = sensorUpdate.Name;
    sensor.Value = sensorUpdate.Value;
    await db.SaveChangesAsync();
    return Results.NoContent();
});

app.MapDelete("/sensores/{id}", [Authorize] async (int id, SmarthomeContext db) =>
{
    if (await db.Sensors.FindAsync(id) is Sensor sensor)
    {
        db.Sensors.Remove(sensor);
        await db.SaveChangesAsync();
        return Results.Ok(sensor);
    }
    return Results.NotFound();
});

app.Run();

static string Sha1(string pass)
{
    return string.Join("", SHA1.Create().ComputeHash(Encoding.UTF8.GetBytes(pass)).Select(x => x.ToString("x2")));
}
class User
{
    [Key]
    public string? Username { get; set; }
    public string? Password { get; set; }
}
class Sensor
{
    [Key]
    public int Id { get; set; }
    public string? Name { get; set; }
    public double Value { get; set; }
    public DateTime Date { get; set; }
}

class SmarthomeContext : DbContext
{
    public DbSet<User> Users => Set<User>();
    public DbSet<Sensor> Sensors => Set<Sensor>();
    public SmarthomeContext(DbContextOptions<SmarthomeContext> options) : base(options)
    {
    }
}
