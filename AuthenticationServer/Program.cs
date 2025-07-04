using Microsoft.IdentityModel.Tokens;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using AuthenticationServer.Controllers;

namespace AuthenticationServer {
    public class Program {
        public static void Main(string[] args) {
            var builder = WebApplication.CreateBuilder(args);

            // Add services to the container.

            builder.Services.AddControllers();

            builder.Services.AddOpenApi(options => {
                options.AddDocumentTransformer((document, context, cancellationToken) => {
                    document.Info = new() {
                        Title = "Microservicios: Servidor de Autenticaci�n", Version = "v1", Description = "Ejemplo de un servidor de autenticaci�n con JWT Bearer"
                    };
                    return Task.CompletedTask;
                });
            });
            builder.Services.AddCors(options => { 
                options.AddPolicy("AllowAll", builder => builder.AllowAnyOrigin().AllowAnyMethod().AllowAnyHeader()); 
            });

            KeyGenerator.GenerateRsaKeys();
            // Configuraci�n de la autenticaci�n JWT Bearer
            builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
                .AddJwtBearer(options => {
                    options.TokenValidationParameters = new TokenValidationParameters {
                        ValidateIssuer = true, // Valida el emisor del token
                        ValidateAudience = true, // Valida la audiencia del token
                        ValidateLifetime = true, // Valida la fecha de expiraci�n del token
                        ValidateIssuerSigningKey = true, // MUY IMPORTANTE: Valida la firma del token

                        // Obtener la configuraci�n desde appsettings.json
                        ValidIssuer = builder.Configuration["Jwt:Issuer"],
                        ValidAudience = builder.Configuration["Jwt:Audience"],
                        // Especificamos la clave p�blica para la validaci�n de la firma (RS256)
                        IssuerSigningKey = new RsaSecurityKey(KeyGenerator.RsaPublicKey),

                        ClockSkew = TimeSpan.Zero // Elimina la tolerancia de tiempo por defecto (5 minutos)
                    };
                });
            builder.Services.AddAuthorization(); // Habilita la autorizaci�n

            var app = builder.Build();

            // Configure the HTTP request pipeline.
            if(app.Environment.IsDevelopment()) {
            }

                app.MapOpenApi();
                app.UseSwaggerUI(options => {
                    options.SwaggerEndpoint("/openapi/v1.json", "v1");
                });

            app.UseCors("AllowAll");

            app.UseAuthentication(); // Debe ir antes de UseAuthorization
            app.UseAuthorization();


            app.MapControllers();

            app.Run();
        }
    }
}
