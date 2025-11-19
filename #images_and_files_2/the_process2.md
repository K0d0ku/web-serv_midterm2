# web-service development 2nd midterm task

## in here i show my process/progress in the making of this project and fulfilling its requirements  
!!! The list of **_Tools_** and **_Packages_** are listed in [README.md](https://github.com/K0d0ku/web-serv_midterm/blob/master/README.md)  
Table of contents  
- [Requirements](#requirements)
- [Process](#process)
  - [1. Implementation of CRUD operations using the REST architectural style](#1-implementation-of-crud-operations-using-the-rest-architectural-style)
    - [1.1. Implementation of validation (DataAnnotation, FluentAPI)](#11-implementation-of-validation-dataannotation-fluentapi)
  - [2. Implementation of Dependency Injection](#2-implementation-of-dependency-injection)
    - [2.1. Logging (Seq, Serilog)](#21-logging-seq-serilog)
    - [2.2. Repository Pattern](#22-repository-pattern)
  - [3. API testing](#3-api-testing)
    - [3.1. Using HTTPClient (or its analogues) in the WEB part (possibly ASP.NET Core or other solutions)](#31-using-httpclient-or-its-analogues-in-the-web-part-possibly-aspnet-core-or-other-solutions)
    - [3.2. Using Postman or other analogues](#32-using-postman-or-other-analogues)
  - [4. Implementation of API authorization (JWT or other options)](#4-implementation-of-api-authorization-jwt-or-other-options)
  - [5. Implementation of Authentication and Authorization in an application using Identity](#5-implementation-of-authentication-and-authorization-in-an-application-using-identity)  
- [Additional content](#additional-content)

## Requirements
i was given a list of requirements to make the project by following it so i can pass my midterm  
the list of requirements are:
![requirements](https://github.com/K0d0ku/web-serv_midterm/blob/master/%23images_and_files/requirements.png)  
and following that list i have fulfilled the needed job to do:

## Process
I kinda had a bit of experience with .Net Maui and made an android app with a Local Database that also includes some of the requirements like: CRUD, DataAnnotation etc. from this project: [Link🔗](https://github.com/K0d0ku/cloud_app_dev_exam_project)  

### 1. Implementation of CRUD operations using the REST architectural style  

The API implements full CRUD (Create, Read, Update, Delete) functionality for the Customer resource, following REST conventions.  
Each operation is exposed as a clear, predictable HTTP endpoint under /api/Auth/customers.

| Operation | HTTP Method | Endpoint                   | Description                 | Access Control     |
| --------- | ----------- | -------------------------- | --------------------------- | ------------------ |
| Create    | `POST`      | `/api/Auth/register`       | Register a new customer     | Public (Anonymous) |
| Read All  | `GET`       | `/api/Auth/customers`      | Get a list of all customers | Admin only         |
| Read One  | `GET`       | `/api/Auth/customers/{id}` | Get customer by ID          | Admin or Self      |
| Update    | `PUT`       | `/api/Auth/customers/{id}` | Update customer info        | Admin or Self      |
| Delete    | `DELETE`    | `/api/Auth/customers/{id}` | Delete customer             | Admin only         |  

This controller exposes all CRUD operations through REST endpoints:  
[Create - AuthController.cs](https://github.com/K0d0ku/web-serv_midterm/blob/74ce5e44ff67db98236399b36b331dac2b20ce4a/Controllers/AuthController.cs#L28-L46)  
```
        // C
        [HttpPost("register")]
        [AllowAnonymous]
        public IActionResult Register([FromBody] Customer customer)
        {
            if (!ModelState.IsValid)
                return BadRequest(ModelState);

            if (_repository.ExistsByEmail(customer.Email))
                return BadRequest(new { Message = "Email already registered." });

            if (string.IsNullOrEmpty(customer.Role))
                customer.Role = "Customer"; // default for now

            _repository.Add(customer);

            _logger.LogInformation("Customer registered successfully: {CustomerId}", customer.Id);
            return Ok(new { Message = "Registration successful", CustomerId = customer.Id });
        }
```
![Crud - Create](https://github.com/K0d0ku/web-serv_midterm/blob/master/%23images_and_files/ApiTestCrud1.png)  
![Crud - Create](https://github.com/K0d0ku/web-serv_midterm/blob/master/%23images_and_files/ApiTestCrudDb1.png)  
> its accNUpdated after the Update and i didnt have the picture before the update

[Read (all) - AuthController.cs](https://github.com/K0d0ku/web-serv_midterm/blob/74ce5e44ff67db98236399b36b331dac2b20ce4a/Controllers/AuthController.cs#L89-L97)
```
        // R
        [HttpGet("customers")]
        [Authorize(Roles = "Admin")]
        public IActionResult GetAllCustomers()
        {
            _logger.LogInformation("Fetching all customers");
            var customers = _repository.GetAll();
            return Ok(customers);
        }
```
![Crud - Read(All)](https://github.com/K0d0ku/web-serv_midterm/blob/master/%23images_and_files/ApiTestCrud2.png)  

[Read (ID) - AuthController.cs](https://github.com/K0d0ku/web-serv_midterm/blob/74ce5e44ff67db98236399b36b331dac2b20ce4a/Controllers/AuthController.cs#L99-L113)  
```
        // R id relevant
        [HttpGet("customers/{id}")]
        [Authorize] 
        public IActionResult GetCustomerById(int id)
        {
            var customer = _repository.GetById(id);
            if (customer == null)
                return NotFound(new { Message = "Customer not found" });

            var userId = User.FindFirst("Id")?.Value;
            if (!User.IsInRole("Admin") && userId != customer.Id.ToString())
                return Forbid();

            return Ok(customer);
        }
```
![Crud - Read(Id)](https://github.com/K0d0ku/web-serv_midterm/blob/master/%23images_and_files/ApiTestCrud2ByID.png)  

[Update - AuthController.cs](https://github.com/K0d0ku/web-serv_midterm/blob/74ce5e44ff67db98236399b36b331dac2b20ce4a/Controllers/AuthController.cs#L115-L136)  
```
        // U id relevant
        [HttpPut("customers/{id}")]
        [Authorize] 
        public IActionResult UpdateCustomer(int id, [FromBody] Customer updatedCustomer)
        {
            var customer = _repository.GetById(id);
            if (customer == null)
                return NotFound(new { Message = "Customer not found" });

            var userId = User.FindFirst("Id")?.Value;
            if (!User.IsInRole("Admin") && userId != customer.Id.ToString())
                return Forbid();

            customer.Nickname = updatedCustomer.Nickname;
            customer.Email = updatedCustomer.Email;
            customer.Password = updatedCustomer.Password;

            _repository.Update(customer);
            _logger.LogInformation("Customer with ID {CustomerId} updated successfully", id);

            return Ok(new { Message = "Customer updated successfully" });
        }
```
**Before**  
![Crud - Update](https://github.com/K0d0ku/web-serv_midterm/blob/master/%23images_and_files/ApiTestCrud3before.png)  
![Crud - Update](https://github.com/K0d0ku/web-serv_midterm/blob/master/%23images_and_files/ApiTestCrudDb3Before.png)  
**After**  
![Crud - Update](https://github.com/K0d0ku/web-serv_midterm/blob/master/%23images_and_files/ApiTestCrud3After.png)  
![Crud - Update](https://github.com/K0d0ku/web-serv_midterm/blob/master/%23images_and_files/ApiTestCrudDb3After.png)  

[Delete - AuthController.cs](https://github.com/K0d0ku/web-serv_midterm/blob/74ce5e44ff67db98236399b36b331dac2b20ce4a/Controllers/AuthController.cs#L138-L151)  
```
        // D id relevant
        [HttpDelete("customers/{id}")]
        [Authorize(Roles = "Admin")] 
        public IActionResult DeleteCustomer(int id)
        {
            var customer = _repository.GetById(id);
            if (customer == null)
                return NotFound(new { Message = "Customer not found" });

            _repository.Delete(id);
            _logger.LogInformation("Customer with ID {CustomerId} deleted successfully", id);

            return Ok(new { Message = "Customer deleted successfully" });
        }
```
**Created Dummy account**  
![Crud - Delete](https://github.com/K0d0ku/web-serv_midterm/blob/master/%23images_and_files/ApiTestCrud4Dum.png)  
![Crud - Delete](https://github.com/K0d0ku/web-serv_midterm/blob/master/%23images_and_files/ApiTestCrud4DumDB.png)  
**to delete another account**  
![Crud - Delete](https://github.com/K0d0ku/web-serv_midterm/blob/master/%23images_and_files/ApiTestCrud4Del.png)  
![Crud - Delete](https://github.com/K0d0ku/web-serv_midterm/blob/master/%23images_and_files/ApiTestCrud4ChkDB.png)  
![Crud - Delete](https://github.com/K0d0ku/web-serv_midterm/blob/master/%23images_and_files/ApiTestCrud4Chk.png)  
  
#### REST principles applied:
 - Each method corresponds directly to a standard HTTP verb.  
 - URLs are resource-based (/api/Auth/customers).  
 - No unnecessary verbs in URL names.  
 - Proper use of status codes (200, 401, 403, 404, 400).  
 - Role-based access for security.  
  
### 1.1. Implementation of validation (DataAnnotation, FluentAPI)  
The project uses DataAnnotation attributes directly on the [Customer.cs](https://github.com/K0d0ku/web-serv_midterm/blob/master/Models/Customer.cs) model to enforce validation rules at the model level.  
This ensures invalid data is rejected automatically before business logic executes.  
[Customer.cs](https://github.com/K0d0ku/web-serv_midterm/blob/c67fe31b22bd8da1505ffbeda6b870939c785728/Models/Customer.cs#L1-L24)  
```
﻿using System.ComponentModel.DataAnnotations;

namespace KuroApi.Models
{
    public class Customer
    {
        [Key]
        public int Id { get; set; }

        [Required]
        [StringLength(50)]
        public string Nickname { get; set; }

        [Required]
        [EmailAddress]
        public string Email { get; set; }

        [Required]
        [MinLength(6)]
        public string Password { get; set; }

        public string Role { get; set; } = "Customer";
    }
}
```
#### Validation rules in place:  
 - Nickname → required, max length 50  
 - Email → required, must be a valid email  
 - Password → required, must be at least 6 characters  
 - Id → marked as primary key

This validation is automatically enforced by the ASP.NET Core model binder —  
if the payload doesn’t match the validation rules, the controller returns 400 Bad Request without entering the repository layer.  
  
### 2. Implementation of Dependency Injection  
 - Dependency Injection (DI): [Program.cs](https://github.com/K0d0ku/web-serv_midterm/blob/master/Program.cs) registers [AppDbContext](https://github.com/K0d0ku/web-serv_midterm/blob/master/Data/AppDbContext.cs), [ICustomerRepository](https://github.com/K0d0ku/web-serv_midterm/blob/master/Repositories/ICustomerRepository.cs) → [CustomerRepository](https://github.com/K0d0ku/web-serv_midterm/blob/master/Repositories/CustomerRepository.cs), HttpClient, Identity, Authentication & Authorization. Controllers receive services through constructor injection ([AuthController](https://github.com/K0d0ku/web-serv_midterm/blob/master/Controllers/AuthController.cs)).  
 - Logging (Serilog): configured at app startup in [Program.cs](https://github.com/K0d0ku/web-serv_midterm/blob/master/Program.cs) (console + rolling file sink). Controllers use injected ILogger<T> to write structured logs.  
 - Repository Pattern: [ICustomerRepository](https://github.com/K0d0ku/web-serv_midterm/blob/master/Repositories/ICustomerRepository.cs) (interface) and [CustomerRepository](https://github.com/K0d0ku/web-serv_midterm/blob/master/Repositories/CustomerRepository.cs) (implementation) encapsulate all EF Core DB access. Controllers call repository methods instead of talking directly to [AppDbContext](https://github.com/K0d0ku/web-serv_midterm/blob/master/Data/AppDbContext.cs).

[AppDbContext.cs](https://github.com/K0d0ku/web-serv_midterm/blob/master/Data/AppDbContext.cs) — EF Core context (where models are registered)  
```
﻿using Microsoft.EntityFrameworkCore;
using KuroApi.Models;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;

namespace KuroApi.Data
{
    public class AppDbContext : IdentityDbContext<AppUser>
    {
        public AppDbContext(DbContextOptions<AppDbContext> options) : base(options) { }
        public DbSet<Customer> Customers { get; set; }
    }
}
```
Configurations in [appsettings.json](https://github.com/K0d0ku/web-serv_midterm/blob/c67fe31b22bd8da1505ffbeda6b870939c785728/appsettings.json#L2-L4) relevant to DI / logging / repository  
```
"ConnectionStrings": {
    "DefaultConnection": "Host=localhost;Port=5432;Database=KuroApiDb;Username=postgres;Password=chillen45inda3"
  },
```  

#### Dependency Injection  
[Program.cs](https://github.com/K0d0ku/web-serv_midterm/blob/master/Program.cs)
```
// db context its postgres btw
builder.Services.AddDbContext<AppDbContext>(options =>
    options.UseNpgsql(builder.Configuration.GetConnectionString("DefaultConnection")));

// dependency injection
builder.Services.AddScoped<ICustomerRepository, CustomerRepository>();

// HttpClient factory
builder.Services.AddHttpClient();

// identity
builder.Services.AddIdentity<AppUser, IdentityRole>(options =>
{
    options.Password.RequireNonAlphanumeric = false;
    options.Password.RequireUppercase = false;
    options.Password.RequireLowercase = false;
    options.Password.RequireDigit = false;
    options.Password.RequiredLength = 6;
})
.AddEntityFrameworkStores<AppDbContext>()
.AddDefaultTokenProviders();
```  
#### How controllers consume services (example from [AuthController](https://github.com/K0d0ku/web-serv_midterm/blob/c67fe31b22bd8da1505ffbeda6b870939c785728/Controllers/AuthController.cs#L15-L26) ):  
```
public class AuthController : ControllerBase
{
    private readonly ICustomerRepository _repository;
    private readonly IConfiguration _configuration;
    private readonly ILogger<AuthController> _logger;

    public AuthController(ICustomerRepository repository,
                          IConfiguration configuration,
                          ILogger<AuthController> logger)
    {
        _repository = repository;
        _configuration = configuration;
        _logger = logger;
    }

    // ... controller actions use _repository and _logger
    // rest of the code 
}
```  
  
### 2.1. Logging (Seq, Serilog)  
[Program.cs](https://github.com/K0d0ku/web-serv_midterm/blob/c67fe31b22bd8da1505ffbeda6b870939c785728/Program.cs#L20-L27)  
```
// log using serilog
Log.Logger = new LoggerConfiguration()
    .WriteTo.Console()
    .WriteTo.File("logs/log-.txt", rollingInterval: RollingInterval.Day)
    .CreateLogger();

var builder = WebApplication.CreateBuilder(args);
builder.Host.UseSerilog();
```
 - Creates a global Serilog logger and instructs the host to use Serilog as the logging provider.  
 - Two sinks are configured: console output and daily rolling file logs/log-YYYYMMDD.txt.

#### How controllers write logs (example snippets from [AuthController](https://github.com/K0d0ku/web-serv_midterm/blob/master/Controllers/AuthController.cs):  
```
_logger.LogInformation("Customer registered successfully: {CustomerId}", customer.Id);
_logger.LogInformation("Login successful for email {Email}", login.Email);
_logger.LogInformation("Fetching all customers");
_logger.LogInformation("Customer with ID {CustomerId} updated successfully", id);
_logger.LogInformation("Customer with ID {CustomerId} deleted successfully", id);
```
Additional proof of serilog loggin files in:
 - ↳Logs
   - ↳ [log-20251017.txt](https://github.com/K0d0ku/web-serv_midterm/blob/master/logs/log-20251017.txt)
```
2025-10-17 05:07:29.344 +05:00 [INF] Authorization failed. These requirements were not met:
RolesAuthorizationRequirement:User.IsInRole must be true for one of the following roles: (Admin)
2025-10-17 05:07:29.353 +05:00 [INF] AuthenticationScheme: Bearer was challenged.
2025-10-17 05:07:29.355 +05:00 [INF] Request finished HTTP/1.1 DELETE https://localhost:5255/api/Auth/customers/5 - 401 0 null 18.8682ms
2025-10-17 05:07:37.284 +05:00 [INF] Request starting HTTP/1.1 DELETE https://localhost:5255/api/Auth/customers/5 - null null
2025-10-17 05:07:37.289 +05:00 [INF] Authorization failed. These requirements were not met:
RolesAuthorizationRequirement:User.IsInRole must be true for one of the following roles: (Admin)
2025-10-17 05:07:37.293 +05:00 [INF] AuthenticationScheme: Bearer was forbidden.
2025-10-17 05:07:37.295 +05:00 [INF] Request finished HTTP/1.1 DELETE https://localhost:5255/api/Auth/customers/5 - 403 0 null 10.9217ms
```  
  
### 2.2. Repository Pattern  
Interface: [ICustomerRepository](https://github.com/K0d0ku/web-serv_midterm/blob/master/Repositories/ICustomerRepository.cs)  
```
﻿using KuroApi.Models;
using System.Collections.Generic;

namespace KuroApi.Repositories
{
    public interface ICustomerRepository
    {
        IEnumerable<Customer> GetAll();
        Customer GetById(int id);
        void Add(Customer customer);
        void Update(Customer customer);
        void Delete(int id);
        bool ExistsByEmail(string email);
    }
}
```
Implementation: [CustomerRepository](https://github.com/K0d0ku/web-serv_midterm/blob/master/Repositories/CustomerRepository.cs)
```
using KuroApi.Data;
using KuroApi.Models;
using System.Collections.Generic;
using System.Linq;

namespace KuroApi.Repositories
{
    public class CustomerRepository : ICustomerRepository
    {
        private readonly AppDbContext _context;

        public CustomerRepository(AppDbContext context)
        {
            _context = context;
        }

        public IEnumerable<Customer> GetAll() => _context.Customers.ToList();

        public Customer GetById(int id) => _context.Customers.Find(id);

        public void Add(Customer customer)
        {
            _context.Customers.Add(customer);
            _context.SaveChanges();
        }

        public void Update(Customer customer)
        {
            _context.Customers.Update(customer);
            _context.SaveChanges();
        }

        public void Delete(int id)
        {
            var customer = _context.Customers.Find(id);
            if (customer != null)
            {
                _context.Customers.Remove(customer);
                _context.SaveChanges();
            }
        }

        public bool ExistsByEmail(string email) => _context.Customers.Any(c => c.Email == email);
    }
}
```  
What it does is, it keeps the data access separate from controllers and business logic.  
Example usage in [AuthController](https://github.com/K0d0ku/web-serv_midterm/blob/master/Controllers/AuthController.cs)  
```
// check existence
if (_repository.ExistsByEmail(customer.Email))
    return BadRequest(...);

// create
_repository.Add(customer);

// read
var list = _repository.GetAll();

// update
_repository.Update(customer);

// delete
_repository.Delete(id);
```
Also to separate business logic from data access, the API uses the Repository pattern too.  
All database operations for Customer are centralized in:  
[CustomerRepository](https://github.com/K0d0ku/web-serv_midterm/blob/master/Repositories/CustomerRepository.cs)  
```
public IEnumerable<Customer> GetAll() => _context.Customers.ToList();
public Customer GetById(int id) => _context.Customers.Find(id);
public void Add(Customer customer) { ... }
public void Update(Customer customer) { ... }
public void Delete(int id) { ... }
```  
  
### 3. API testing  
You can find a lot of pictures as proof of Api Testing in [↳ Images and Files](https://github.com/K0d0ku/web-serv_midterm/tree/master/%23images_and_files) folder of the repository  

### 3.1. Using HTTPClient (or its analogues) in the WEB part (possibly ASP.NET Core or other solutions)  
For HTTPCLient or its analogues i used the ASP.NET's built in **_Swagger_** to test the api, `it also contains the authorization from №4th and №5th requirements for the project`.  
Here are the images:
- ![Swagger Test](https://github.com/K0d0ku/web-serv_midterm/blob/master/%23images_and_files/apiTestSwagger.png)  
**The rest of the images are just the link cause they are the full Scroll screenshots that also include the full **_CRUD_** phase of all**  
- [KuroApiNoAdminTest](https://github.com/K0d0ku/web-serv_midterm/blob/master/%23images_and_files/KuroApiNoAdminTest.png)  
- [KuroApiAdminTest](https://github.com/K0d0ku/web-serv_midterm/blob/master/%23images_and_files/KuroApiAdminTest.png)

### 3.2. Using Postman or other analogues  
For external API Test i used the Postman's desktop app to test and you've already seen its screenshots above many times, and here are couple of them `which btw also contains auth part too`.  
![PostmanTest](https://github.com/K0d0ku/web-serv_midterm/blob/master/%23images_and_files/ApiTestCrud2.png)  
![PostmanTest](https://github.com/K0d0ku/web-serv_midterm/blob/master/%23images_and_files/ApiTestCrud3After.png)  
  
### 4. Implementation of API authorization (JWT or other options)  
#### JWT Configuration in: 
[Program.cs](https://github.com/K0d0ku/web-serv_midterm/blob/master/Program.cs)  
```
// swagger with JWT authorization
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen(c =>
{
    c.SwaggerDoc("v1", new OpenApiInfo { Title = "KuroApi", Version = "v1" });

    // JWT auth config
    c.AddSecurityDefinition("Bearer", new OpenApiSecurityScheme
    {
        Description = "JWT Authorization header using the Bearer scheme. Example: 'Bearer {token}'",
        Name = "Authorization",
        In = ParameterLocation.Header,
        Type = SecuritySchemeType.ApiKey,
        Scheme = "Bearer"
    });

    c.AddSecurityRequirement(new OpenApiSecurityRequirement()
    {
        {
            new OpenApiSecurityScheme
            {
                Reference = new OpenApiReference { Type = ReferenceType.SecurityScheme, Id = "Bearer" }
            },
            Array.Empty<string>()
        }
    });
});


// JWT authentication
var jwtSettings = builder.Configuration.GetSection("JwtSettings");
var key = Encoding.ASCII.GetBytes(jwtSettings["Secret"]);

builder.Services
    .AddAuthentication(options =>
    {
        options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
        options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
    })
    .AddJwtBearer(options =>
    {
        options.RequireHttpsMetadata = false;
        options.SaveToken = true;
        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidateAudience = true,
            ValidateLifetime = true,
            ValidateIssuerSigningKey = true,
            ValidIssuer = jwtSettings["Issuer"],
            ValidAudience = jwtSettings["Audience"],
            IssuerSigningKey = new SymmetricSecurityKey(key),
            ClockSkew = TimeSpan.Zero
        };
    });

// auth
builder.Services.AddAuthorization();
```
- Configures the app to accept only valid JWT tokens.  
- Enforces token signature validation (using the secret key).  
- Checks issuer, audience, and token expiry.  
- Hooks into the Authentication and Authorization middleware pipeline.  
  
Then later in the pipeline:
```
app.UseAuthentication();
app.UseAuthorization();
```
This ensures every request passes through JWT validation before hitting a controller.  

#### JWT Settings in [appsettings.json](https://github.com/K0d0ku/web-serv_midterm/blob/f3136998e647d2d851db9df3c47a50099d80c48c/appsettings.json#L6-L11)  
```
"JwtSettings": {
    "Secret": "Fuckass41longsecret63myahh69RequiringMeToLenghtenThisFuckassSecret696969!",
    "Issuer": "KuroApi",
    "Audience": "KuroApiUsers",
    "ExpiryMinutes": 60
  }
```
 - Defines the secret key used to sign the JWT.  
 - Sets the issuer and audience to validate token origin and destination.  
 - Defines expiry time for token validity.
  
#### Token Generation — [AuthController.cs](https://github.com/K0d0ku/web-serv_midterm/blob/f3136998e647d2d851db9df3c47a50099d80c48c/Controllers/AuthController.cs#L48-L87)
```
// login & JWT 
        [HttpPost("login")]
        [AllowAnonymous]
        public IActionResult Login([FromBody] Customer login)
        {
            var customer = _repository.GetAll()
                .FirstOrDefault(c => c.Email == login.Email && c.Password == login.Password);

            if (customer == null)
                return Unauthorized(new { Message = "Invalid credentials" });

            var jwtSettings = _configuration.GetSection("JwtSettings");
            var key = new SymmetricSecurityKey(Encoding.ASCII.GetBytes(jwtSettings["Secret"]));
            var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

            var claims = new[]
            {
                new Claim(JwtRegisteredClaimNames.Sub, customer.Email),
                new Claim(ClaimTypes.Role, customer.Role),
                new Claim("Id", customer.Id.ToString())
            };

            var token = new JwtSecurityToken(
                issuer: jwtSettings["Issuer"],
                audience: jwtSettings["Audience"],
                claims: claims,
                expires: DateTime.UtcNow.AddMinutes(double.Parse(jwtSettings["ExpiryMinutes"])),
                signingCredentials: creds
            );

            var tokenString = new JwtSecurityTokenHandler().WriteToken(token);

            _logger.LogInformation("Login successful for email {Email}", login.Email);
            return Ok(new
            {
                Token = tokenString,
                Expires = DateTime.UtcNow.AddMinutes(double.Parse(jwtSettings["ExpiryMinutes"])),
                Role = customer.Role
            });
        }
```
 - Creates claims:  
   - sub → Email (standard claim)  
   - role → User role (Admin, Customer, etc.)  
   - Id → User ID  
 - Signs the token with HmacSha256 using the configured secret key.  
 - Returns it to the client on successful login.  
The client then uses this token in the Authorization header:  
Authorization: Bearer `<token>`  

#### Securing Endpoints with [Authorize]:  
[AuthController.cs](https://github.com/K0d0ku/web-serv_midterm/blob/master/Controllers/AuthController.cs)
```
 [HttpGet("customers")]
        [Authorize(Roles = "Admin")]
        public IActionResult GetAllCustomers()


[HttpGet("customers/{id}")]
        [Authorize] 
        public IActionResult GetCustomerById(int id)


[HttpPut("customers/{id}")]
        [Authorize] 
        public IActionResult UpdateCustomer(int id, [FromBody] Customer updatedCustomer)


[HttpDelete("customers/{id}")]
        [Authorize(Roles = "Admin")] 
        public IActionResult DeleteCustomer(int id)
```  
 - [Authorize] → endpoint requires a valid JWT.  
 - [Authorize(Roles = "Admin")] → requires both a valid JWT and role claim of Admin.  
 - Users with Customer role can only access their own data:
   - ```
            var userId = User.FindFirst("Id")?.Value;
            if (!User.IsInRole("Admin") && userId != customer.Id.ToString())
                return Forbid();
     ```  
This enforces fine-grained role-based access control.  
  
#### Integration with Swagger  
[Program.cs](https://github.com/K0d0ku/web-serv_midterm/blob/f3136998e647d2d851db9df3c47a50099d80c48c/Program.cs#L40-L59)  
```
// JWT auth config
    c.AddSecurityDefinition("Bearer", new OpenApiSecurityScheme
    {
        Description = "JWT Authorization header using the Bearer scheme. Example: 'Bearer {token}'",
        Name = "Authorization",
        In = ParameterLocation.Header,
        Type = SecuritySchemeType.ApiKey,
        Scheme = "Bearer"
    });

    c.AddSecurityRequirement(new OpenApiSecurityRequirement()
    {
        {
            new OpenApiSecurityScheme
            {
                Reference = new OpenApiReference { Type = ReferenceType.SecurityScheme, Id = "Bearer" }
            },
            Array.Empty<string>()
        }
    });
```
Swagger UI now includes an “Authorize” button, where users can paste their JWT token.  
Once authenticated, it automatically adds the token to every subsequent request in Swagger.  

**Additional image of JWT Bearer Token Authorization in Postman:***  
![JWTPostmanTest](https://github.com/K0d0ku/web-serv_midterm/blob/master/%23images_and_files/ApiTestCrud2.png)  
    
### 5. Implementation of Authentication and Authorization in an application using Identity  
This part of the project handles user authentication and role-based authorization through the ASP.NET Core Identity system, integrated with JWT authentication.  
Identity provides a built-in membership system with:  
 - User management (registration, password hashing, etc.)  
 - Role-based access control  
 - Token providers for authentication flows  
In this project, Identity is used alongside JWT to enable secure API access and role restriction between Admin and Customer users.  

#### Identity User Model
[AppUser.cs](https://github.com/K0d0ku/web-serv_midterm/blob/f3136998e647d2d851db9df3c47a50099d80c48c/Models/AppUser.cs#L1-L10)
```
﻿using Microsoft.AspNetCore.Identity;

namespace KuroApi.Models
{
    public class AppUser : IdentityUser
    {
        public string Nickname { get; set; } = string.Empty;
        public string Role { get; set; } = "Customer";
    }
}
```
 - Inherits from IdentityUser (built-in Identity class).  
 - Adds two custom properties:  
   - Nickname — friendly display name.  
   - Role — default role assigned to users is Customer.  
 - This enables the Identity system to work with our custom application data.  
It is the core identity entity, used when creating accounts and associating roles.  

#### Database Context Integration
[AppDbContext.cs](https://github.com/K0d0ku/web-serv_midterm/blob/master/Data/AppDbContext.cs)  
```
﻿using Microsoft.EntityFrameworkCore;
using KuroApi.Models;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;

namespace KuroApi.Data
{
    public class AppDbContext : IdentityDbContext<AppUser>
    {
        public AppDbContext(DbContextOptions<AppDbContext> options) : base(options) { }
        public DbSet<Customer> Customers { get; set; }
    }
}
```  
 - Inherits from IdentityDbContext<AppUser> which sets up:  
   - Identity tables (AspNetUsers, AspNetRoles, AspNetUserRoles, etc.)  
   - Relationships between users, roles, and claims.  
 - The project also keeps a separate Customer entity to support legacy / additional business logic.  
Identity tables and customer data coexist in the same PostgreSQL database.  

#### Identity Configuration
[Program.cs](https://github.com/K0d0ku/web-serv_midterm/blob/f3136998e647d2d851db9df3c47a50099d80c48c/Program.cs#L70-L79)
```
// identity
builder.Services.AddIdentity<AppUser, IdentityRole>(options =>
{
    options.Password.RequireNonAlphanumeric = false;
    options.Password.RequireUppercase = false;
    options.Password.RequireLowercase = false;
    options.Password.RequireDigit = false;
    options.Password.RequiredLength = 6;
})
.AddEntityFrameworkStores<AppDbContext>()
.AddDefaultTokenProviders();
```  
 - AddIdentity<AppUser, IdentityRole> registers the Identity system.  
 - Configures password requirements (weaker here for simplicity).  
 - Links Identity to our AppDbContext.  
 - Adds token providers for authentication flows.  
It enables the use of UserManager, RoleManager, and Identity middleware out of the box.  

#### Role Seeding (Admin / Customer)
[Program.cs](https://github.com/K0d0ku/web-serv_midterm/blob/f3136998e647d2d851db9df3c47a50099d80c48c/Program.cs#L114-L142)
```
// for now i seed a temp admin 
using (var scope = app.Services.CreateScope())
{
    var repo = scope.ServiceProvider.GetRequiredService<ICustomerRepository>();
    var roleManager = scope.ServiceProvider.GetRequiredService<RoleManager<IdentityRole>>();

    async Task SeedRolesAndAdminAsync()
    {
        var roles = new[] { "Customer", "Admin" };
        foreach (var role in roles)
        {
            if (!await roleManager.RoleExistsAsync(role))
                await roleManager.CreateAsync(new IdentityRole(role));
        }

        if (!repo.ExistsByEmail("admin@example.com"))
        {
            var admin = new Customer
            {
                Nickname = "Admin",
                Email = "admin@example.com",
                Password = "Admin123!",
                Role = "Admin"
            };
            repo.Add(admin);
        }
    }

    await SeedRolesAndAdminAsync();
}
```  
 - Creates default roles: Customer and Admin.  
 - Seeds an initial admin account if not present.  
 - This ensures access control can be tested right away.  
Admin role has full access, Customer role has limited access.  

#### Integration with JWT Authentication
[Program.cs](https://github.com/K0d0ku/web-serv_midterm/blob/f3136998e647d2d851db9df3c47a50099d80c48c/Program.cs#L82-L106)
```
// JWT authentication
var jwtSettings = builder.Configuration.GetSection("JwtSettings");
var key = Encoding.ASCII.GetBytes(jwtSettings["Secret"]);

builder.Services
    .AddAuthentication(options =>
    {
        options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
        options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
    })
    .AddJwtBearer(options =>
    {
        options.RequireHttpsMetadata = false;
        options.SaveToken = true;
        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidateAudience = true,
            ValidateLifetime = true,
            ValidateIssuerSigningKey = true,
            ValidIssuer = jwtSettings["Issuer"],
            ValidAudience = jwtSettings["Audience"],
            IssuerSigningKey = new SymmetricSecurityKey(key),
            ClockSkew = TimeSpan.Zero
        };
    });
```  
 - Configures JWT authentication.  
 - Validates issuer, audience, and signing key.  
 - Identity users can authenticate and receive JWT tokens upon login.  
This is where Identity meets stateless API security.

#### Authorization with Roles
[AuthController.cs](https://github.com/K0d0ku/web-serv_midterm/blob/master/Controllers/AuthController.cs)
```
[HttpPost("register")]
        [AllowAnonymous]
        public IActionResult Register([FromBody] Customer customer)
```  
 -  [AllowAnonymous] doesnt require anything in the context of registration it fits perfect  
***  
```
 [HttpGet("customers")]
        [Authorize(Roles = "Admin")]
        public IActionResult GetAllCustomers()

[HttpDelete("customers/{id}")]
        [Authorize(Roles = "Admin")] 
        public IActionResult DeleteCustomer(int id)
```  
 - [Authorize(Roles = "Admin")] restricts access to Admins only.  
 - Non-admins will get a 403 Forbidden response.  
***  
```
[HttpPut("customers/{id}")]
        [Authorize] 
        public IActionResult UpdateCustomer(int id, [FromBody] Customer updatedCustomer)

[HttpGet("customers/{id}")]
        [Authorize] 
        public IActionResult GetCustomerById(int id)

```  
 - [Authorize] requires any authenticated user.  
 - Logic inside checks if the user matches the ID or has Admin role.
 - Prevents one user from reading another user’s profile.  
This demonstrates fine-grained access control combining Identity roles with JWT claims.
  
### Additional content  
Most of the image and files content is located in: [↳Images and Files](https://github.com/K0d0ku/web-serv_midterm/tree/master/%23images_and_files) folder  

#### Database scheme auto generated with DataAnnotation  
![KuroApiDB](https://github.com/K0d0ku/web-serv_midterm/blob/master/%23images_and_files/KuroApiDb.png)  
A customer table auto generated and auto updated with DataAnnotation and [AuthController.cs](https://github.com/K0d0ku/web-serv_midterm/blob/master/Controllers/AuthController.cs):  
![CustomerTable](https://github.com/K0d0ku/web-serv_midterm/blob/master/%23images_and_files/customerSchemeDb.png)  
DataBase Migration Table:  
![DbMigrations](https://github.com/K0d0ku/web-serv_midterm/blob/master/%23images_and_files/DbMigrations.png)  
User Roles and its ID Table:  
![](https://github.com/K0d0ku/web-serv_midterm/blob/master/%23images_and_files/UserRoles.png)  

#### JWT Bearer Token and Identity Auth in Postman
![1](https://github.com/K0d0ku/web-serv_midterm/blob/master/%23images_and_files/JWTBearerAuth.png)  
![2](https://github.com/K0d0ku/web-serv_midterm/blob/master/%23images_and_files/JWTBearerAuth2.png)
![3](https://github.com/K0d0ku/web-serv_midterm/blob/master/%23images_and_files/JWTBearerAuth3.png)

#### Api test in Swagger
> the size of the images are too big `(1920x6480)` so its just a link here
- [KuroApiNoAdminTest](https://github.com/K0d0ku/web-serv_midterm/blob/master/%23images_and_files/KuroApiNoAdminTest.png)  
- [KuroApiAdminTest](https://github.com/K0d0ku/web-serv_midterm/blob/master/%23images_and_files/KuroApiAdminTest.png)

#### Roadmap i made in .word
[1st-midterm.docx](https://github.com/K0d0ku/web-serv_midterm/blob/master/%23images_and_files/1st-midterm.docx)
