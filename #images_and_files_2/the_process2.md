# web-service development 2nd midterm task
___Update: Dont worry i excluded the `.gitignore` on purpose cause i wanted to show the [.env](https://github.com/K0d0ku/web-serv_midterm2/blob/main/.env), [swagger docs](https://github.com/K0d0ku/web-serv_midterm2/tree/main/docs) and [logs](https://github.com/K0d0ku/web-serv_midterm2/tree/main/logs) on purpose___  
___

## in here i show my process/progress in the making of this project and fulfilling its requirements  
!!! The list of **_Tools_** and **_Packages_** are listed in [README.md](https://github.com/K0d0ku/web-serv_midterm2/blob/main/README.md), and previous process can be seen in [the_process.md](https://github.com/K0d0ku/web-serv_midterm1/blob/master/%23images_and_files/the_process.md)  
  
#### Table of contents:  
- [Requirements](#requirements)
- [Process](#process)
- [1. Implementing CRUD operations using an external REST style](#1-implementing-crud-operations-using-an-external-rest-style)
  - [1.1 Implementing validation](#11-implementing-validation)
- [2. Implementing dependency injection](#2-implementing-dependency-injection)
  - [2.1 Logging](#21-logging)
  - [2.2 Repository pattern using a Postgres database](#22-repository-pattern-using-a-postgres-database)
- [3. API testing](#3-api-testing)
  - [3.1 Using net/http](#31-using-nethttp-or-its-equivalent)
  - [3.2 Using Postman or other equivalents](#32-using-postman-or-other-equivalents)
- [4. Implementing API authorization (JWT or other options)](#4-implementing-api-authorization-jwt-or-other-options)
- [Additional content](#additional-content)
___

## Requirements
i was given another list of requirements to make the project by following it so i can pass my 2nd midterm  
the list of requirements are:
![requirements2](https://github.com/K0d0ku/web-serv_midterm2/blob/main/%23images_and_files_2/requirements2.png)  
and following that list i have fulfilled the needed job to do:
___

## Process

I kinda had a bit of experience with .Net Maui and made an android app with a Local Database that also includes some of the requirements like: CRUD, DataAnnotation etc. from the projects like: android app development with its local database [Link🔗](https://github.com/K0d0ku/cloud_app_dev_exam_project) and making simple api in .Net Core Web API with database integration and user's permission to certain types of data [Link🔗](https://github.com/K0d0ku/web-serv_midterm1/blob/master/%23images_and_files/the_process.md)  

### Idea
I took the inspiration and idea from my [.Net B2B2C app](https://github.com/K0d0ku/cloud_app_dev_exam_project), [Postgres Mustream database](https://github.com/K0d0ku/mustream) and [.Net Core Web Api project](https://github.com/K0d0ku/web-serv_midterm1), and used some of their functions in this project.  
The idea is simple, make an api with several roles with `RBAC` for certain data and api endpoints, and mainaining it all with simple data validation and dto to keep the implementation clean.
for the idea / purpose i reused the idea from my Postgres Mustream Database and B2B2C Maui app projects, which also has RBAC, and thought of something like the following:
there will be 2 roles:
- Artist
- Listener

and `Admin` but its not technically a role,  
and 3 Api endpoint categories:  
- User  
- Music  
- Genre

and with RBAC each role will have their own access to the endpoints across these categories:  
#### User Endpoints RBAC:
| Endpoint            | Artist | Listener | Admin |
| ------------------- | ------ | -------- | ----- |
| POST `/register`    | Allowed      | Allowed        | Allowed     |
| POST `/login`       | Allowed      | Allowed        | Allowed     |
| GET `/users`        | Denied      | Denied        | Allowed     |
| GET `/users/:id`    | ID Locked     | ID Locked       | Allowed     |
| PUT `/users/:id`    | ID Locked     | ID Locked       | Allowed     |
| DELETE `/users/:id` | ID Locked     | ID Locked       | Allowed     |  

#### Music Endpoints RBAC:  
| Endpoint            | Artist | Listener | Admin |
| ------------------- | ------ | -------- | ----- |
| GET `/music`        | Allowed      | Allowed        | Allowed     |
| GET `/music/:id`    | Allowed      | Allowed        | Allowed     |
| POST `/music`       | Allowed      | Denied        | Allowed     |
| PUT `/music/:id`    | ID Locked     | Denied        | ID Locked    |
| DELETE `/music/:id` | ID Locked     | Denied        | ID Locked    |  

#### Genre Endpoints RBAC:
| Endpoint             | Artist | Listener | Admin |
| -------------------- | ------ | -------- | ----- |
| GET `/genres`        | Allowed      | Allowed        | Allowed     |
| GET `/genres/:id`    | Allowed      | Allowed        | Allowed     |
| POST `/genres`       | Denied      | Denied        | Allowed     |
| PUT `/genres/:id`    | Denied      | Denied        | Allowed     |
| DELETE `/genres/:id` | Denied      | Denied        | Allowed     |

in simple terms, upon registration, login and JWT Bearer authorization:
- Admin can do everything and additionally:
  - Create genres (admin only),
  - Update genres (admin only),
  - Delete genres (admin only),
- Artist can:
  - Create music,
  - Update music (only own),
  - Delete music (Only own),
  - Get all music or get by id,
  - Can get all genres or get by id,
  - Get user data (only own),
  - Can update credentials (only own),
  - Can delete account (only own)
- Listener can:
  - Get all music or get by id,
  - Can get all genres or get by id,
  - Get user data (only own),
  - Can update credentials (only own),
  - Can delete account (only own)
___  

## 1. Implementing CRUD operations using an external REST style
The project follows a RESTful approach for managing users, music, and genres. The architecture separates concerns across handlers, services, and repositories, ensuring clean code and maintainability. Each entity (User, Music, Genre) has its own dedicated CRUD endpoints.  
#### Users (Authentication & Profile Management)  
- Endpoints: `/register`, `/login`, `/users`, `/users/:id`
- Functionality:
  - `Register` and `Login` allow external clients to create accounts and authenticate, issuing JWT tokens.
  - Users can fetch, update, or delete their profile (or Admin can manage any user).
- Implementation Details:
  - The `AuthHandler` binds incoming JSON payloads to DTOs and validates them using the `validator` package.
  - The `UserService` handles business logic:
     ```
     user, err := s.repo.GetByID(userID)
     ```
    ensuring proper access control before updating or deleting.
- RBAC:
  - Admin has full access to all user data.
  - Artists and Listeners can access and modify only their own profiles.

#### Music
- Endpoints: /music, /music/:id
- Functionality:
  - Artists and Admins can create, update, or delete music entries.
  - All authenticated users can list and fetch music.
- Implementation Details:
  - The MusicHandler uses MusicService to perform operations, enforcing ownership checks:
     ```
     if user.Role == models.RoleArtist && music.ArtistID.String() != user.ID.String() {
    return nil, errors.New("artists can only update their own music")
    }
     ```
  - Genres are validated against the GenreRepository before associating with music.
- RBAC:
  - Artist → CRUD on own music
  - Admin → CRUD on any music
  - Listener → Read-only 

#### Genres
- Endpoints: /genres, /genres/:id
- Functionality:
  - Only Admin can create, update, or delete genres.
  - Authenticated users can list and fetch genres.
- Implementation Details:
  - The GenreService ensures that updates and deletions reference existing genres.
  - Handlers wrap service responses and log events via Zerolog:
     ```
     logger.LogEvent("CreateGenre", "", "", "success", map[string]interface{}{"name": req.Name})
     ```
- RBAC:
  - Admin → Full CRUD
  - Artist/Listener → Read-only

### 1.1 Implementing validation
Validation in the project is handled using `go-playground/validator`, ensuring that all incoming API requests comply with expected formats and constraints. The validation rules are applied at the DTO level using struct tags, and enforced in the handlers before any business logic executes.

For example, when a user registers, the `RegisterUserRequest` struct defines required fields and constraints for `Name`, `Email`, `Password`, and `Role`. If a request fails validation, the `validationErrorResponse` function generates a structured error response for the client.
[dto.go:](https://github.com/K0d0ku/web-serv_midterm2/blob/main/dto/dto.go)
```
type RegisterUserRequest struct {
	Name     string `json:"name" validate:"required,min=2,max=100"`
	Email    string `json:"email" validate:"required,email"`
	Password string `json:"password" validate:"required,min=6"`
	Role     string `json:"role" validate:"required,oneof=Artist Listener"`
}

type UpdateUserRequest struct {
	Name     string `json:"name" validate:"omitempty,min=2,max=100"`
	Email    string `json:"email" validate:"omitempty,email"`
	Password string `json:"password" validate:"omitempty,min=6"`
}

type CreateMusicRequest struct {
	Title       string `json:"title" validate:"required,min=2,max=100"`
	Description string `json:"description" validate:"omitempty,max=255"`
	FileURL     string `json:"file_url" validate:"required,url"`
	GenreID     string `json:"genre_id" validate:"required,uuid"`
}

type UpdateMusicRequest struct {
	Title       string `json:"title" validate:"omitempty,min=2,max=100"`
	Description string `json:"description" validate:"omitempty,max=255"`
	FileURL     string `json:"file_url" validate:"omitempty,url"`
	GenreID     string `json:"genre_id" validate:"omitempty,uuid"`
}
```
[validation.go:](https://github.com/K0d0ku/web-serv_midterm2/blob/501b8695e680bcc10638e29da00482183c32d423/handlers/validation.go#L9-L20)
```
// validation.go
func validationErrorResponse(c echo.Context, err error) error {
	errs := err.(validator.ValidationErrors)
	messages := make([]string, 0)

	for _, e := range errs {
		messages = append(messages, e.Field()+" failed on "+e.Tag())
	}

	return c.JSON(http.StatusBadRequest, echo.Map{
		"error": messages,
	})
}
```
In handlers, after binding the request body to a DTO, validation is immediately applied:
```
if err := h.Validator.Struct(req); err != nil {
    return validationErrorResponse(c, err)
}
```
This ensures all API inputs are sanitized and structured before hitting the service layer, preventing invalid data from affecting the database or application logic.  
![validation](https://github.com/K0d0ku/web-serv_midterm2/blob/main/%23images_and_files_2/screenshots%20for%20documentation/PostmanValidation.png)  

## 2. Implementing dependency injection
This project follows a constructor-based dependency injection style, where each layer receives its dependencies explicitly during initialization. Nothing is created deep inside business logic; instead, the application wires every component at the entry point. This approach improves testability, reduces coupling, and makes it painfully obvious (in a good way) what each part depends on.

The entire dependency graph begins in main.go, where repositories, services, and handlers are instantiated and then passed down.  
This creates a clear hierarchy:
Database → Repository → Service → Handler → Router  

#### Initialization in [main.go](https://github.com/K0d0ku/web-serv_midterm2/blob/main/main.go)
The main function is responsible for wiring all dependencies. It constructs repositories from the database connection, injects them into services, and finally passes those services into handlers. Echo groups then receive the fully wired handlers.  
```
// main.go (Dependency Wiring)
// Repositories
userRepo := repositories.NewUserRepository(config.DB)
musicRepo := repositories.NewMusicRepository(config.DB)
genreRepo := repositories.NewGenreRepository(config.DB)

// Services
userService := services.NewUserService(userRepo)
genreService := services.NewGenreService(genreRepo)
musicService := services.NewMusicService(musicRepo, genreRepo)

// Handlers
authHandler := handlers.NewAuthHandler(userService)
musicHandler := handlers.NewMusicHandler(musicService, genreService)
```  
This explicit wiring prevents hidden dependencies and keeps the system predictable. Any component’s requirements are visible at a glance.  

#### Database Injection [config/db.go](https://github.com/K0d0ku/web-serv_midterm2/blob/main/config/db.go)
The database layer is created once and injected into repositories. GORM is used as the ORM layer, with the database handle stored in a shared package variable.  
Every repository receives this DB instance, ensuring consistent access and migrations.  
```
db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{})
DB = db

db.AutoMigrate(&models.User{}, &models.Genre{}, &models.Music{})
```  
This single connection becomes the root of all data-related dependencies.

#### Routing and Handler Injection  
Handlers are added to Echo routes only after being constructed with their required services. No handler internally creates a repository or service; everything is provided from above.  
[main.go](https://github.com/K0d0ku/web-serv_midterm2/blob/main/main.go)  
```
e.POST("/register", authHandler.Register)
e.POST("/login", authHandler.Login)

musicGroup := e.Group("/music")
musicGroup.Use(mw.AuthMiddleware)
musicGroup.POST("", musicHandler.CreateMusic, mw.RoleMiddleware("Artist", "Admin"))
```
This final wiring step connects the HTTP interface to the fully-injected backend logic.  

![MusicArtistCreateMusic1.png](https://github.com/K0d0ku/web-serv_midterm2/blob/main/%23images_and_files_2/test%20screenshots/api%20tests/swagger/music/artist/MusicArtistCreateMusic1.png)  
![MusicArtistCreateMusic2.png](https://github.com/K0d0ku/web-serv_midterm2/blob/main/%23images_and_files_2/test%20screenshots/api%20tests/swagger/music/artist/MusicArtistCreateMusic2.png)  

### 2.1 Logging
The project integrates structured logging using Zerolog, ensuring that every request, error, service action, or system event is captured with consistent metadata. Logging is initialized once at startup, injected through the application's flow, and automatically rotated based on time. This satisfies the requirement of centralized diagnostic information and structured log output suitable for Seq or other JSON log processors.  

#### Logger Initialization
The logging subsystem prepares a dedicated directory, generates a timestamped log file, and configures Zerolog to write both to console and file simultaneously. This provides immediate visibility during development and persistent logs for auditing.
[logger/logger.go](https://github.com/K0d0ku/web-serv_midterm2/blob/main/logger/logger.go)  
```
var (
	sessionFile *os.File
)

func InitLogger() {
	if err := os.MkdirAll("logs", os.ModePerm); err != nil {
		panic(err)
	}

	sessionFile = createLogFile()

	multi := zerolog.MultiLevelWriter(
		zerolog.ConsoleWriter{Out: os.Stdout, TimeFormat: time.RFC3339},
		sessionFile,
	)

	log.Logger = zerolog.New(multi).With().Timestamp().Logger()
	log.Info().Msg("Zerolog initialized")
}
```
This logger is invoked immediately in the entry point, ensuring that all subsequent components receive consistent logging behavior.  
[main.go](https://github.com/K0d0ku/web-serv_midterm2/blob/main/main.go)  
```
logger.InitLogger()
logger.LogEvent("AppStartup", "", "", "info", map[string]interface{}{"message": "Initializing application"})
```

#### Structured Event Logging
All noteworthy events—database actions, authentication attempts, request failures, and service-level behavior—are recorded through a custom helper. Each entry includes mandatory fields such as event name, user ID, role, and status. This format makes it easy to analyze system behavior in Seq or other log aggregators.  
[logger/logger.go](https://github.com/K0d0ku/web-serv_midterm2/blob/main/logger/logger.go)  
```
func LogEvent(event string, userId string, role string, status string, details map[string]interface{}) {
	RotateLog()
	log.Info().
		Str("event", event).
		Str("userId", userId).
		Str("role", role).
		Str("status", status).
		Fields(details).
		Msg(event)
}
```

#### Automatic Log Rotation
The logger monitors timestamps and seamlessly rotates files when the hour changes. This prevents excessively large log files and organizes logs chronologically.  
[logger/logger.go](https://github.com/K0d0ku/web-serv_midterm2/blob/main/logger/logger.go)  
```
func RotateLog() {
	now := time.Now()
	currentHour := now.Format("2006-01-02_15")

	if sessionFile == nil {
		sessionFile = createLogFile()
		return
	}

	currentFileHour := sessionFile.Name()[len("logs/log_") : len("logs/log_")+13]

	if currentFileHour != currentHour {
		sessionFile.Close()
		sessionFile = createLogFile()
		log.Logger = zerolog.New(zerolog.MultiLevelWriter(
			zerolog.ConsoleWriter{Out: os.Stdout, TimeFormat: time.RFC3339},
			sessionFile,
		)).With().Timestamp().Logger()
		log.Info().Msg("Log rotated due to hour change")
	}
}
```

#### Request-Level Logging
Every HTTP request is captured through middleware, ensuring that the application records method, path, status code, and execution time. This provides clear visibility into API interactions.  
[middleware/logging_middleware.go](https://github.com/K0d0ku/web-serv_midterm2/blob/main/middleware/logging_middleware.go)  
```
func LoggingMiddleware(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		start := time.Now()
		err := next(c)
		stop := time.Since(start)

		logger.LogEvent(
			"HTTPRequest",
			"",
			"",
			"info",
			map[string]interface{}{
				"method": c.Request().Method,
				"path":   c.Request().URL.Path,
				"status": c.Response().Status,
				"time":   stop.String(),
			},
		)

		return err
	}
}
```

Terminal log:  
![APiZerologTerminalLog.png](https://github.com/K0d0ku/web-serv_midterm2/blob/main/%23images_and_files_2/test%20screenshots/api%20tests/APiZerologTerminalLog.png)  
Log from hourly rotated Json:  
[log_2025-11-23_16-20-51.json](https://github.com/K0d0ku/web-serv_midterm2/blob/main/logs/log_2025-11-23_16-20-51.json)  
```
{
  "level": "info",
  "event": "GetAllMusic",
  "userId": "",
  "role": "",
  "status": "success",
  "count": 16,
  "time": "2025-11-23T16:24:08+05:00",
  "message": "GetAllMusic"
}
{
  "level": "info",
  "method": "GET",
  "path": "/music",
  "user_id": "a1f3b798-c986-4fad-bd3f-04dbf6a4a8d6",
  "role": "Artist",
  "duration_ms": 20.5128,
  "time": "2025-11-23T16:24:08+05:00",
  "message": "Request completed"
}
{
  "level": "info",
  "event": "GetMusicByID",
  "userId": "",
  "role": "",
  "status": "success",
  "id": "6428c6a0-a46f-401d-bc33-6c0ea018a42c",
  "time": "2025-11-23T16:25:07+05:00",
  "message": "GetMusicByID"
}
{
  "level": "info",
  "method": "GET",
  "path": "/music/6428c6a0-a46f-401d-bc33-6c0ea018a42c",
  "user_id": "a1f3b798-c986-4fad-bd3f-04dbf6a4a8d6",
  "role": "Artist",
  "duration_ms": 6.3153,
  "time": "2025-11-23T16:25:07+05:00",
  "message": "Request completed"
}
{
  "level": "info",
  "event": "GetMusicByID",
  "userId": "",
  "role": "",
  "status": "success",
  "id": "4e213ff9-eff5-424f-ac19-31b76a777d98",
  "time": "2025-11-23T16:26:28+05:00",
  "message": "GetMusicByID"
}
```  

### 2.2 Repository pattern using a Postgres database  
The repository layer isolates database logic behind clean interfaces.  
Handlers and services never see SQL, never touch GORM/pgx, and never care how persistence works.  
They operate strictly through repository contracts — which keeps the codebase maintainable, swappable, and testable.

#### User:
[repositories/user_repository.go](https://github.com/K0d0ku/web-serv_midterm2/blob/main/repositories/user_repository.go)
```
type UserRepository interface {
	Create(ctx context.Context, user *models.User) error
	FindByEmail(ctx context.Context, email string) (*models.User, error)
	FindByID(ctx context.Context, id string) (*models.User, error)
	Update(ctx context.Context, user *models.User) error
	Delete(ctx context.Context, id string) error
}
```
This file defines the contract. Business logic depends on this interface, not on any database engine. Service layer consumes this interface to remain fully decoupled.  

[repositories/user_repository.go](https://github.com/K0d0ku/web-serv_midterm2/blob/main/repositories/user_repository.go)
```
type userRepository struct {
	db *gorm.DB
}

func NewUserRepository(db *gorm.DB) UserRepository {
	return &userRepository{db}
}

func (r *userRepository) Create(user *models.User) error {
	return r.db.Create(user).Error
}

func (r *userRepository) GetByEmail(email string) (*models.User, error) {
	var user models.User
	result := r.db.Where("email = ?", email).First(&user)

	if errors.Is(result.Error, gorm.ErrRecordNotFound) {
		return nil, nil
	}

	return &user, result.Error
}
```
A concrete repository implementation using Postgres via pgxpool. This is the layer that speaks SQL. Nothing above this layer should ever be aware of SQL strings, tables, or drivers.  

How this integrates into current architecture
Handlers → Services → Repositories → Postgres

Dependency injection step already wires:
- NewUserRepositoryPg(db) into
- NewUserService(repo) into
- NewUserHandler(service)

Which means a handler never knows if data comes from Postgres, SQLite, Redis, a mock — or a file on disk. Only the DI container decides.  
![SwaggerUserRegistration2.png](https://github.com/K0d0ku/web-serv_midterm2/blob/main/%23images_and_files_2/test%20screenshots/api%20tests/swagger/user/SwaggerUserRegistration2.png)  

#### Genre
[repositories/genre_repository.go](https://github.com/K0d0ku/web-serv_midterm2/blob/main/repositories/genre_repository.go)  
```
type GenreRepository interface {
	Create(ctx context.Context, genre *models.Genre) error
	FindByID(ctx context.Context, id string) (*models.Genre, error)
	FindAll(ctx context.Context) ([]models.Genre, error)
	Update(ctx context.Context, genre *models.Genre) error
	Delete(ctx context.Context, id string) error
}
```
This file defines the abstraction used by the service layer when working with music genres.
[repositories/genre_repository.go](https://github.com/K0d0ku/web-serv_midterm2/blob/main/repositories/genre_repository.go)  
```
type genreRepository struct {
	db *gorm.DB
}

func NewGenreRepository(db *gorm.DB) GenreRepository {
	return &genreRepository{db}
}

func (r *genreRepository) Create(genre *models.Genre) error {
	return r.db.Create(genre).Error
}

func (r *genreRepository) GetAll() ([]models.Genre, error) {
	var genres []models.Genre
	err := r.db.Find(&genres).Error
	return genres, err
}

func (r *genreRepository) GetByID(id string) (*models.Genre, error) {
	var genre models.Genre
	result := r.db.Where("id = ?", id).First(&genre)

	if errors.Is(result.Error, gorm.ErrRecordNotFound) {
		return nil, nil
	}

	return &genre, result.Error
}
```
A concrete implementation using Postgres. This is where SQL interactions are contained.
![GenreNoAdminGetAllGenres1.png](https://github.com/K0d0ku/web-serv_midterm2/blob/main/%23images_and_files_2/test%20screenshots/api%20tests/swagger/genre/GenreNoAdminGetAllGenres1.png)  

#### Music
[repositories/music_repository.go](https://github.com/K0d0ku/web-serv_midterm2/blob/main/repositories/music_repository.go)  
```
type MusicRepository interface {
	Create(ctx context.Context, music *models.Music) error
	FindByID(ctx context.Context, id string) (*models.Music, error)
	FindAllByArtist(ctx context.Context, artistID string) ([]models.Music, error)
	Update(ctx context.Context, music *models.Music) error
	Delete(ctx context.Context, id string) error
}
```
This interface defines how music data is accessed and manipulated.  
[repositories/music_repository.go](https://github.com/K0d0ku/web-serv_midterm2/blob/main/repositories/music_repository.go)  
```
type musicRepository struct {
	db *gorm.DB
}

func NewMusicRepository(db *gorm.DB) MusicRepository {
	return &musicRepository{db}
}

func (r *musicRepository) Create(music *models.Music) error {
	return r.db.Create(music).Error
}

func (r *musicRepository) GetAll() ([]models.Music, error) {
	var musics []models.Music
	err := r.db.Preload("Artist").Preload("Genre").Find(&musics).Error
	return musics, err
}

func (r *musicRepository) GetByID(id string) (*models.Music, error) {
	var music models.Music
	result := r.db.Preload("Artist").Preload("Genre").Where("id = ?", id).First(&music)

	if errors.Is(result.Error, gorm.ErrRecordNotFound) {
		return nil, nil
	}

	return &music, result.Error
}
```
This implementation encapsulates all Postgres operations for music records.  
![MusicListenerGetAllMusic.png](https://github.com/K0d0ku/web-serv_midterm2/blob/main/%23images_and_files_2/test%20screenshots/api%20tests/swagger/music/listener/MusicListenerGetAllMusic.png)

## 3. API testing
Content here.

### 3.1 Using net/http (or its equivalent)
Content here.

### 3.2 Using Postman or other equivalents
Content here.

## 4. Implementing API authorization (JWT or other options)
Content here.



### Additional content  
Most of the image and files content is located in: [↳Images and Files_2](https://github.com/K0d0ku/web-serv_midterm2/tree/main/%23images_and_files_2) folder  

#### Roadmap i made in .word
[2nd-midterm.docx](#)
