package main

import (
	"github.com/google/uuid"
	"github.com/joho/godotenv"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"golang.org/x/crypto/bcrypt"
	"midterm2/config"
	"midterm2/docs"
	"midterm2/handlers"
	"midterm2/logger"
	mw "midterm2/middleware"
	"midterm2/models"
	"midterm2/repositories"
	"midterm2/services"

	"os"

	echoSwagger "github.com/swaggo/echo-swagger"
)

// @title Midterm2 Music API
// @version 1.0
// @description Music API with Users, Genres, and JWT authentication, UPDATE i tried sorting endpoints without editing auto generated swagger files it didnt worked
// @host localhost:8080
// @BasePath /
// @securityDefinitions.apikey ApiKeyAuth
// @in header
// @name Authorization
func main() {
	// Logger
	logger.InitLogger()
	logger.LogEvent("AppStartup", "", "", "info", map[string]interface{}{"message": "Initializing application"})

	// Load Env
	if err := godotenv.Load(); err != nil {
		logger.LogEvent("EnvLoad", "", "", "warning", map[string]interface{}{"message": "No .env file found, using system env"})
	} else {
		logger.LogEvent("EnvLoad", "", "", "info", map[string]interface{}{"message": ".env loaded successfully"})
	}

	// Connect DB
	config.ConnectDB()
	logger.LogEvent("DBConnect", "", "", "info", map[string]interface{}{"message": "Database connection established"})

	// Repositories
	userRepo := repositories.NewUserRepository(config.DB)
	musicRepo := repositories.NewMusicRepository(config.DB)
	genreRepo := repositories.NewGenreRepository(config.DB)

	// Services
	userService := services.NewUserService(userRepo)
	genreService := services.NewGenreService(genreRepo)
	//musicService := services.NewMusicService(musicRepo)
	musicService := services.NewMusicService(musicRepo, genreRepo)

	// Handlers
	authHandler := handlers.NewAuthHandler(userService)
	musicHandler := handlers.NewMusicHandler(musicService, genreService, userService)

	// Admin
	if err := SeedAdmin(userRepo); err != nil {
		logger.LogEvent("SeedAdmin", "", "", "error", map[string]interface{}{"error": err.Error()})
	} else {
		logger.LogEvent("SeedAdmin", "", "", "info", map[string]interface{}{"message": "Admin user ensured"})
	}

	e := echo.New()
	e.Use(mw.LoggingMiddleware)

	e.Use(middleware.CORSWithConfig(middleware.CORSConfig{
		AllowOrigins: []string{"http://localhost:5173"}, //react origin
		AllowMethods: []string{"GET", "POST", "PUT", "DELETE"},
		AllowHeaders: []string{"Authorization", "Content-Type"},
	}))

	// Swagger
	docs.SwaggerInfo.Title = "Midterm2 API"
	docs.SwaggerInfo.Description = "Music API with Users, Genres, and JWT authentication, UPDATE i tried sorting endpoints without editing auto generated swagger files it didnt worked"
	docs.SwaggerInfo.Version = "1.0"
	docs.SwaggerInfo.Host = "localhost:8080"
	docs.SwaggerInfo.BasePath = "/"
	docs.SwaggerInfo.Schemes = []string{"http"}
	e.GET("/swagger/*", echoSwagger.WrapHandler)

	// Public Routes
	e.POST("/register", authHandler.Register)
	e.POST("/login", authHandler.Login)

	// Protected Routes
	usersGroup := e.Group("/users")
	usersGroup.Use(mw.AuthMiddleware)
	usersGroup.GET("", authHandler.ListAllUsers, mw.RoleMiddleware("Admin"))
	usersGroup.GET("/:id", authHandler.GetUserByID, mw.RoleMiddleware("Admin", "Artist", "Listener"))
	usersGroup.PUT("/:id", authHandler.UpdateUser, mw.RoleMiddleware("Admin", "Artist", "Listener"))
	//usersGroup.DELETE("/:id", authHandler.DeleteUser, mw.RoleMiddleware("Admin"))
	usersGroup.DELETE("/:id", authHandler.DeleteUser)

	musicGroup := e.Group("/music")
	musicGroup.Use(mw.AuthMiddleware)
	musicGroup.GET("/artist-data/:id", musicHandler.GetArtistByID)
	musicGroup.GET("/search", musicHandler.Search)
	musicGroup.GET("/artist/:artistId", musicHandler.GetMusicByArtistID)
	musicGroup.GET("/artists", musicHandler.ListAllArtists)
	musicGroup.GET("", musicHandler.GetAllMusic)
	musicGroup.GET("/:id", musicHandler.GetMusicByID)
	musicGroup.POST("", musicHandler.CreateMusic, mw.RoleMiddleware("Artist", "Admin"))
	musicGroup.PUT("/:id", musicHandler.UpdateMusic, mw.RoleMiddleware("Artist", "Admin"))
	musicGroup.DELETE("/:id", musicHandler.DeleteMusic, mw.RoleMiddleware("Artist", "Admin"))

	genreGroup := e.Group("/genres")
	genreGroup.Use(mw.AuthMiddleware)
	genreGroup.GET("", musicHandler.GetAllGenres)
	genreGroup.GET("/:id", musicHandler.GetGenreByID)
	genreGroup.POST("", musicHandler.CreateGenre, mw.RoleMiddleware("Admin"))
	genreGroup.PUT("/:id", musicHandler.UpdateGenre, mw.RoleMiddleware("Admin"))
	genreGroup.DELETE("/:id", musicHandler.DeleteGenre, mw.RoleMiddleware("Admin"))

	// Start Server
	logger.LogEvent("ServerStart", "", "", "info", map[string]interface{}{"port": 8080})
	if err := e.Start(":8080"); err != nil {
		logger.LogEvent("ServerStart", "", "", "fatal", map[string]interface{}{"error": err.Error()})
	}
}

func SeedAdmin(userRepo repositories.UserRepository) error {
	adminEmail := os.Getenv("ADMIN_EMAIL")
	if adminEmail == "" {
		return nil
	}

	existingAdmin, _ := userRepo.GetByEmail(adminEmail)
	if existingAdmin != nil {
		return nil
	}

	password := os.Getenv("ADMIN_PASSWORD")
	if password == "" {
		return nil
	}

	hashed, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return err
	}

	admin := models.User{
		ID:       uuid.New(),
		Name:     os.Getenv("ADMIN_NAME"),
		Email:    adminEmail,
		Password: string(hashed),
		Role:     models.RoleAdmin,
	}

	if err := userRepo.Create(&admin); err != nil {
		return err
	}
	return nil
}
