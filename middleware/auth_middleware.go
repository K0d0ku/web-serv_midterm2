package middleware

import (
	"net/http"
	"os"
	"strings"

	"github.com/golang-jwt/jwt/v5"
	"github.com/labstack/echo/v4"
	"midterm2/config"
	"midterm2/models"
	"midterm2/repositories"
)

var JWTSecret = []byte(os.Getenv("JWT_SECRET"))

func AuthMiddleware(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		authHeader := c.Request().Header.Get("Authorization")
		if authHeader == "" {
			return c.JSON(http.StatusUnauthorized, echo.Map{"error": "Missing Authorization header"})
		}

		parts := strings.Split(authHeader, " ")
		if len(parts) != 2 || parts[0] != "Bearer" {
			return c.JSON(http.StatusUnauthorized, echo.Map{"error": "Invalid Authorization header"})
		}

		tokenStr := parts[1]

		token, err := jwt.Parse(tokenStr, func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, echo.NewHTTPError(http.StatusUnauthorized, "Unexpected signing method")
			}
			return JWTSecret, nil
		})

		if err != nil || !token.Valid {
			return c.JSON(http.StatusUnauthorized, echo.Map{"error": "Invalid token"})
		}

		claims, ok := token.Claims.(jwt.MapClaims)
		if !ok {
			return c.JSON(http.StatusUnauthorized, echo.Map{"error": "Invalid token claims"})
		}

		userIDStr, ok := claims["sub"].(string)
		if !ok {
			return c.JSON(http.StatusUnauthorized, echo.Map{"error": "Invalid user ID in token"})
		}

		userRepo := repositories.NewUserRepository(config.DB)
		user, err := userRepo.GetByID(userIDStr)
		if err != nil || user == nil {
			return c.JSON(http.StatusUnauthorized, echo.Map{"error": "User not found"})
		}

		c.Set("user", user)

		return next(c)
	}
}

func RoleMiddleware(allowedRoles ...string) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			user, ok := c.Get("user").(*models.User)
			if !ok || user == nil {
				return c.JSON(http.StatusForbidden, echo.Map{"error": "No user in context"})
			}

			for _, allowed := range allowedRoles {
				if string(user.Role) == allowed {
					return next(c)
				}
			}

			return c.JSON(http.StatusForbidden, echo.Map{"error": "Insufficient permissions"})
		}
	}
}
