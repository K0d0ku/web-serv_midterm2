package middleware

import (
	"time"

	"github.com/labstack/echo/v4"
	"midterm2/logger"
	"midterm2/models"

	"github.com/rs/zerolog/log"
)

func LoggingMiddleware(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		start := time.Now()
		err := next(c)
		stop := time.Now()

		logger.LogRotation()

		user, _ := c.Get("user").(*models.User)
		log.Info().
			Str("method", c.Request().Method).
			Str("path", c.Request().URL.Path).
			Str("user_id", func() string {
				if user != nil {
					return user.ID.String()
				}
				return "guest"
			}()).
			Str("role", func() string {
				if user != nil {
					return string(user.Role)
				}
				return "guest"
			}()).
			Dur("duration_ms", stop.Sub(start)).
			Msg("Request completed")
		return err
	}
}
