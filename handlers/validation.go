package handlers

import (
	"github.com/go-playground/validator/v10"
	"github.com/labstack/echo/v4"
	"net/http"
)

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
