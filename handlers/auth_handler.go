package handlers

import (
	"net/http"
	"time"

	"github.com/go-playground/validator/v10"
	"github.com/labstack/echo/v4"
	"midterm2/dto"
	"midterm2/logger"
	"midterm2/models"
	"midterm2/services"
	"midterm2/utils"
)

type AuthHandler struct {
	UserService services.UserService
	Validator   *validator.Validate
}

func NewAuthHandler(userService services.UserService) *AuthHandler {
	return &AuthHandler{
		UserService: userService,
		Validator:   validator.New(),
	}
}

// PUBLIC HANDLERS

// Register godoc
// @Summary Register a new user
// @Description Create a new user account. Only Artist and Listener roles allowed.
// @Tags 1Auth
// @Accept json
// @Produce json
// @Param register body dto.RegisterUserRequest true "User registration payload"
// @Success 200 {object} map[string]interface{}
// @Failure 400 {object} map[string]interface{}
// @Router /register [post]
func (h *AuthHandler) Register(c echo.Context) error {
	var req dto.RegisterUserRequest
	if err := c.Bind(&req); err != nil {
		logger.LogEvent("UserRegister", "", "", "failed", map[string]interface{}{"error": "Invalid JSON"})
		return c.JSON(http.StatusBadRequest, echo.Map{"message": "Invalid JSON"})
	}

	if err := h.Validator.Struct(req); err != nil {
		return validationErrorResponse(c, err)
	}

	user, err := h.UserService.Register(req.Name, req.Email, req.Password, req.Role)
	if err != nil {
		logger.LogEvent("UserRegister", "", "", "failed", map[string]interface{}{"email": req.Email, "error": err.Error()})
		return c.JSON(http.StatusBadRequest, echo.Map{"message": "Registration failed", "details": map[string]string{"error": err.Error()}})
	}

	logger.LogEvent("UserRegister", user.ID.String(), req.Role, "success", map[string]interface{}{"email": req.Email})
	return c.JSON(http.StatusOK, echo.Map{"message": "Registration successful", "userId": user.ID})
}

// Login godoc
// @Summary Login user
// @Description Authenticate user and return JWT token
// @Tags 1Auth
// @Accept json
// @Produce json
// @Param login body dto.LoginRequest true "Login credentials"
// @Success 200 {object} map[string]interface{}
// @Failure 400 {object} map[string]interface{}
// @Failure 401 {object} map[string]interface{}
// @Router /login [post]
func (h *AuthHandler) Login(c echo.Context) error {
	var req dto.LoginRequest
	if err := c.Bind(&req); err != nil {
		logger.LogEvent("UserLogin", "", "", "failed", map[string]interface{}{"error": "Invalid JSON"})
		return c.JSON(http.StatusBadRequest, echo.Map{"message": "Invalid JSON"})
	}

	if err := h.Validator.Struct(req); err != nil {
		return validationErrorResponse(c, err)
	}

	user, err := h.UserService.Login(req.Email, req.Password)
	if err != nil {
		logger.LogEvent("UserLogin", "", "", "failed", map[string]interface{}{"email": req.Email, "error": err.Error()})
		return c.JSON(http.StatusUnauthorized, echo.Map{"message": "Authentication failed"})
	}

	token, _ := utils.CreateToken(user.ID.String(), string(user.Role))
	logger.LogEvent("UserLogin", user.ID.String(), string(user.Role), "success", map[string]interface{}{"email": req.Email})

	return c.JSON(http.StatusOK, echo.Map{
		"token":   token,
		"role":    user.Role,
		"expires": time.Now().Add(24 * time.Hour),
	})
}

// PROTECTED HANDLERS

// ListAllUsers godoc
// @Summary Get all users
// @Description List all users (Admin only)
// @Tags 2Users
// @Produce json
// @Success 200 {array} models.User
// @Failure 500 {object} map[string]interface{}
// @Security ApiKeyAuth
// @Router /users [get]
func (h *AuthHandler) ListAllUsers(c echo.Context) error {
	users, err := h.UserService.GetAll()
	if err != nil {
		logger.LogEvent("ListAllUsers", "", "", "failed", map[string]interface{}{"error": err.Error()})
		return c.JSON(http.StatusInternalServerError, echo.Map{"message": "Failed to fetch users"})
	}
	logger.LogEvent("ListAllUsers", "", "", "success", map[string]interface{}{"count": len(users)})
	return c.JSON(http.StatusOK, users)
}

// GetUserByID godoc
// @Summary Get user by ID
// @Description Fetch a single user by ID. Admin or self only.
// @Tags 2Users
// @Produce json
// @Param id path string true "User ID"
// @Success 200 {object} models.User
// @Failure 404 {object} map[string]interface{}
// @Failure 403 {object} map[string]interface{}
// @Security ApiKeyAuth
// @Router /users/{id} [get]
func (h *AuthHandler) GetUserByID(c echo.Context) error {
	id := c.Param("id")
	currentUser := c.Get("user").(*models.User)

	user, err := h.UserService.GetByID(id)
	if err != nil || user == nil {
		logger.LogEvent("GetUserByID", "", string(currentUser.Role), "failed", map[string]interface{}{"id": id})
		return c.JSON(http.StatusNotFound, echo.Map{"message": "User not found"})
	}

	if currentUser.Role != models.RoleAdmin && currentUser.ID != user.ID {
		logger.LogEvent("GetUserByID", currentUser.ID.String(), string(currentUser.Role), "failed", map[string]interface{}{"id": id, "error": "insufficient permissions"})
		return c.JSON(http.StatusForbidden, echo.Map{"message": "Access denied"})
	}

	logger.LogEvent("GetUserByID", currentUser.ID.String(), string(currentUser.Role), "success", map[string]interface{}{"id": id})
	return c.JSON(http.StatusOK, user)
}

// UpdateUser godoc
// @Summary Update user
// @Description Update user info. Admin or self only.
// @Tags 2Users
// @Accept json
// @Produce json
// @Param id path string true "User ID"
// @Param update body dto.UpdateUserRequest true "User update payload"
// @Success 200 {object} models.User
// @Failure 400 {object} map[string]interface{}
// @Failure 403 {object} map[string]interface{}
// @Security ApiKeyAuth
// @Router /users/{id} [put]
func (h *AuthHandler) UpdateUser(c echo.Context) error {
	id := c.Param("id")
	currentUser := c.Get("user").(*models.User)

	var req dto.UpdateUserRequest
	if err := c.Bind(&req); err != nil {
		logger.LogEvent("UpdateUser", currentUser.ID.String(), string(currentUser.Role), "failed", map[string]interface{}{"error": "Invalid JSON"})
		return c.JSON(http.StatusBadRequest, echo.Map{"message": "Invalid JSON"})
	}

	if err := h.Validator.Struct(req); err != nil {
		return validationErrorResponse(c, err)
	}

	updatedUser, err := h.UserService.Update(id, &models.User{
		Name:     req.Name,
		Email:    req.Email,
		Password: req.Password,
	}, currentUser)
	if err != nil {
		logger.LogEvent("UpdateUser", currentUser.ID.String(), string(currentUser.Role), "failed", map[string]interface{}{"error": err.Error()})
		return c.JSON(http.StatusForbidden, echo.Map{"message": "Update failed"})
	}

	logger.LogEvent("UpdateUser", currentUser.ID.String(), string(currentUser.Role), "success", map[string]interface{}{"updatedId": updatedUser.ID})
	return c.JSON(http.StatusOK, updatedUser)
}

// DeleteUser godoc
// @Summary Delete user
// @Description Delete a user. Admin only.
// @Tags 2Users
// @Produce json
// @Param id path string true "User ID"
// @Success 200 {object} map[string]interface{}
// @Failure 403 {object} map[string]interface{}
// @Security ApiKeyAuth
// @Router /users/{id} [delete]
func (h *AuthHandler) DeleteUser(c echo.Context) error {
	id := c.Param("id")
	currentUser := c.Get("user").(*models.User)

	if err := h.UserService.Delete(id, currentUser); err != nil {
		logger.LogEvent("DeleteUser", currentUser.ID.String(), string(currentUser.Role), "failed", map[string]interface{}{"id": id, "error": err.Error()})
		return c.JSON(http.StatusForbidden, echo.Map{"message": "Delete failed"})
	}

	logger.LogEvent("DeleteUser", currentUser.ID.String(), string(currentUser.Role), "success", map[string]interface{}{"deletedId": id})
	return c.JSON(http.StatusOK, echo.Map{"message": "User deleted"})
}
