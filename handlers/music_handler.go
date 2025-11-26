package handlers

import (
	"github.com/google/uuid"
	"net/http"

	"github.com/go-playground/validator/v10"
	"github.com/labstack/echo/v4"
	"midterm2/dto"
	"midterm2/logger"
	"midterm2/models"
	"midterm2/services"
)

type MusicHandler struct {
	MusicService services.MusicService
	UserService  services.UserService
	GenreService services.GenreService
	Validator    *validator.Validate
}

func NewMusicHandler(mSvc services.MusicService, gSvc services.GenreService, uSvc services.UserService) *MusicHandler {
	return &MusicHandler{
		MusicService: mSvc,
		GenreService: gSvc,
		UserService:  uSvc,
		Validator:    validator.New(),
	}
}

// GENRES

// GetAllGenres godoc
// @Summary Get all genres
// @Description Fetches all music genres
// @Tags 4Genres
// @Produce json
// @Success 200 {array} models.Genre
// @Failure 500 {object} map[string]interface{}
// @Router /genres [get]
// @Security ApiKeyAuth
func (h *MusicHandler) GetAllGenres(c echo.Context) error {
	genres, err := h.GenreService.GetAll()
	if err != nil {
		logger.LogEvent("GetAllGenres", "", "", "failed", map[string]interface{}{"error": err.Error()})
		return c.JSON(http.StatusInternalServerError, echo.Map{"message": "Failed to fetch genres"})
	}
	logger.LogEvent("GetAllGenres", "", "", "success", map[string]interface{}{"count": len(genres)})
	return c.JSON(http.StatusOK, genres)
}

// GetGenreByID godoc
// @Summary Get genre by ID
// @Description Fetches a genre by its ID
// @Tags 4Genres
// @Produce json
// @Param id path string true "Genre ID"
// @Success 200 {object} models.Genre
// @Failure 404 {object} map[string]interface{}
// @Router /genres/{id} [get]
// @Security ApiKeyAuth
func (h *MusicHandler) GetGenreByID(c echo.Context) error {
	id := c.Param("id")
	genre, err := h.GenreService.GetByID(id)
	if err != nil || genre == nil {
		logger.LogEvent("GetGenreByID", "", "", "failed", map[string]interface{}{"id": id, "error": err.Error()})
		return c.JSON(http.StatusNotFound, echo.Map{"message": "Genre not found"})
	}
	logger.LogEvent("GetGenreByID", "", "", "success", map[string]interface{}{"id": id})
	return c.JSON(http.StatusOK, genre)
}

// CreateGenre godoc
// @Summary Create a new genre
// @Description Only Admins can create genres
// @Tags 4Genres
// @Accept json
// @Produce json
// @Param genre body dto.CreateGenreRequest true "Create Genre Request"
// @Success 201 {object} models.Genre
// @Failure 400 {object} map[string]interface{}
// @Failure 500 {object} map[string]interface{}
// @Router /genres [post]
// @Security ApiKeyAuth
func (h *MusicHandler) CreateGenre(c echo.Context) error {
	var req dto.CreateGenreRequest
	if err := c.Bind(&req); err != nil {
		logger.LogEvent("CreateGenre", "", "", "failed", map[string]interface{}{"error": "Invalid JSON"})
		return c.JSON(http.StatusBadRequest, echo.Map{"message": "Invalid JSON"})
	}
	if err := h.Validator.Struct(req); err != nil {
		return validationErrorResponse(c, err)
	}

	genre, err := h.GenreService.Create(req)
	if err != nil {
		logger.LogEvent("CreateGenre", "", "", "failed", map[string]interface{}{"name": req.Name, "error": err.Error()})
		return c.JSON(http.StatusInternalServerError, echo.Map{"message": "Failed to create genre"})
	}

	logger.LogEvent("CreateGenre", "", "", "success", map[string]interface{}{"name": req.Name, "genreId": genre.ID})
	return c.JSON(http.StatusCreated, genre)
}

// UpdateGenre godoc
// @Summary Update a genre
// @Description Updates a genre by ID
// @Tags 4Genres
// @Accept json
// @Produce json
// @Param id path string true "Genre ID"
// @Param genre body dto.UpdateGenreRequest true "Update Genre Request"
// @Success 200 {object} models.Genre
// @Failure 400 {object} map[string]interface{}
// @Failure 404 {object} map[string]interface{}
// @Router /genres/{id} [put]
// @Security ApiKeyAuth
func (h *MusicHandler) UpdateGenre(c echo.Context) error {
	id := c.Param("id")
	var req dto.UpdateGenreRequest
	if err := c.Bind(&req); err != nil {
		logger.LogEvent("UpdateGenre", "", "", "failed", map[string]interface{}{"error": "Invalid JSON"})
		return c.JSON(http.StatusBadRequest, echo.Map{"message": "Invalid JSON"})
	}
	if err := h.Validator.Struct(req); err != nil {
		return validationErrorResponse(c, err)
	}

	updated, err := h.GenreService.Update(id, req)
	if err != nil {
		logger.LogEvent("UpdateGenre", "", "", "failed", map[string]interface{}{"id": id, "error": err.Error()})
		return c.JSON(http.StatusBadRequest, echo.Map{"message": "Failed to update genre"})
	}

	logger.LogEvent("UpdateGenre", "", "", "success", map[string]interface{}{"id": id, "name": updated.Name})
	return c.JSON(http.StatusOK, updated)
}

// DeleteGenre godoc
// @Summary Delete a genre
// @Description Deletes a genre by ID
// @Tags 4Genres
// @Produce json
// @Param id path string true "Genre ID"
// @Success 200 {object} map[string]string
// @Failure 400 {object} map[string]interface{}
// @Router /genres/{id} [delete]
// @Security ApiKeyAuth
func (h *MusicHandler) DeleteGenre(c echo.Context) error {
	id := c.Param("id")
	if err := h.GenreService.Delete(id); err != nil {
		logger.LogEvent("DeleteGenre", "", "", "failed", map[string]interface{}{"id": id, "error": err.Error()})
		return c.JSON(http.StatusBadRequest, echo.Map{"message": "Failed to delete genre"})
	}
	logger.LogEvent("DeleteGenre", "", "", "success", map[string]interface{}{"id": id})
	return c.JSON(http.StatusOK, echo.Map{"message": "Genre deleted"})
}

// MUSIC

// Search godoc
// @Summary Search by artist, music, or genre
// @Description Global search across music title, artist name, and genre name
// @Tags 3Music
// @Produce json
// @Param q query string true "Search Query"
// @Success 200 {array} models.Music
// @Failure 400 {object} map[string]interface{}
// @Failure 500 {object} map[string]interface{}
// @Router /music/search [get]
// @Security ApiKeyAuth
func (h *MusicHandler) Search(c echo.Context) error {
	query := c.QueryParam("q")

	if query == "" {
		return c.JSON(http.StatusBadRequest, echo.Map{
			"message": "Search query is required",
		})
	}
	results, err := h.MusicService.Search(query)
	if err != nil {
		logger.LogEvent("Search", "", "", "failed", map[string]interface{}{
			"query": query,
			"error": err.Error(),
		})
		return c.JSON(http.StatusInternalServerError, echo.Map{
			"message": "Search failed",
		})
	}
	logger.LogEvent("Search", "", "", "success", map[string]interface{}{
		"query": query,
		"count": len(results),
	})
	return c.JSON(http.StatusOK, results)
}

// GetMusicByArtistID godoc
// @Summary Get all music by artist ID
// @Description Fetches all music tracks for a specific artist
// @Tags 3Music
// @Produce json
// @Param artistId path string true "Artist ID"
// @Success 200 {array} models.Music
// @Failure 400 {object} map[string]interface{}
// @Failure 404 {object} map[string]interface{}
// @Failure 500 {object} map[string]interface{}
// @Router /music/artist/{artistId} [get]
// @Security ApiKeyAuth
func (h *MusicHandler) GetMusicByArtistID(c echo.Context) error {
	artistID := c.Param("artistId")

	// Validate UUID
	if _, err := uuid.Parse(artistID); err != nil {
		logger.LogEvent("GetMusicByArtistID", "", "", "failed", map[string]interface{}{
			"artistId": artistID,
			"error":    "Invalid UUID",
		})
		return c.JSON(http.StatusBadRequest, echo.Map{"message": "Invalid artist ID"})
	}

	musics, err := h.MusicService.GetByArtistID(artistID)
	if err != nil {
		logger.LogEvent("GetMusicByArtistID", "", "", "failed", map[string]interface{}{
			"artistId": artistID,
			"error":    err.Error(),
		})
		return c.JSON(http.StatusInternalServerError, echo.Map{"message": "Failed to fetch music"})
	}

	if len(musics) == 0 {
		logger.LogEvent("GetMusicByArtistID", "", "", "success", map[string]interface{}{
			"artistId": artistID,
			"count":    0,
		})
		return c.JSON(http.StatusNotFound, echo.Map{"message": "No music found for this artist"})
	}

	logger.LogEvent("GetMusicByArtistID", "", "", "success", map[string]interface{}{
		"artistId": artistID,
		"count":    len(musics),
	})
	return c.JSON(http.StatusOK, musics)
}

// ListAllArtists godoc
// @Summary List all artists
// @Description Returns all users with role Artist
// @Tags 3Music
// @Produce json
// @Success 200 {array} models.User
// @Failure 500 {object} map[string]interface{}
// @Router /music/artists [get]
// @Security ApiKeyAuth
func (h *MusicHandler) ListAllArtists(c echo.Context) error {
	artists, err := h.UserService.ListAllArtists() // <-- call UserService
	if err != nil {
		logger.LogEvent("ListAllArtists", "", "", "failed", map[string]interface{}{"error": err.Error()})
		return c.JSON(http.StatusInternalServerError, echo.Map{"message": "Failed to fetch artists"})
	}
	logger.LogEvent("ListAllArtists", "", "", "success", map[string]interface{}{"count": len(artists)})
	return c.JSON(http.StatusOK, artists)
}

// GetAllMusic godoc
// @Summary Get all music
// @Description Fetch all music tracks
// @Tags 3Music
// @Produce json
// @Success 200 {array} models.Music
// @Failure 500 {object} map[string]interface{}
// @Router /music [get]
// @Security ApiKeyAuth
func (h *MusicHandler) GetAllMusic(c echo.Context) error {
	musics, err := h.MusicService.GetAll()
	if err != nil {
		logger.LogEvent("GetAllMusic", "", "", "failed", map[string]interface{}{"error": err.Error()})
		return c.JSON(http.StatusInternalServerError, echo.Map{"message": "Failed to fetch music"})
	}
	logger.LogEvent("GetAllMusic", "", "", "success", map[string]interface{}{"count": len(musics)})
	return c.JSON(http.StatusOK, musics)
}

// GetMusicByID godoc
// @Summary Get music by ID
// @Description Fetch a music track by ID
// @Tags 3Music
// @Produce json
// @Param id path string true "Music ID"
// @Success 200 {object} models.Music
// @Failure 404 {object} map[string]interface{}
// @Router /music/{id} [get]
// @Security ApiKeyAuth
func (h *MusicHandler) GetMusicByID(c echo.Context) error {
	id := c.Param("id")
	music, err := h.MusicService.GetByID(id)
	if err != nil || music == nil {
		logger.LogEvent("GetMusicByID", "", "", "failed", map[string]interface{}{"id": id, "error": err.Error()})
		return c.JSON(http.StatusNotFound, echo.Map{"message": "Music not found"})
	}
	logger.LogEvent("GetMusicByID", "", "", "success", map[string]interface{}{"id": id})
	return c.JSON(http.StatusOK, music)
}

// CreateMusic godoc
// @Summary Create new music
// @Description Only Artists or Admins can create music
// @Tags 3Music
// @Accept json
// @Produce json
// @Param music body dto.CreateMusicRequest true "Create Music Request"
// @Success 201 {object} models.Music
// @Failure 400 {object} map[string]interface{}
// @Failure 403 {object} map[string]interface{}
// @Router /music [post]
// @Security ApiKeyAuth
func (h *MusicHandler) CreateMusic(c echo.Context) error {
	currentUser := c.Get("user").(*models.User)

	var req dto.CreateMusicRequest
	if err := c.Bind(&req); err != nil {
		logger.LogEvent("CreateMusic", currentUser.ID.String(), string(currentUser.Role), "failed", map[string]interface{}{"error": "Invalid JSON"})
		return c.JSON(http.StatusBadRequest, echo.Map{"message": "Invalid JSON"})
	}
	if err := h.Validator.Struct(req); err != nil {
		return validationErrorResponse(c, err)
	}

	newM, err := h.MusicService.Create(req, currentUser)
	if err != nil {
		logger.LogEvent("CreateMusic", currentUser.ID.String(), string(currentUser.Role), "failed", map[string]interface{}{"title": req.Title, "error": err.Error()})
		return c.JSON(http.StatusForbidden, echo.Map{"message": "Failed to create music"})
	}

	logger.LogEvent("CreateMusic", currentUser.ID.String(), string(currentUser.Role), "success", map[string]interface{}{"title": req.Title, "musicId": newM.ID})
	return c.JSON(http.StatusCreated, newM)
}

// UpdateMusic godoc
// @Summary Update music
// @Description Update a music track by ID
// @Tags 3Music
// @Accept json
// @Produce json
// @Param id path string true "Music ID"
// @Param music body dto.UpdateMusicRequest true "Update Music Request"
// @Success 200 {object} models.Music
// @Failure 400 {object} map[string]interface{}
// @Failure 403 {object} map[string]interface{}
// @Failure 404 {object} map[string]interface{}
// @Router /music/{id} [put]
// @Security ApiKeyAuth
func (h *MusicHandler) UpdateMusic(c echo.Context) error {
	currentUser := c.Get("user").(*models.User)
	id := c.Param("id")

	var req dto.UpdateMusicRequest
	if err := c.Bind(&req); err != nil {
		logger.LogEvent("UpdateMusic", currentUser.ID.String(), string(currentUser.Role), "failed", map[string]interface{}{"error": "Invalid JSON"})
		return c.JSON(http.StatusBadRequest, echo.Map{"message": "Invalid JSON"})
	}
	if err := h.Validator.Struct(req); err != nil {
		return validationErrorResponse(c, err)
	}

	updated, err := h.MusicService.Update(id, req, currentUser)
	if err != nil {
		logger.LogEvent("UpdateMusic", currentUser.ID.String(), string(currentUser.Role), "failed", map[string]interface{}{"musicId": id, "error": err.Error()})
		return c.JSON(http.StatusForbidden, echo.Map{"message": "Failed to update music"})
	}

	logger.LogEvent("UpdateMusic", currentUser.ID.String(), string(currentUser.Role), "success", map[string]interface{}{"musicId": updated.ID})
	return c.JSON(http.StatusOK, updated)
}

// DeleteMusic godoc
// @Summary Delete music
// @Description Deletes a music track by ID
// @Tags 3Music
// @Produce json
// @Param id path string true "Music ID"
// @Success 200 {object} map[string]string
// @Failure 403 {object} map[string]interface{}
// @Router /music/{id} [delete]
// @Security ApiKeyAuth
func (h *MusicHandler) DeleteMusic(c echo.Context) error {
	currentUser := c.Get("user").(*models.User)
	id := c.Param("id")

	if err := h.MusicService.Delete(id, currentUser); err != nil {
		logger.LogEvent("DeleteMusic", currentUser.ID.String(), string(currentUser.Role), "failed", map[string]interface{}{"musicId": id, "error": err.Error()})
		return c.JSON(http.StatusForbidden, echo.Map{"message": "Failed to delete music"})
	}

	logger.LogEvent("DeleteMusic", currentUser.ID.String(), string(currentUser.Role), "success", map[string]interface{}{"musicId": id})
	return c.JSON(http.StatusOK, echo.Map{"message": "Music deleted"})
}
