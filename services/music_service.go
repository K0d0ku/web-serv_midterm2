package services

import (
	"errors"
	"strings"

	"github.com/google/uuid"
	"midterm2/dto"
	"midterm2/models"
	"midterm2/repositories"
)

type MusicService interface {
	Create(req dto.CreateMusicRequest, user *models.User) (*models.Music, error)
	Update(id string, req dto.UpdateMusicRequest, user *models.User) (*models.Music, error)
	Delete(id string, user *models.User) error
	GetAll() ([]models.Music, error)
	GetByID(id string) (*models.Music, error)
	GetByTitle(title string) (*models.Music, error)
	GetByGenre(genreID string) ([]models.Music, error)

	GetAllArtists() ([]models.User, error)
	GetByArtistID(artistID string) ([]models.Music, error)
	Search(query string) ([]models.Music, error)
	GetArtistByID(artistID string) (*models.User, error)
}

type musicService struct {
	musicRepo repositories.MusicRepository
	genreRepo repositories.GenreRepository
}

func NewMusicService(mRepo repositories.MusicRepository, gRepo repositories.GenreRepository) MusicService {
	return &musicService{
		musicRepo: mRepo,
		genreRepo: gRepo,
	}
}

func (s *musicService) Create(req dto.CreateMusicRequest, user *models.User) (*models.Music, error) {
	if user.Role != models.RoleArtist && user.Role != models.RoleAdmin {
		return nil, errors.New("only artists or admins can create music")
	}

	genreUUID, err := uuid.Parse(req.GenreID)
	if err != nil {
		return nil, errors.New("invalid genre_id: must be a valid UUID")
	}

	genre, err := s.genreRepo.GetByID(genreUUID.String())
	if err != nil {
		return nil, err
	}
	if genre == nil {
		return nil, errors.New("genre not found")
	}

	m := &models.Music{
		Title:       req.Title,
		Description: req.Description,
		FileURL:     req.FileURL,
		GenreID:     genreUUID,
		ArtistID:    user.ID,
	}

	if err := s.musicRepo.Create(m); err != nil {
		return nil, err
	}

	return m, nil
}

func (s *musicService) Update(id string, req dto.UpdateMusicRequest, user *models.User) (*models.Music, error) {
	music, err := s.musicRepo.GetByID(id)
	if err != nil {
		return nil, err
	}
	if music == nil {
		return nil, errors.New("music not found")
	}

	if user.Role == models.RoleArtist && music.ArtistID.String() != user.ID.String() {
		return nil, errors.New("artists can only update their own music")
	}

	if req.Title != "" {
		music.Title = req.Title
	}
	if req.Description != "" {
		music.Description = req.Description
	}
	if req.FileURL != "" {
		music.FileURL = req.FileURL
	}
	if req.GenreID != "" {
		genreUUID, err := uuid.Parse(req.GenreID)
		if err != nil {
			return nil, errors.New("invalid genre_id: must be a valid UUID")
		}
		genre, err := s.genreRepo.GetByID(genreUUID.String())
		if err != nil {
			return nil, err
		}
		if genre == nil {
			return nil, errors.New("genre not found")
		}
		music.GenreID = genreUUID
	}

	if err := s.musicRepo.Update(music); err != nil {
		return nil, err
	}

	return music, nil
}

func (s *musicService) Delete(id string, user *models.User) error {
	music, err := s.musicRepo.GetByID(id)
	if err != nil {
		return err
	}
	if music == nil {
		return errors.New("music not found")
	}

	if user.Role == models.RoleArtist && music.ArtistID.String() != user.ID.String() {
		return errors.New("artists can only delete their own music")
	}

	return s.musicRepo.Delete(id)
}

func (s *musicService) GetAll() ([]models.Music, error) {
	return s.musicRepo.GetAll()
}

func (s *musicService) GetByID(id string) (*models.Music, error) {
	return s.musicRepo.GetByID(id)
}

func (s *musicService) GetByTitle(title string) (*models.Music, error) {
	m, err := s.musicRepo.GetByTitle(title)
	if err != nil {
		return nil, err
	}
	if m == nil {
		return nil, errors.New("music not found")
	}
	return m, nil
}

func (s *musicService) GetByGenre(genreID string) ([]models.Music, error) {
	return s.musicRepo.GetByGenre(genreID)
}

func (s *musicService) GetAllArtists() ([]models.User, error) {
	musics, err := s.musicRepo.GetAll()
	if err != nil {
		return nil, err
	}
	artistMap := make(map[string]models.User)
	for _, m := range musics {
		artistMap[m.Artist.ID.String()] = m.Artist
	}
	artists := make([]models.User, 0, len(artistMap))
	for _, a := range artistMap {
		artists = append(artists, a)
	}
	return artists, nil
}

func (s *musicService) GetByArtistID(artistID string) ([]models.Music, error) {
	return s.musicRepo.GetByArtistID(artistID)
}

func (s *musicService) Search(query string) ([]models.Music, error) {
	query = strings.TrimSpace(query)
	if query == "" {
		return nil, errors.New("search query is empty")
	}
	return s.musicRepo.Search(query)
}

func (s *musicService) GetArtistByID(artistID string) (*models.User, error) {
	artist, err := s.musicRepo.GetArtistByID(artistID)
	if err != nil {
		return nil, err
	}
	if artist == nil {
		return nil, errors.New("artist not found or invalid role")
	}
	return artist, nil
}
