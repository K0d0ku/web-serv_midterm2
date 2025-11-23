package services

import (
	"errors"
	"strings"

	"midterm2/dto"
	"midterm2/models"
	"midterm2/repositories"
)

type GenreService interface {
	Create(req dto.CreateGenreRequest) (*models.Genre, error)
	Update(id string, req dto.UpdateGenreRequest) (*models.Genre, error)
	Delete(id string) error
	GetAll() ([]models.Genre, error)
	GetByID(id string) (*models.Genre, error)
	GetByName(name string) (*models.Genre, error)
}

type genreService struct {
	repo repositories.GenreRepository
}

func NewGenreService(repo repositories.GenreRepository) GenreService {
	return &genreService{repo: repo}
}

func (s *genreService) Create(req dto.CreateGenreRequest) (*models.Genre, error) {
	g := &models.Genre{
		Name:        req.Name,
		Description: req.Description,
	}
	if err := s.repo.Create(g); err != nil {
		return nil, err
	}
	return g, nil
}

func (s *genreService) Update(id string, req dto.UpdateGenreRequest) (*models.Genre, error) {
	existing, err := s.repo.GetByID(id)
	if err != nil {
		return nil, err
	}
	if existing == nil {
		return nil, errors.New("genre not found")
	}

	if req.Name != "" {
		existing.Name = req.Name
	}
	if req.Description != "" {
		existing.Description = req.Description
	}

	if err := s.repo.Update(existing); err != nil {
		return nil, err
	}
	return existing, nil
}

func (s *genreService) Delete(id string) error {
	existing, err := s.repo.GetByID(id)
	if err != nil {
		return err
	}
	if existing == nil {
		return errors.New("genre not found")
	}
	return s.repo.Delete(id)
}

func (s *genreService) GetAll() ([]models.Genre, error) {
	return s.repo.GetAll()
}

func (s *genreService) GetByID(id string) (*models.Genre, error) {
	return s.repo.GetByID(id)
}

func (s *genreService) GetByName(name string) (*models.Genre, error) {
	genres, err := s.repo.GetAll()
	if err != nil {
		return nil, err
	}
	for _, g := range genres {
		if strings.EqualFold(g.Name, name) {
			return &g, nil
		}
	}
	return nil, errors.New("genre not found")
}
