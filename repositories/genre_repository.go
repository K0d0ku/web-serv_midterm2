package repositories

import (
	"errors"

	"gorm.io/gorm"
	"midterm2/models"
)

type GenreRepository interface {
	Create(genre *models.Genre) error
	GetAll() ([]models.Genre, error)
	GetByID(id string) (*models.Genre, error)
	GetByName(name string) (*models.Genre, error)
	Update(genre *models.Genre) error
	Delete(id string) error
}

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

func (r *genreRepository) GetByName(name string) (*models.Genre, error) {
	var genre models.Genre
	result := r.db.Where("LOWER(name) = LOWER(?)", name).First(&genre)

	if errors.Is(result.Error, gorm.ErrRecordNotFound) {
		return nil, nil
	}

	return &genre, result.Error
}

func (r *genreRepository) Update(genre *models.Genre) error {
	return r.db.Save(genre).Error
}

func (r *genreRepository) Delete(id string) error {
	return r.db.Delete(&models.Genre{}, "id = ?", id).Error
}
