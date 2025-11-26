package repositories

import (
	"errors"

	"gorm.io/gorm"
	"midterm2/models"
)

type MusicRepository interface {
	Create(music *models.Music) error
	GetAll() ([]models.Music, error)
	GetByID(id string) (*models.Music, error)
	GetByGenre(genreID string) ([]models.Music, error)
	GetByTitle(title string) (*models.Music, error)
	Update(music *models.Music) error
	Delete(id string) error
	GetByArtistID(artistID string) ([]models.Music, error)
	Search(query string) ([]models.Music, error)
}

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

func (r *musicRepository) GetByGenre(genreID string) ([]models.Music, error) {
	var musics []models.Music
	err := r.db.Preload("Artist").Preload("Genre").Where("genre_id = ?", genreID).Find(&musics).Error
	return musics, err
}

func (r *musicRepository) GetByTitle(title string) (*models.Music, error) {
	var music models.Music
	result := r.db.Where("LOWER(title) = LOWER(?)", title).First(&music)

	if errors.Is(result.Error, gorm.ErrRecordNotFound) {
		return nil, nil
	}

	return &music, result.Error
}

func (r *musicRepository) Update(music *models.Music) error {
	return r.db.Save(music).Error
}

func (r *musicRepository) Delete(id string) error {
	return r.db.Delete(&models.Music{}, "id = ?", id).Error
}

func (r *musicRepository) GetByArtistID(artistID string) ([]models.Music, error) {
	var musics []models.Music
	err := r.db.Preload("Artist").Preload("Genre").Where("artist_id = ?", artistID).Find(&musics).Error
	return musics, err
}

func (r *musicRepository) Search(query string) ([]models.Music, error) {
	var results []models.Music

	q := "%" + query + "%"

	err := r.db.
		Preload("Artist").
		Preload("Genre").
		Joins("LEFT JOIN users ON users.id = musics.artist_id").
		Joins("LEFT JOIN genres ON genres.id = musics.genre_id").
		Where(
			"LOWER(musics.title) LIKE LOWER(?) OR LOWER(users.name) LIKE LOWER(?) OR LOWER(genres.name) LIKE LOWER(?)",
			q, q, q,
		).
		Find(&results).Error

	return results, err
}
