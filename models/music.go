package models

import (
	"github.com/google/uuid"
	"time"
)

type Music struct {
	ID          uuid.UUID `gorm:"type:uuid;default:uuid_generate_v4();primaryKey"`
	Title       string    `gorm:"size:100;not null" validate:"required,min=2,max=100"`
	Description string    `gorm:"size:255" validate:"max=255"`
	FileURL     string    `gorm:"size:255" validate:"required,url"`

	GenreID uuid.UUID `gorm:"type:uuid"`
	Genre   Genre     `gorm:"constraint:OnUpdate:CASCADE,OnDelete:SET NULL;"`

	ArtistID uuid.UUID `gorm:"type:uuid"`
	Artist   User      `gorm:"constraint:OnUpdate:CASCADE,OnDelete:SET NULL;"`

	CreatedAt time.Time
}
