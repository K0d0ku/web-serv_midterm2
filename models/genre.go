package models

import (
	"github.com/google/uuid"
)

type Genre struct {
	ID          uuid.UUID `gorm:"type:uuid;default:uuid_generate_v4();primaryKey"`
	Name        string    `gorm:"size:50;uniqueIndex;not null" validate:"required,min=2,max=50"`
	Description string    `gorm:"size:255" validate:"max=255"`

	Music []Music `gorm:"foreignKey:GenreID"`
}
