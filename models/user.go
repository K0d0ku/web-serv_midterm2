package models

import (
	"github.com/google/uuid"
	"time"
)

type UserRole string

const (
	RoleAdmin    UserRole = "Admin"
	RoleArtist   UserRole = "Artist"
	RoleListener UserRole = "Listener"
)

type User struct {
	ID        uuid.UUID `gorm:"type:uuid;default:uuid_generate_v4();primaryKey"`
	Name      string    `gorm:"size:100;not null" validate:"required,min=2,max=100"`
	Email     string    `gorm:"size:150;uniqueIndex;not null" validate:"required,email"`
	Password  string    `gorm:"not null" validate:"required,min=6"`
	Role      UserRole  `gorm:"type:varchar(20);not null" validate:"required,oneof=Admin Artist Listener"`
	CreatedAt time.Time
	UpdatedAt time.Time

	UploadedMusic []Music `gorm:"foreignKey:ArtistID"`
}
