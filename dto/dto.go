package dto

// User DTOs
type RegisterUserRequest struct {
	Name     string `json:"name" validate:"required,min=2,max=100"`
	Email    string `json:"email" validate:"required,email"`
	Password string `json:"password" validate:"required,min=6"`
	Role     string `json:"role" validate:"required,oneof=Artist Listener"`
}

type LoginRequest struct {
	Email    string `json:"email" validate:"required,email"`
	Password string `json:"password" validate:"required"`
}

type UpdateUserRequest struct {
	Name     string `json:"name" validate:"omitempty,min=2,max=100"`
	Email    string `json:"email" validate:"omitempty,email"`
	Password string `json:"password" validate:"omitempty,min=6"`
}

// Genre DTOs
type CreateGenreRequest struct {
	Name        string `json:"name" validate:"required,min=2,max=50"`
	Description string `json:"description" validate:"omitempty,max=255"`
}

type UpdateGenreRequest struct {
	Name        string `json:"name" validate:"omitempty,min=2,max=50"`
	Description string `json:"description" validate:"omitempty,max=255"`
}

// Music DTOs
type CreateMusicRequest struct {
	Title       string `json:"title" validate:"required,min=2,max=100"`
	Description string `json:"description" validate:"omitempty,max=255"`
	FileURL     string `json:"file_url" validate:"required,url"`
	GenreID     string `json:"genre_id" validate:"required,uuid"`
	// ArtistID is intentionally omitted — artist is taken from auth token/currentUser
}

type UpdateMusicRequest struct {
	Title       string `json:"title" validate:"omitempty,min=2,max=100"`
	Description string `json:"description" validate:"omitempty,max=255"`
	FileURL     string `json:"file_url" validate:"omitempty,url"`
	GenreID     string `json:"genre_id" validate:"omitempty,uuid"`
}
