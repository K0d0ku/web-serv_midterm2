package services

import (
	"errors"

	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
	"midterm2/models"
	"midterm2/repositories"
)

type UserService interface {
	Register(name, email, password, role string) (*models.User, error)
	Login(email, password string) (*models.User, error)
	GetAll() ([]models.User, error)
	GetByID(id string) (*models.User, error)
	Update(userID string, updater *models.User, currentUser *models.User) (*models.User, error)
	Delete(userID string, currentUser *models.User) error

	ListAllArtists() ([]models.User, error)
}

type userService struct {
	repo repositories.UserRepository
}

func NewUserService(repo repositories.UserRepository) UserService {
	return &userService{repo: repo}
}

func (s *userService) Register(name, email, password, role string) (*models.User, error) {
	if s.repo.ExistsByEmail(email) {
		return nil, errors.New("email already registered")
	}

	hashed, _ := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	user := &models.User{
		ID:       uuid.New(),
		Name:     name,
		Email:    email,
		Password: string(hashed),
		Role:     models.UserRole(role),
	}

	if err := s.repo.Create(user); err != nil {
		return nil, err
	}

	return user, nil
}

func (s *userService) Login(email, password string) (*models.User, error) {
	user, _ := s.repo.GetByEmail(email)
	if user == nil {
		return nil, errors.New("invalid credentials")
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(password)); err != nil {
		return nil, errors.New("invalid credentials")
	}

	return user, nil
}

func (s *userService) GetAll() ([]models.User, error) {
	return s.repo.GetAll()
}

func (s *userService) GetByID(id string) (*models.User, error) {
	return s.repo.GetByID(id)
}

func (s *userService) Update(userID string, updater *models.User, currentUser *models.User) (*models.User, error) {
	user, _ := s.repo.GetByID(userID)
	if user == nil {
		return nil, errors.New("user not found")
	}

	if currentUser.Role != models.RoleAdmin && currentUser.ID != user.ID {
		return nil, errors.New("access denied")
	}

	if updater.Name != "" {
		user.Name = updater.Name
	}
	if updater.Email != "" {
		user.Email = updater.Email
	}
	if updater.Password != "" {
		hashed, _ := bcrypt.GenerateFromPassword([]byte(updater.Password), bcrypt.DefaultCost)
		user.Password = string(hashed)
	}

	if err := s.repo.Update(user); err != nil {
		return nil, err
	}

	return user, nil
}

func (s *userService) Delete(userID string, currentUser *models.User) error {
	if currentUser.Role != models.RoleAdmin && currentUser.ID.String() != userID {
		return errors.New("access denied")
	}
	return s.repo.Delete(userID)
}

func (s *userService) ListAllArtists() ([]models.User, error) {
	return s.repo.GetAllArtists()
}
