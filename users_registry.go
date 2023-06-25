package auth

import (
	"errors"
	"fmt"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

var UnauthorizedError = errors.New("unauthorized")

type UsersRegistry struct {
	storage       Storage
	refreshTokens map[string]string // refresh token -> username
	secret        string
}

func NewRegistry(storage Storage, secret string) *UsersRegistry {
	return &UsersRegistry{
		storage:       storage,
		refreshTokens: make(map[string]string),
		secret:        secret,
	}
}

func (u *UsersRegistry) Register(username string, password string) error {
	user, err := u.storage.Load(username)

	if err != nil {
		return fmt.Errorf("error loading user: %w", err)
	}

	if user != nil {
		return errors.New("user already exists")
	}

	err = u.storage.Save(&User{
		Username: username,
		Roles:    NewRoleSet(),
		Options:  make(map[string]string),
	})

	if err != nil {
		return err
	}

	err = u.storage.SetPassword(username, password)
	if err != nil {
		return err
	}

	return nil
}

func (u *UsersRegistry) Login(username string, password string) (token string, refreshToken string, err error) {
	user, err := u.storage.Load(username)

	if err != nil {
		return "", "", fmt.Errorf("error loading user: %w", err)
	}

	if user == nil {
		return "", "", UnauthorizedError
	}

	if user.Blacklisted {
		return "", "", UnauthorizedError
	}

	ok, err := u.storage.ValidatePassword(username, password)
	if err != nil {
		return "", "", err
	}

	if !ok {
		return "", "", UnauthorizedError
	}

	tkn := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"username": user.Username,
		"roles":    user.Roles.String(),
	})

	refreshToken = uuid.New().String()

	u.refreshTokens[refreshToken] = user.Username

	token, err = tkn.SignedString([]byte(u.secret))
	if err != nil {
		return "", "", err
	}

	return token, refreshToken, nil
}

func (u *UsersRegistry) Refresh(username, refreshToken string) (token string, err error) {

	_, ok := u.refreshTokens[refreshToken]
	if !ok {
		return "", UnauthorizedError
	}

	if u.refreshTokens[refreshToken] != username {
		return "", UnauthorizedError
	}

	user, err := u.storage.Load(username)
	if err != nil {
		return "", fmt.Errorf("error loading user: %w", err)
	}

	if user == nil {
		return "", UnauthorizedError
	}

	if user.Blacklisted {
		return "", UnauthorizedError
	}

	tkn := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"username": user.Username,
		"roles":    user.Roles.String(),
	})

	token, err = tkn.SignedString([]byte(u.secret))
	if err != nil {
		return "", err
	}

	return token, nil

}

func (u *UsersRegistry) Logout(username, refreshToken string) error {
	user, err := u.storage.Load(username)

	if err != nil {
		return fmt.Errorf("error loading user: %w", err)
	}

	if user == nil {
		return UnauthorizedError
	}

	if u.refreshTokens[refreshToken] != username {
		return UnauthorizedError
	}

	delete(u.refreshTokens, refreshToken)
	return nil
}

func (u *UsersRegistry) Blacklist(username string) error {
	user, err := u.storage.Load(username)
	if err != nil {
		return fmt.Errorf("error loading user: %w", err)
	}

	if user == nil {
		return UnauthorizedError
	}

	user.Blacklisted = true

	return u.storage.Save(user)
}

func (u *UsersRegistry) Unblacklist(username string) error {
	user, err := u.storage.Load(username)

	if err != nil {
		return fmt.Errorf("error loading user: %w", err)
	}

	if user == nil {
		return UnauthorizedError
	}

	user.Blacklisted = false

	return u.storage.Save(user)
}

func (u *UsersRegistry) SetRoles(username string, roles ...string) error {
	user, err := u.storage.Load(username)

	if err != nil {
		return fmt.Errorf("error loading user: %w", err)
	}

	if user == nil {
		return UnauthorizedError
	}

	if user.Roles.HasAny(RoleAdmin) {
		return errors.New("admin role can't be removed")
	}

	user.Roles.Add(roles...)
	return u.storage.Save(user)
}
