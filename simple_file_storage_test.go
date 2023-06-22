package auth

import (
	"os"
	"testing"
)

func TestNewSimpleFileStorage(t *testing.T) {
	os.Remove("storage.dat")
	storage, err := NewSimpleFileStorage("storage.dat", "salt")
	if err != nil {
		t.Errorf("error initializing storage: %v", err)
	}
	if storage == nil {
		t.Error("storage is nil")
	}
}

func TestSimpleFileStorage_Save_Load_Auth(t *testing.T) {
	os.Remove("storage.dat")
	storage, err := NewSimpleFileStorage("storage.dat", "salt")
	if err != nil {
		t.Errorf("error initializing storage: %v", err)
	}
	if storage == nil {
		t.Error("storage is nil")
	}

	user := &User{
		Username:    "test",
		Roles:       NewRoleSet().Add("test_role"),
		Blacklisted: false,
	}

	err = storage.Save(user)
	if err != nil {
		t.Errorf("error saving user: %v", err)
	}

	v, err := storage.ValidatePassword("test", "test")
	if err != nil {
		t.Errorf("error validating password: %v", err)
	}

	if v {
		t.Errorf("password validation should fail")
	}

	err = storage.SetPassword("test", "test")

	if err != nil {
		t.Errorf("error setting password: %v", err)
	}

	v, err = storage.ValidatePassword("test", "test")

	if err != nil {
		t.Errorf("error validating password: %v", err)
	}

	if !v {
		t.Errorf("password validation should succeed")
	}

	storage2, err := NewSimpleFileStorage("storage.dat", "salt")
	if err != nil {
		t.Errorf("error initializing storage: %v", err)
	}

	if storage2 == nil {
		t.Error("storage is nil")
	}

	user2, err := storage2.Load("test")
	if err != nil {
		t.Errorf("error loading user: %v", err)
	}

	if user2 == nil {
		t.Error("user is nil")
	}

	if user2.Username != "test" {
		t.Errorf("user.Username should be 'test', got '%s'", user2.Username)
	}

	if user2.Blacklisted {
		t.Error("user should not be blacklisted")
	}

	if user2.Roles == nil {
		t.Error("user.Roles is nil")
	}

	if len(user2.Roles.List()) != 1 {
		t.Errorf("user.Roles.list should have 1 element, got %d", len(user2.Roles.List()))
	}

	if user2.Roles.List()[0] != "test_role" {
		t.Errorf("user.Roles.list[0] should be '%s', got '%s'", "test_role", user2.Roles.List()[0])
	}

	v, err = storage2.ValidatePassword("test", "test")

	if err != nil {
		t.Errorf("error validating password: %v", err)
	}

	if !v {
		t.Errorf("password validation should succeed")
	}

}

func TestSimpleFileStorage_Delete(t *testing.T) {
	os.Remove("storage.dat")
	storage, err := NewSimpleFileStorage("storage.dat", "salt")
	if err != nil {
		t.Errorf("error initializing storage: %v", err)
	}
	if storage == nil {
		t.Error("storage is nil")
	}

	user := &User{
		Username:    "test",
		Roles:       NewRoleSet().Add("test"),
		Blacklisted: false,
	}

	err = storage.Save(user)
	if err != nil {
		t.Errorf("error saving user: %v", err)
	}

	err = storage.SetPassword("test", "test")
	if err != nil {
		t.Errorf("error setting password: %v", err)
	}

	err = storage.Delete("test")
	if err != nil {
		t.Errorf("error deleting user: %v", err)
	}

	storage2, err := NewSimpleFileStorage("storage.dat", "salt")
	if err != nil {
		t.Errorf("error initializing storage: %v", err)
	}

	user, err = storage2.Load("test")
	if err != nil {
		t.Errorf("error loading user: %v", err)
	}

	if user != nil {
		t.Error("user should be nil")
	}

	v, err := storage2.ValidatePassword("test", "test")
	if err != nil {
		t.Errorf("error validating password: %v", err)
	}

	if v {
		t.Errorf("password validation should fail")
	}

}
