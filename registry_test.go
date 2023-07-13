package auth

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

var secret = "test_secret"

type mockStorage struct {
	storage   map[string]*User
	passwords map[string]string
}

func (m mockStorage) Save(u *User) error {
	m.storage[u.Username] = u
	return nil
}

func (m mockStorage) Load(username string) (*User, error) {
	u, ok := m.storage[username]
	if !ok {
		return nil, nil
	}
	return u, nil
}

func (m mockStorage) Delete(username string) error {
	delete(m.storage, username)
	delete(m.passwords, username)
	return nil
}

func (m mockStorage) SetPassword(username string, password string) error {
	_, ok := m.storage[username]
	if !ok {
		return nil
	}
	m.passwords[username] = password
	return nil
}

func (m mockStorage) ValidatePassword(username string, password string) (bool, error) {
	_, ok := m.storage[username]
	if !ok {
		return false, nil
	}
	p, ok := m.passwords[username]
	if !ok {
		return false, nil
	}
	return p == password, nil
}

func newMockStorage() *mockStorage {
	return &mockStorage{
		passwords: make(map[string]string),
		storage:   make(map[string]*User),
	}
}

func TestUsers_Register(t *testing.T) {
	users := NewRegistry(newMockStorage(), secret)

	err := users.Register("user1", "password1")
	if err != nil {
		t.Error("registering user failed")
	}
}

func TestUsers_RegisterDuplicate(t *testing.T) {
	users := NewRegistry(newMockStorage(), secret)

	err := users.Register("user1", "password1")
	if err != nil {
		t.Error("registering user failed")
	}

	err = users.Register("user1", "password1")
	if err == nil {
		t.Error("registering duplicate user succeeded")
	}

}

func TestUsers_Login(t *testing.T) {
	users := NewRegistry(newMockStorage(), secret)

	err := users.Register("user1", "password1")
	if err != nil {
		t.Error("registering user failed")
	}

	token, refreshToken, err := users.Login("user1", "password1")
	if err != nil {
		t.Error("login failed")
	}

	if token == "" {
		t.Error("token is empty")
	}

	if refreshToken == "" {
		t.Error("refresh token is empty")
	}
}

func TestUsers_LoginWrongPassword(t *testing.T) {
	users := NewRegistry(newMockStorage(), secret)

	err := users.Register("user1", "password1")
	if err != nil {
		t.Error("registering user failed")
	}

	_, _, err = users.Login("user1", "password2")
	if err == nil {
		t.Error("login succeeded with wrong password")
	}
}

func TestUsers_LoginWrongUsername(t *testing.T) {
	users := NewRegistry(newMockStorage(), secret)

	err := users.Register("user1", "password1")
	if err != nil {
		t.Error("registering user failed")
	}

	_, _, err = users.Login("user2", "password1")
	if err == nil {
		t.Error("login succeeded with wrong username")
	}
}

func TestUsers_Refresh(t *testing.T) {
	users := NewRegistry(newMockStorage(), secret)

	err := users.Register("user1", "password1")
	if err != nil {
		t.Error("registering user failed")
	}

	_, refreshToken, err := users.Login("user1", "password1")
	if err != nil {
		t.Error("login failed")
	}

	token, err := users.Refresh("user1", refreshToken)
	if err != nil {
		t.Error("refresh failed")
	}

	if token == "" {
		t.Error("token is empty")
	}
}

func TestUsers_RefreshWrongRefreshToken(t *testing.T) {
	users := NewRegistry(newMockStorage(), secret)

	err := users.Register("user1", "password1")
	if err != nil {
		t.Error("registering user failed")
	}

	_, _, err = users.Login("user1", "password1")
	if err != nil {
		t.Error("login failed")
	}

	_, err = users.Refresh("user1", "wrong refresh token")
	if err == nil {
		t.Error("refresh succeeded with wrong refresh token")
	}
}

func TestUsers_RefreshWrongUsername(t *testing.T) {
	ms := newMockStorage()

	users := NewRegistry(ms, secret)

	err := users.Register("user1", "password1")
	if err != nil {
		t.Error("registering user failed")
	}

	_, refreshToken, err := users.Login("user1", "password1")
	if err != nil {
		t.Error("login failed")
	}

	ms.Delete("user1")

	_, err = users.Refresh("user1", refreshToken)
	if err == nil {
		t.Error("refresh succeeded with wrong username")
	}
}

func TestUsers_Blacklist(t *testing.T) {
	users := NewRegistry(newMockStorage(), secret)

	err := users.Register("user1", "password1")
	if err != nil {
		t.Error("registering user failed")
	}

	_, refreshToken, err := users.Login("user1", "password1")
	if err != nil {
		t.Error("login failed")
	}

	err = users.Blacklist("user1")
	if err != nil {
		t.Error("blacklist failed")
	}

	_, err = users.Refresh("user1", refreshToken)
	if err == nil {
		t.Error("refresh succeeded with blacklisted refresh token")
	}
}

func TestUsers_BlacklistWrongUsername(t *testing.T) {
	users := NewRegistry(newMockStorage(), secret)

	err := users.Register("user1", "password1")
	if err != nil {
		t.Error("registering user failed")
	}

	_, refreshToken, err := users.Login("user1", "password1")
	if err != nil {
		t.Error("login failed")
	}

	err = users.Blacklist("user2")
	if err == nil {
		t.Error("blacklist succeeded with wrong username")
	}

	_, err = users.Refresh("user1", refreshToken)
	if err != nil {
		t.Error("refresh failed")
	}
}

func TestAuthRequired_NoAuth(t *testing.T) {
	users := NewRegistry(newMockStorage(), secret)

	err := users.Register("user1", "password1")
	if err != nil {
		t.Error("registering user failed")
	}

	req, err := http.NewRequest("GET", "http://example.com/foo", nil)
	if err != nil {
		t.Fatal(err)
	}

	rr := httptest.NewRecorder()

	authenticator := NewMiddleware(secret)

	httpHandlerFunc := authenticator.Wrap(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.WriteHeader(http.StatusOK)
	}), true)

	httpHandlerFunc.ServeHTTP(rr, req)

	if status := rr.Code; status != http.StatusUnauthorized {
		t.Error("request succeeded without authorization")
	}
}
func TestAuthRequired_AuthCorrect(t *testing.T) {
	users := NewRegistry(newMockStorage(), secret)

	err := users.Register("user1", "password1")
	if err != nil {
		t.Error("registering user failed")
	}

	err = users.SetRoles("user1", RoleAdmin)
	if err != nil {
		t.Error("setting roles failed")
	}

	req, err := http.NewRequest("GET", "http://example.com/foo", nil)
	if err != nil {
		t.Fatal(err)
	}

	token, _, err := users.Login("user1", "password1")
	if err != nil {
		t.Fatal("login failed")
	}

	req.Header.Set("Authorization", "Bearer "+token)

	rr := httptest.NewRecorder()

	authenticator := NewMiddleware(secret)

	httpHandlerFunc := authenticator.Wrap(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.WriteHeader(http.StatusOK)
	}), true)

	httpHandlerFunc.ServeHTTP(rr, req)

	if status := rr.Code; status == http.StatusUnauthorized {
		t.Error("Authorization failed")
	}
}
