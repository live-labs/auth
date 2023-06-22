package auth

import (
	"bufio"
	"crypto"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"
)

// SimpleFileStorage is a simple file-based storage implementation
// for the UsersRegistry. It stores users in a hystorical file order.
// It is not intended for production usr, but it is useful for testing.
// The file format is:
// +unix_timestamp_ms:username:password_hash:role1,role2,role3:0|1:{json encoded user data}
// -unix_timestamp_ms:username
// file is append-only, so if a user is deleted, the line is added with -username
type SimpleFileStorage struct {
	path      string
	salt      string
	stateLock sync.Mutex

	state          map[string]*User
	passwordHashes map[string]string
}

func (s *SimpleFileStorage) open() (*os.File, error) {
	f, err := os.OpenFile(s.path, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0600)
	if err != nil {
		return nil, err
	}
	return f, nil
}

func NewSimpleFileStorage(path, salt string) (*SimpleFileStorage, error) {

	sfs := &SimpleFileStorage{
		path:           path,
		state:          make(map[string]*User),
		passwordHashes: make(map[string]string),
	}

	err := sfs.loadState()
	if err != nil {
		return nil, fmt.Errorf("error loading state: %w", err)
	}

	return sfs, nil

}

func (s *SimpleFileStorage) loadState() error {
	f, err := s.open()
	if err != nil {
		return fmt.Errorf("error opening file: %w", err)
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()

		parts := strings.SplitN(line[1:], ":", 6)
		//timestamp := parts[0]
		username := parts[1]

		switch line[0] {
		case '+':
			passwordHash := parts[2]
			roles := parts[3]
			banned := parts[4] == "1"
			options := parts[5]

			var userOptions map[string]string
			err := json.Unmarshal([]byte(options), &userOptions)
			if err != nil {
				return fmt.Errorf("error unmarshaling user options: %w", err)
			}

			rl := NewRoleSet()
			rl.LoadFrom(roles)

			// add user
			s.state[username] = &User{
				Username:    username,
				Roles:       rl,
				Blacklisted: banned,
				Options:     userOptions,
			}
			s.passwordHashes[username] = passwordHash
		case '-':
			delete(s.state, username)
			delete(s.passwordHashes, username)
		default:
			return fmt.Errorf("invalid line in file: %s", line)
		}
	}
	return nil
}

func (s *SimpleFileStorage) Save(u *User) error {
	s.stateLock.Lock()
	defer s.stateLock.Unlock()

	f, err := s.open()
	if err != nil {
		return fmt.Errorf("error opening file: %w", err)
	}
	defer f.Close()

	ts := time.Now().UnixMilli()

	bl := 0
	if u.Blacklisted {
		bl = 1
	}

	options, err := json.Marshal(u.Options)
	if err != nil {
		return fmt.Errorf("error marshaling user options: %w", err)
	}

	// write user to file
	_, err = f.WriteString(fmt.Sprintf("+%d:%s:%s:%s:%d:%s\n", ts, u.Username, s.passwordHashes[u.Username], u.Roles.String(), bl, options))
	if err != nil {
		return fmt.Errorf("error writing to file: %w", err)
	}

	s.state[u.Username] = u

	return nil
}

func (s *SimpleFileStorage) Load(username string) (*User, error) {
	s.stateLock.Lock()
	defer s.stateLock.Unlock()

	u, ok := s.state[username]
	if !ok {
		return nil, nil
	}
	return u, nil
}

func (s *SimpleFileStorage) Delete(username string) error {
	s.stateLock.Lock()
	defer s.stateLock.Unlock()

	f, err := s.open()
	if err != nil {
		return fmt.Errorf("error opening file: %w", err)
	}
	defer f.Close()

	ts := time.Now().UnixMilli()

	// write user to file
	_, err = f.WriteString(fmt.Sprintf("-%d:%s\n", ts, username))
	if err != nil {
		return fmt.Errorf("error writing to file: %w", err)
	}

	delete(s.state, username)
	delete(s.passwordHashes, username)

	return nil
}

func (s *SimpleFileStorage) SetPassword(username string, password string) error {
	s.stateLock.Lock()
	defer s.stateLock.Unlock()

	f, err := s.open()
	if err != nil {
		return fmt.Errorf("error opening file: %w", err)
	}
	defer f.Close()

	user, ok := s.state[username]
	if !ok {
		return fmt.Errorf("user not found")
	}

	ts := time.Now().UnixMilli()
	bl := 0
	if user.Blacklisted {
		bl = 1
	}

	options, err := json.Marshal(user.Options)
	if err != nil {
		return fmt.Errorf("error marshaling user options: %w", err)
	}

	// write user to file
	_, err = f.WriteString(fmt.Sprintf("+%d:%s:%s:%s:%d:%s\n", ts, username, s.hashPassword(password), s.state[username].Roles.String(), bl, options))
	if err != nil {
		return fmt.Errorf("error writing to file: %w", err)
	}

	s.passwordHashes[username] = s.hashPassword(password)

	return nil
}

func (s *SimpleFileStorage) ValidatePassword(username string, password string) (bool, error) {
	s.stateLock.Lock()
	defer s.stateLock.Unlock()

	_, ok := s.state[username]
	if !ok {
		return false, nil
	}

	hash, ok := s.passwordHashes[username]
	if !ok {
		return false, nil
	}

	return hash == s.hashPassword(password), nil
}

func (s *SimpleFileStorage) hashPassword(password string) string {
	hash := crypto.SHA256.New().Sum([]byte(password + s.salt))
	return fmt.Sprintf("%x", hash)
}
