package auth

// Storage is an interface for user storage. It is used by Registry.
// It should be implemented by the user of the library.
type Storage interface {
	// Save saves a new user or updates an existing one.
	Save(u *User) error
	// Load loads a user by username. Returns nil if user not found.
	Load(username string) (*User, error)
	// Delete deletes a user by username. Missing user should not return error.
	Delete(username string) error

	// SetPassword sets a password for a user. Missing user should not return error.
	SetPassword(username string, password string) error
	// ValidatePassword validates a password for a user. Missing user should not return error,
	// but should return false.
	ValidatePassword(username string, password string) (bool, error) // should return false if user not found

}
