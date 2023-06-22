package auth

type User struct {
	// Username is a unique identifier of the user. It is used as a key in the storage.
	// Password is not stored in the User struct. It is stored in the storage.
	Username string
	// Roles is a list of roles assigned to the user. It is used for authorization.
	Roles RoleSet
	// Blacklisted is a flag that indicates that the user is blacklisted and should
	// not be allowed to login.
	Blacklisted bool
	// Options is a map of user options. It can be used to store additional information
	// about the user.
	Options map[string]string
}
