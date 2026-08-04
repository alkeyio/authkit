package sql

import "github.com/tniah/authkit/models"

// Compile-time check that *User implements models.User.
var _ models.User = (*User)(nil)

type User struct {
	UserID string `json:"user_id"`
}

func (u *User) GetUserID() string {
	return u.UserID
}
