package domain

import "time"

// User represents an admin panel user.
type User struct {
	ID        int
	Username  string
	Password  string // bcrypt hash
	Role      string // "admin" | "analyst"
	CreatedAt time.Time
}
