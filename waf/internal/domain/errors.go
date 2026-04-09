package domain

import "errors"

// ErrInvalidCredentials is returned when a login attempt fails due to bad username or password.
var ErrInvalidCredentials = errors.New("invalid credentials")
