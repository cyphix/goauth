package goauth

import "errors"

// InputError marks validation problems that should surface as HTTP 400/409
// instead of 500.
type InputError struct{ msg string }

func (e InputError) Error() string { return e.msg }

// ErrInvalidInput builds an InputError.
func ErrInvalidInput(msg string) error { return InputError{msg: msg} }

// IsInputError reports whether err is an InputError.
func IsInputError(err error) bool {
	var ie InputError
	return errors.As(err, &ie)
}

var (
	// ErrInvalidCredentials is returned for unknown users, wrong passwords
	// and disabled accounts (indistinguishable on purpose).
	ErrInvalidCredentials = errors.New("invalid credentials")
	// ErrNotFound is returned when a record does not exist.
	ErrNotFound = errors.New("not found")
	// ErrPasswordManagedByIdP is returned when an OIDC-linked account without a local password tries to create one via self-service.
	ErrPasswordManagedByIdP = errors.New("password is managed by the identity provider")
)
