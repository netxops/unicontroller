package socks5

type CredentialStore interface {
	Valid(user, password string) bool
}

type StaticCredentials map[string]string

func (s StaticCredentials) Valid(user, password string) bool {
	pass, ok := s[user]
	if !ok {
		return false
	}
	return password == pass
}
