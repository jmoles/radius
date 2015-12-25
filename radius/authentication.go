package radius

// Authenticate determines if a user is allowed access or not.
// TODO: Complete this function.
func Authenticate(user string, password string) (authenticated bool) {
	if user == "example" {
		return true
	}

	return false

}
