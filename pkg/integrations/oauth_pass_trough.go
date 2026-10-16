package integrations

import (
	"fmt"
	"net/http"
)

type OAuthPassThroughAuthenticator struct{}

func NewOAuthPassThroughAuthenticator() *OAuthPassThroughAuthenticator {
	return &OAuthPassThroughAuthenticator{}
}

func (a *OAuthPassThroughAuthenticator) Authenticate(r *http.Request) error {
	tokenValue := r.Context().Value("pass_through_oauth_token")
	token, ok := tokenValue.(string)
	if !ok || token == "" {
		// Fail closed: never fall back to a token cached from another user's request.
		return fmt.Errorf("OAuth pass-through token is missing or not a string")
	}

	r.Header.Set("Authorization", token)
	return nil
}
