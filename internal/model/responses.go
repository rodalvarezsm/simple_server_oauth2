package model

type TokenResponse struct {
	AccessToken string `json:"access_token"`
	Scope       string `json:"scope"`
	TokenType   string `json:"token_type"`
	Expiry      string `json:"expires_in"`
}

type IntrospectionResponse struct {
	Active   bool   `json:"active"`
	ClientId string `json:"client_id,omitempty"`
	Expiry   int64  `json:"expiry,omitempty"`
}
