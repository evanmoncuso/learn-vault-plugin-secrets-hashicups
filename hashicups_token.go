package secretsengine

import (
	"context"
	"fmt"

	"github.com/google/uuid"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

const (
	hashiCupsTokenType = "hashicups_token"
)

// hashiCupsToken defines a secret for the HashiCups token
type hashiCupsToken struct {
	UserID   int    `json:"user_id"`
	Username string `json:"username"`
	TokenID  string `json:"token_id"`
	Token    string `json:"token"`
}

// hashiCupsToken defines a secret to store for a given role
// and how it should be revoked or renewed.
func (b *hashiCupsBackend) hashiCupsToken() *framework.Secret {
	return &framework.Secret{
		Type: hashiCupsTokenType,
		Fields: map[string]*framework.FieldSchema{
			"token": {
				Type:        framework.TypeString,
				Description: "HashiCups token",
			},
		},
		Revoke: b.tokenRevoke,
	}
}

// tokenRevoke removes the token from the Vault storage API and calls the client to revoke the token
func (b *hashiCupsBackend) tokenRevoke(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	client, err := b.getClient(ctx, req.Storage)

	if err != nil {
		return nil, fmt.Errorf("error getting client: %w", err)
	}

	token := ""
	tokenRaw, ok := req.Secret.InternalData["token"]

	if ok {
		token, ok = tokenRaw.(string)
		if !ok {
			return nil, fmt.Errorf("invalid value for token in the internal data")
		}
	}

	if err := deleteToken(ctx, client, token); err != nil {
		return nil, fmt.Errorf("error revokeing user token: %w", err)
	}

	return nil, nil
}

// tokenRenew calls the client to create a new token and stores it in the Vault storage API
func (b *hashiCupsBackend) tokenRenew(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {

	return nil, nil
}

// internal functions
func deleteToken(ctx context.Context, c *hashiCupsClient, token string) error {
	// set the token on the client, so the hashicups server can know what token to invalidate
	c.Client.Token = token

	err := c.SignOut()

	// ?
	if err != nil {
		return nil
	}

	return nil
}

func createToken(ctx context.Context, c *hashiCupsClient, username string) (*hashiCupsToken, error) {
	// this secrets engine cannot sign in as multiple "users"
	// so the username is effectively "hardcoded" from the config
	response, err := c.SignIn()
	if err != nil {
		return nil, fmt.Errorf("error creating hashicups token: %w", err)
	}

	tokenID := uuid.New().String()

	return &hashiCupsToken{
		UserID: response.UserID,
		// could/should we retrieve this from storage?
		Username: username,
		TokenID:  tokenID,
		Token:    response.Token,
	}, nil
}
