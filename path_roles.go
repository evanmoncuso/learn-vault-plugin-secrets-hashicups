package secretsengine

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

// hashiCupsRoleEntry defines the data required
// for a Vault role to access and call the HashiCups
// token endpoints
type hashiCupsRoleEntry struct {
	Username string        `json:"username"`
	UserID   int           `json:"user_id"`
	Token    string        `json:"token"`
	TokenID  string        `json:"token_id"`
	TTL      time.Duration `json:"ttl"`
	MaxTTL   time.Duration `json:"max_ttl"`
}

// toResponseData returns response data for a role
func (r *hashiCupsRoleEntry) toResponseData() map[string]interface{} {
	respData := map[string]interface{}{
		"ttl":      r.TTL.Seconds(),
		"max_ttl":  r.MaxTTL.Seconds(),
		"username": r.Username,
	}
	return respData
}

// pathRole extends the Vault API with a `/role`
// endpoint for the backend. You can choose whether
// or not certain attributes should be displayed,
// required, and named. You can also define different
// path patterns to list all roles.
func pathRole(b *hashiCupsBackend) []*framework.Path {
	return []*framework.Path{
		{
			Pattern: "role/" + framework.GenericNameRegex("name"),
			Fields: map[string]*framework.FieldSchema{
				"name": {
					Type:        framework.TypeLowerCaseString,
					Description: "name of the role",
					Required:    true,
				},
				"username": {
					Type:        framework.TypeString,
					Description: "the username for api",
					Required:    true,
				},
				"ttl": {
					Type:        framework.TypeDurationSecond,
					Description: "default lease lifetime (in seconds) for the credential. Unset and 0 will use system default",
				},
				"max_ttl": {
					Type:        framework.TypeDurationSecond,
					Description: "maximum lifetime (in seconds) for the credential. Unset and 0 will use system default",
				},
			},
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ReadOperation: &framework.PathOperation{
					Callback: b.pathRolesRead,
				},
				logical.CreateOperation: &framework.PathOperation{
					Callback: b.pathRolesWrite,
				},
				logical.UpdateOperation: &framework.PathOperation{
					Callback: b.pathRolesWrite,
				},
				logical.DeleteOperation: &framework.PathOperation{
					Callback: b.pathRolesDelete,
				},
			},
			HelpSynopsis:    pathRoleHelpSynopsis,
			HelpDescription: pathRoleHelpDescription,
		},
		{
			Pattern: "role/?$",
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ListOperation: &framework.PathOperation{
					Callback: b.pathRolesList,
				},
			},
			HelpSynopsis:    pathRoleListHelpSynopsis,
			HelpDescription: pathRoleListHelpDescription,
		},
	}
}

// get a role from Vault storage
func (b *hashiCupsBackend) getRole(ctx context.Context, s logical.Storage, name string) (*hashiCupsRoleEntry, error) {
	// validate
	if name == "" {
		return nil, errors.New("missing role name. name cannot be blank")
	}

	// try to get the role from storage
	entry, err := s.Get(ctx, "role/"+name)
	if err != nil {
		return nil, err
	}

	// handle none/not found
	if entry == nil {
		return nil, nil
	}

	var role hashiCupsRoleEntry

	// decode entry from JSON into struct
	if err := entry.DecodeJSON(&role); err != nil {
		return nil, err
	}

	// profit
	return &role, nil
}

// handle the role read request
func (b *hashiCupsBackend) pathRolesRead(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	entry, err := b.getRole(ctx, req.Storage, d.Get("name").(string))
	if err != nil {
		return nil, err
	}

	if entry == nil {
		return nil, nil
	}

	return &logical.Response{
		Data: entry.toResponseData(),
	}, nil
}

// store the role in Vault storage
func setRole(ctx context.Context, s logical.Storage, name string, roleEntry *hashiCupsRoleEntry) error {
	entry, err := logical.StorageEntryJSON("role/"+name, roleEntry)
	if err != nil {
		return err
	}

	if entry == nil {
		return nil
	}

	if err := s.Put(ctx, entry); err != nil {
		return err
	}

	return nil
}

// handle the write request for this role
func (b *hashiCupsBackend) pathRolesWrite(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	name, ok := d.GetOk("name")
	// validate
	if !ok {
		return logical.ErrorResponse("name cannot be blank"), nil
	}

	// try to get the role from vault storage
	roleEntry, err := b.getRole(ctx, req.Storage, name.(string))
	if err != nil {
		return nil, err
	}

	if roleEntry == nil {
		roleEntry = &hashiCupsRoleEntry{}
	}

	isCreateOperation := (req.Operation == logical.CreateOperation)

	if username, ok := d.GetOk("username"); ok {
		roleEntry.Username = username.(string)
	} else if !ok && isCreateOperation {
		return nil, errors.New("missing username in role")
	}

	if ttlRaw, ok := d.GetOk("ttl"); ok {
		roleEntry.TTL = time.Duration(ttlRaw.(int)) * time.Second
	} else if isCreateOperation {
		// in this case, missing means use default value
		roleEntry.TTL = time.Duration(d.Get("ttl").(int)) * time.Second
	}

	if maxTtlRaw, ok := d.GetOk("max_ttl"); ok {
		roleEntry.MaxTTL = time.Duration(maxTtlRaw.(int)) * time.Second
	} else if isCreateOperation {
		roleEntry.MaxTTL = time.Duration(d.Get("max_ttl").(int)) * time.Second
	}

	// make sure the ttl is not longer than the max_ttl
	if roleEntry.MaxTTL != 0 && roleEntry.TTL > roleEntry.MaxTTL {
		return logical.ErrorResponse("ttl cannot be longer than max_ttl"), nil
	}

	if err := setRole(ctx, req.Storage, name.(string), roleEntry); err != nil {
		return nil, err
	}

	return nil, nil
}

// handle the delete request for this role
func (b *hashiCupsBackend) pathRolesDelete(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	err := req.Storage.Delete(ctx, "role/"+d.Get("name").(string))
	if err != nil {
		return nil, fmt.Errorf("error deleteing hashicups role: %w", err)
	}

	return nil, nil
}

func (b *hashiCupsBackend) pathRolesList(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	entries, err := req.Storage.List(ctx, "role/")
	if err != nil {
		return nil, err
	}

	return logical.ListResponse(entries), nil
}

const (
	pathRoleHelpSynopsis    = `Manages the Vault role for generating HashiCups tokens.`
	pathRoleHelpDescription = `
This path allows you to read and write roles used to generate HashiCups tokens.
You can configure a role to manage a user's token by setting the username field.
`

	pathRoleListHelpSynopsis    = `List the existing roles in HashiCups backend`
	pathRoleListHelpDescription = `Roles will be listed by the role name.`
)
