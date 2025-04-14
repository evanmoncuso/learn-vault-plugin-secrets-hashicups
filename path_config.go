package secretsengine

import (
	"context"
	"errors"
	"fmt"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

const (
	configStoragePath = "config"
)

// hashiCupsConfig includes the minimum configuration
// required to instantiate a new HashiCups client.
type hashiCupsConfig struct {
	Username string `json:"username"`
	Password string `json:"password"`
	URL      string `json:"url"`
}

// pathConfig extends the Vault API with a `/config`
// endpoint for the backend. You can choose whether
// or not certain attributes should be displayed,
// required, and named. For example, password
// is marked as sensitive and will not be output
// when you read the configuration.
func pathConfig(b *hashiCupsBackend) *framework.Path {
	return &framework.Path{
		Pattern: "config",
		Fields: map[string]*framework.FieldSchema{
			"username": {
				Type:        framework.TypeString,
				Description: "your username for hashicups",
				Required:    true,
				DisplayAttrs: &framework.DisplayAttributes{
					Name:      "Username",
					Sensitive: false,
				},
			},
			"password": {
				Type:        framework.TypeString,
				Description: "your password for hashicups",
				Required:    true,
				DisplayAttrs: &framework.DisplayAttributes{
					Name:      "Password",
					Sensitive: true,
				},
			},
			"url": {
				Type:        framework.TypeString,
				Description: "your host for hashicups",
				Required:    true,
				DisplayAttrs: &framework.DisplayAttributes{
					Name:      "URL",
					Sensitive: false,
				},
			},
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ReadOperation: &framework.PathOperation{
				Callback: b.pathReadConfig,
			},
			// create and update share the same handler. These could be separated if we wanted
			logical.CreateOperation: &framework.PathOperation{
				Callback: b.pathWriteConfig,
			},
			logical.UpdateOperation: &framework.PathOperation{
				Callback: b.pathWriteConfig,
			},
			logical.DeleteOperation: &framework.PathOperation{
				Callback: b.pathDeleteConfig,
			},
		},
		ExistenceCheck:  b.pathConfigExistenceCheck,
		HelpSynopsis:    pathConfigHelpSynopsis,
		HelpDescription: pathConfigHelpDescription,
	}
}

// pathConfigExistenceCheck verifies if the configuration exists.
func (b *hashiCupsBackend) pathConfigExistenceCheck(ctx context.Context, req *logical.Request, data *framework.FieldData) (bool, error) {
	out, err := req.Storage.Get(ctx, req.Path)
	if err != nil {
		return false, fmt.Errorf("existence check failed: %w", err)
	}

	return out != nil, nil
}

func (b *hashiCupsBackend) pathReadConfig(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	config, err := getConfig(ctx, req.Storage)
	if err != nil {
		return nil, err
	}

	return &logical.Response{
		Data: map[string]interface{}{
			"username": config.Username,
			"url":      config.URL,
		},
	}, nil
}

func (b *hashiCupsBackend) pathWriteConfig(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	config, err := getConfig(ctx, req.Storage)
	if err != nil {
		return nil, err
	}

	// check that this is a create operation
	// could be "create" or "update"
	createOperation := (req.Operation == logical.CreateOperation)

	// if there's not config AND it's not an update, then it's a create?
	if config == nil {
		// this means we're trying to update on a nil config, so return an error
		if !createOperation {
			return nil, errors.New("no config found during update")
		}

		// otherwise, make a blank config to "create" into
		config = new(hashiCupsConfig)
	}

	// check that all required fields are included and valid
	// populate fields in the config object as you go
	if username, ok := data.GetOk("username"); ok {
		config.Username = username.(string)
	} else if !ok && createOperation {
		return nil, errors.New("missing username in config")
	}

	if url, ok := data.GetOk("url"); ok {
		config.URL = url.(string)
	} else if !ok && createOperation {
		return nil, errors.New("missing URL in config")
	}

	if password, ok := data.GetOk("password"); ok {
		config.Password = password.(string)
	} else if !ok && createOperation {
		return nil, errors.New("missing password in config")
	}

	// attempt to store the entry as JSON
	entry, err := logical.StorageEntryJSON(configStoragePath, config)
	if err != nil {
		return nil, err
	}

	// Put is write
	if err := req.Storage.Put(ctx, entry); err != nil {
		return nil, err
	}

	b.reset()

	return nil, nil
}

func (b *hashiCupsBackend) pathDeleteConfig(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	err := req.Storage.Delete(ctx, configStoragePath)

	if err == nil {
		b.reset()
	}

	return nil, err
}

func getConfig(ctx context.Context, s logical.Storage) (*hashiCupsConfig, error) {
	entry, err := s.Get(ctx, configStoragePath)
	if err != nil {
		return nil, err
	}

	if entry == nil {
		return nil, nil
	}

	config := new(hashiCupsConfig)
	if err := entry.DecodeJSON(&config); err != nil {
		return nil, fmt.Errorf("error reading root configuration: %w", err)
	}

	// return the config, we are done
	return config, nil
}

// pathConfigHelpSynopsis summarizes the help text for the configuration
const pathConfigHelpSynopsis = `Configure the HashiCups backend.`

// pathConfigHelpDescription describes the help text for the configuration
const pathConfigHelpDescription = `
The HashiCups secret backend requires credentials for managing
JWTs issued to users working with the products API.

You must sign up with a username and password and
specify the HashiCups address for the products API
before using this secrets backend.
`
