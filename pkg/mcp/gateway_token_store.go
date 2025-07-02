package mcp

import (
	"context"
	"encoding/json"

	"github.com/arnavsurve/routekit/pkg/crypto"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/mark3labs/mcp-go/client/transport"
)

// GatewayTokenStore implements the transport.TokenStore interface
// using the Routekit database as the backend.
type GatewayTokenStore struct {
	db          *pgxpool.Pool
	userID      string
	serviceName string
}

func NewGatewayTokenStore(db *pgxpool.Pool, userID string, serviceName string) *GatewayTokenStore {
	return &GatewayTokenStore{
		db:          db,
		userID:      userID,
		serviceName: serviceName,
	}
}

func (s *GatewayTokenStore) GetToken() (*transport.Token, error) {
	var encryptedCreds []byte
	err := s.db.QueryRow(context.Background(),
		"SELECT credentials_encrypted FROM connected_services WHERE user_id = $1 AND service_name = $2",
		s.userID, s.serviceName).Scan(&encryptedCreds)
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, transport.ErrOAuthAuthorizationRequired
		}
		return nil, err
	}

	decrypted, err := crypto.Decrypt(encryptedCreds)
	if err != nil {
		return nil, err
	}

	var token transport.Token
	if err := json.Unmarshal(decrypted, &token); err != nil {
		return nil, err
	}
	return &token, nil
}

func (s *GatewayTokenStore) SaveToken(token *transport.Token) error {
	tokenBytes, err := json.Marshal(token)
	if err != nil {
		return err
	}

	encrypted, err := crypto.Encrypt(tokenBytes)
	if err != nil {
		return err
	}

	_, err = s.db.Exec(context.Background(), `
        INSERT INTO connected_services (user_id, service_name, credentials_encrypted)
        VALUES ($1, $2, $3)
        ON CONFLICT (user_id, service_name) DO UPDATE SET
        credentials_encrypted = EXCLUDED.credentials_encrypted;
    `, s.userID, s.serviceName, encrypted)
	return err
}