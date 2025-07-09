package main

import (
	"context"
	"log"
	"os"

	"github.com/jackc/pgx/v5"
	"github.com/joho/godotenv"
)

func main() {
	_ = godotenv.Load()
	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		log.Fatal("DATABASE_URL environment variable not set.")
	}

	conn, err := pgx.Connect(context.Background(), dsn)
	if err != nil {
		log.Fatalf("Failed to connect to database: %v\n", err)
	}
	defer conn.Close(context.Background())

	log.Println("Connected to database.")

	_, err = conn.Exec(context.Background(), "CREATE EXTENSION IF NOT EXISTS vector;")
	if err != nil {
		log.Fatalf("Failed to create pgvector extension: %v\n", err)
	}
	log.Println("pgvector extension created successfully")

	_, err = conn.Exec(context.Background(), `
CREATE TABLE IF NOT EXISTS users (
	id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
	email TEXT NOT NULL UNIQUE,
	password_hash TEXT NOT NULL,
	created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
	`)
	if err != nil {
		log.Fatalf("Failed to create users table: %v\n", err)
	}
	log.Println("Users table is ready.")

	// 	_, err = conn.Exec(context.Background(), `
	// DROP TABLE IF EXISTS capabilities;
	// CREATE TABLE IF NOT EXISTS capabilities (
	// 	fqn TEXT PRIMARY KEY,
	// 	service_name TEXT NOT NULL,
	// 	tool_name TEXT NOT NULL,
	// 	description TEXT,
	// 	target_url TEXT NOT NULL,
	// 	input_schema JSONB,
	// 	embedding VECTOR(1536)
	// );
	// 	`)
	// 	if err != nil {
	// 		log.Fatalf("Failed to create capabilities table: %v\n", err)
	// 	}
	// 	log.Println("Capabilities table is ready.")

	_, err = conn.Exec(context.Background(), `
DROP TABLE IF EXISTS connected_services CASCADE;
CREATE TABLE connected_services (
	id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
	user_id UUID NOT NULL,
	service_name TEXT NOT NULL,
	credentials_encrypted BYTEA NOT NULL,
	created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
	UNIQUE(user_id, service_name)
);
	`)
	if err != nil {
		log.Fatalf("Failed to create connected_services table: %v\n", err)
	}
	log.Println("Connected services table is ready.")

	_, err = conn.Exec(context.Background(), `
DROP TABLE IF EXISTS oauth_sessions CASCADE;
CREATE TABLE oauth_sessions (
	state TEXT PRIMARY KEY,
	code_verifier TEXT NOT NULL,
	user_id UUID NOT NULL,
	service_name TEXT NOT NULL,
	created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
	`)
	if err != nil {
		log.Fatalf("Failed to create oauth_sessions table: %v\n", err)
	}
	log.Println("OAuth sessions table is ready.")

	_, err = conn.Exec(context.Background(), `
DROP TABLE IF EXISTS user_service_configs CASCADE;
CREATE TABLE user_service_configs (
	id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
	user_id UUID NOT NULL,
	service_slug TEXT NOT NULL,
    display_name TEXT NOT NULL,
	transport_type TEXT NOT NULL CHECK (transport_type IN ('streamable-http', 'sse')),
	mcp_server_url TEXT,
	auth_type TEXT NOT NULL CHECK (
        auth_type IN (
            'pat',
            'oauth2.1',
            'mcp_remote_managed',
            'api_key_in_header',
            'api_key_in_url',
            'no_auth'
        )
    ),
	auth_config_encrypted BYTEA NOT NULL,
	scopes JSONB,
	audience TEXT,
	created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
	updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
	UNIQUE(user_id, service_slug),
	FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);
	`)
	if err != nil {
		log.Fatalf("Failed to create user_service_configs table: %v\n", err)
	}
	log.Println("User service configs table is ready.")

	_, err = conn.Exec(context.Background(), `
DROP TABLE IF EXISTS user_llm_configs CASCADE;
CREATE TABLE user_llm_configs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    provider_type VARCHAR(50) NOT NULL,
    api_key_encrypted BYTEA NOT NULL,
    base_url TEXT,
    model VARCHAR(100),
    is_default BOOLEAN DEFAULT false,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(user_id, provider_type)
);
        `)
	if err != nil {
		log.Fatalf("Failed to create user_llm_configs table: %v\n", err)
	}
	log.Println("User LLM configs table is ready.")

	log.Println("Migration completed successfully.")
}
