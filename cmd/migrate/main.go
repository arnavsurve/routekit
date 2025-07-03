package main

import (
	"context"
	"log"

	"github.com/jackc/pgx/v5"
)

const DSN = "postgres://routekit:routekit@localhost:5433/routekit?sslmode=disable"

func main() {
	conn, err := pgx.Connect(context.Background(), DSN)
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
CREATE TABLE IF NOT EXISTS connected_services (
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
CREATE TABLE IF NOT EXISTS oauth_sessions (
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

	log.Println("Migration completed successfully.")
}
