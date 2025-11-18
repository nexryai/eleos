package worker

import (
	"context"
	"fmt"
	"log"
	"os"

	"github.com/nexryai/eleos/internal/db"
)

var (
	dbConnectString = os.Getenv("ELEOS_DB_CONNECT_STRING")
)

func getEnv(key, fallback string) string {
    if value, ok := os.LookupEnv(key); ok {
        return value
    }
    return fallback
}

func ExecuteJob() error {
	log.Print("Fetching vulnerabilities...")
	nvdVulnerabilities, err := fetchNewVulnerabilities()
	if err != nil {
		return fmt.Errorf("error executing job: %w", err)
	}

	if nvdVulnerabilities == nil {
		// No vulnerabilities found, nothing to process
		return nil
	}

	log.Print("Parsing vulnerabilities...")
	vulnerabilities, err := processVulnerabilities(nvdVulnerabilities)
	if err != nil {
		return fmt.Errorf("error processing vulnerabilities: %w", err)
	}

	dbContext := context.Background()
	database, err := db.NewDBClient(dbContext, dbConnectString, getEnv("ELEOS_DB_NAME", "eleos-dev"))
	if err != nil {
		return fmt.Errorf("database error: %w", err)
	}

	if err := db.CreateDatabaseIndex(dbContext, database); err != nil {
        log.Fatalf("Failed to create database index: %v", err)
    }

	log.Print("Writing to DB...")
	err = db.CreateVulnerabilityBatch(dbContext, database, vulnerabilities)
	if err != nil {
		return fmt.Errorf("a database transaction failed. aborting.: %w", err)
	}

	return nil
}
