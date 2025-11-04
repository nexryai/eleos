package worker

import (
	"context"
	"fmt"
	"os"

	"github.com/nexryai/eleos/internal/db"
)

var (
	dbConnectString = os.Getenv("DB_CONNECT_STRING")
)

func ExecuteJob() error {
	nvdVulnerabilities, err := fetchNewVulnerabilities()
	if err != nil {
		return fmt.Errorf("error executing job: %w", err)
	}

	if nvdVulnerabilities == nil {
		// No vulnerabilities found, nothing to process
		return nil
	}

	vulnerabilities, err := processVulnerabilities(nvdVulnerabilities)
	if err != nil {
		return fmt.Errorf("error processing vulnerabilities: %w", err)
	}

	dbContext := context.Background()
	database, err := db.NewDBConn(dbContext, dbConnectString)

	db.CreateVulnerabilityBatch(dbContext, database, vulnerabilities)
	if err != nil {
		return fmt.Errorf("error connecting to database: %w", err)
	}

	return nil
}