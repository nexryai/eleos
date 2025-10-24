package worker

import (
	"fmt"
)

func ExecuteJob() error {
	vulnerabilities, err := fetchNewVulnerabilities()
	if err != nil {
		return fmt.Errorf("error executing job: %w", err)
	}

	if vulnerabilities == nil {
		// No vulnerabilities found, nothing to process
		return nil
	}

	_, err = processVulnerabilities(vulnerabilities)
	if err != nil {
		return fmt.Errorf("error processing vulnerabilities: %w", err)
	}

	return nil
}