package nvd

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"time"
)

const (
	baseURL        = "https://services.nvd.nist.gov/rest/json/cves/2.0"
	resultsPerPage = 100
)

// FetchVulnerabilities は指定された期間のNVDデータを取得します
func FetchVulnerabilities(pubStartDate, pubEndDate time.Time) (*[]VulnerabilityItem, error) {
	return fetchVulnerabilitiesRecursive(pubStartDate, pubEndDate, 0)
}

func fetchVulnerabilitiesRecursive(pubStartDate, pubEndDate time.Time, startIndex int) (*[]VulnerabilityItem, error) {
	url := fmt.Sprintf("%s?pubStartDate=%s&pubEndDate=%s&resultsPerPage=%d&startIndex=%d",
		baseURL,
		pubStartDate.Format(time.RFC3339),
		pubEndDate.Format(time.RFC3339),
		resultsPerPage,
		startIndex,
	)

	log.Printf("Fetching NVD data from URL: %s\n", url)

	resp, err := http.Get(url)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch NVD data: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	var apiResp APIResponse
	if err := json.Unmarshal(body, &apiResp); err != nil {
		return nil, fmt.Errorf("failed to unmarshal response: %w", err)
	}

	vulnerabilities := apiResp.Vulnerabilities

	// 残りのデータがある場合は再帰的に取得
	if startIndex+resultsPerPage < apiResp.TotalResults {
		nextVulnerabilities, err := fetchVulnerabilitiesRecursive(
			pubStartDate,
			pubEndDate,
			startIndex+resultsPerPage,
		)
		
		if err != nil {
			return nil, err
		}

		vulnerabilities = append(vulnerabilities, *nextVulnerabilities...)
	}

	return &vulnerabilities, nil
}
