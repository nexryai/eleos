package nvd

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

const (
	baseURL        = "https://services.nvd.nist.gov/rest/json/cves/2.0"
	resultsPerPage = 100
)

// FetchVulnerabilities は指定された期間のNVDデータを取得します
func FetchVulnerabilities(lastModStartDate, lastModEndDate time.Time) (*[]VulnerabilityItem, error) {
	return fetchVulnerabilitiesRecursive(lastModStartDate, lastModEndDate, 0)
}

func fetchVulnerabilitiesRecursive(lastModStartDate, lastModEndDate time.Time, startIndex int) (*[]VulnerabilityItem, error) {
	url := fmt.Sprintf("%s?lastModStartDate=%s&lastModEndDate=%s&resultsPerPage=%d&startIndex=%d",
		baseURL,
		lastModStartDate.Format(time.RFC3339),
		lastModEndDate.Format(time.RFC3339),
		resultsPerPage,
		startIndex,
	)

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
			lastModStartDate,
			lastModEndDate,
			startIndex+resultsPerPage,
		)
		if err != nil {
			return nil, err
		}
		vulnerabilities = append(vulnerabilities, *nextVulnerabilities...)
	}

	return &vulnerabilities, nil
}
