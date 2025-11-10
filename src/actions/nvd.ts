"use server";

import type { LocalizedString, Metrics, NvdCveResponse } from "@/types";

const NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0";
const USER_AGENT = "MyApp/1.0 (https://myapp.example.com)";
const NVD_API_KEY = process.env.NVD_API_KEY ?? null

type LatestCVSS = { score: number; version: string };

const getEnglishDescription = (descriptions: LocalizedString[]): string => {
    const found = descriptions.find(desc => desc.lang === "en");
    return found ? found.value : descriptions[0]?.value ?? "No description available.";
}

const getLatestCvssScore = (metrics: Metrics): LatestCVSS | null => {
    if (metrics.cvssMetricV40 && metrics.cvssMetricV40.length > 0) {
        return {
            score: metrics.cvssMetricV40[0].cvssData.baseScore,
            version: "4.0",
        };
    } else if (metrics.cvssMetricV31 && metrics.cvssMetricV31.length > 0) {
        return {
            score: metrics.cvssMetricV31[0].cvssData.baseScore,
            version: "3.1",
        };
    } else if (metrics.cvssMetricV2 && metrics.cvssMetricV2.length > 0) {
        return {
            score: metrics.cvssMetricV2[0].cvssData.baseScore,
            version: "2.0",
        };
    }

    return null;
};

export async function fetchVulnerability(cve: string): Promise<{ details: NvdCveResponse, summary: string, cvss?: LatestCVSS }> {
    const response = await fetch(`${NVD_API_URL}?cveId=${cve}`, {
        headers: {
            "User-Agent": USER_AGENT,
            ...(NVD_API_KEY ? { "apiKey": NVD_API_KEY } : {}),
        },
    });

    if (!response.ok) {
        throw new Error(`Failed to fetch CVE data: ${response.statusText}`);
    }

    const data: NvdCveResponse = await response.json();

    return {
        details: data,
        summary: getEnglishDescription(data.vulnerabilities[0].cve.descriptions),
        cvss: getLatestCvssScore(data.vulnerabilities[0].cve.metrics) ?? undefined,
    };
}
