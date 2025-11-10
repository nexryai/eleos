"use server";

import type { LocalizedString, NvdCveResponse } from "@/types";

const NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0";
const USER_AGENT = "MyApp/1.0 (https://myapp.example.com)";
const NVD_API_KEY = process.env.NVD_API_KEY ?? null

const getEnglishDescription = (descriptions: LocalizedString[]): string => {
    const found = descriptions.find(desc => desc.lang === "en");
    return found ? found.value : descriptions[0]?.value ?? "No description available.";
}

export async function fetchVulnerability(cve: string): Promise<{ details: NvdCveResponse, summary: string }> {
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
    };
}
