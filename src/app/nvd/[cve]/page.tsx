import { IconShieldExclamation } from "@tabler/icons-react";

import { fetchVulnerability } from "@/actions/nvd";

export default async function ({ params }: { params: Promise<{ cve: string }> }) {
    const cveId = (await params).cve;

    const data = await fetchVulnerability(cveId);

    return (
        <div className="max-w-5xl">
            <div className="flex justify-between">
                <h1 className="text-2xl">{cveId}</h1>

                <div>
                    {data.cvss ? (
                        <div className="flex gap-4 flex-col justify-end relative">
                            <span>CVSS {data.cvss.version}</span>
                            <div className="absolute top-0 -left-18 -z-10">
                                <div className="w-48 h-48 bg-linear-to-br from-red-50 to-red-200 blur-3xl"></div>
                            </div>
                            <div className="flex gap-4 items-center text-3xl text-right text-red-600 rounded-full p-2">
                                <IconShieldExclamation className="ml-4" />
                                <span className="mr-4">{data.cvss.score}</span>
                            </div>
                        </div>
                    ) : (
                        <span>CVSS Score: N/A</span>
                    )}
                </div>
            </div>

            <p className="mt-8">{data.summary}</p>
        </div>
    );
}
