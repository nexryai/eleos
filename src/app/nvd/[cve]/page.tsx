import { fetchVulnerability } from "@/actions/nvd";

export default async ({ params }: { params: Promise<{ cve: string }> }) => {
    const cveId = (await params).cve;

    const data = await fetchVulnerability(cveId);

    return (
        <>
            <h1 className="text-2xl">{cveId}</h1>
            <p className="mt-8">{data.summary}</p>
        </>
    );
};
