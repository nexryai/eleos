import { test } from "@/actions/cve";

export default async ({ params }: { params: Promise<{ cve: string }> }) => {
    const cveId = (await params).cve;

    const testString = test();

    return (
        <>
            <h1 className="text-2xl">{cveId}</h1>
            <p>test {testString}</p>
        </>
    );
};
