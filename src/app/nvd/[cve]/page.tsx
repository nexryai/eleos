export default async ({ params }: { params: Promise<{ cve: string }> }) => {
    const cveId = (await params).cve;

    return (
        <>
            <h1 className="text-2xl">{cveId}</h1>
            <p>test</p>
        </>
    );
};
