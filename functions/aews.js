/**
 * This is the final, correct version of the proxy function.
 * It leverages a professional third-party proxy to handle anti-bot measures.
 */
export async function onRequest(context) {
    const { request } = context;

    try {
        const branchUrl = "https://github.com/aews/jd/tree-commit-info/main"
        const branchRequest = new Request(branchUrl, {
            headers: {
                // 'Origin': requestUrl.origin, // The proxy service requires an Origin header.
                'X-Requested-With': 'XMLHttpRequest',
                'Accept': 'application/json',
                'Content-Type': 'application/json',
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/139.0.0.0 Safari/537.36'
            },
            method: "GET",
            body: null,
            redirect: 'follow' // We can let the proxy service handle redirects.
        });
        const jsons = await fetch(branchRequest);
        if (jsons.status === 200) {
            return new Response("Query branch error " + jsons.statusText, { status: 400 });
        }
        const branchInfo = await jsons.json()
        let subname = ""
        for (let i in branchInfo) {
            if (i.endsWith(".txt")) {
                subname = i
                break
            }
        }
        if (!subname) {
            return new Response("Subscribe addr not exist", { status: 400 });
        }

        const requestUrl = new URL(request.url);
        const targetUrlParam = requestUrl.searchParams.get('url');

        if (!targetUrlParam) {
            return new Response("Query parameter 'url' is missing.", { status: 400 });
        }

        const actualUrlStr = "https://cdn.jsdelivr.net/gh/aews/jd@main/" + subname;

        // We can now use a much simpler request, as the proxy service will handle headers.
        const modifiedRequest = new Request(actualUrlStr, {
            headers: {
                //'Origin': requestUrl.origin, // The proxy service requires an Origin header.
                //'X-Requested-With': 'XMLHttpRequest',
                'Accept': '*/*',
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/139.0.0.0 Safari/537.36'
            },
            method: "GET",
            body: null,
            redirect: 'follow' // We can let the proxy service handle redirects.
        });

        const response = await fetch(modifiedRequest);

        // We still need to filter Set-Cookie to avoid browser security issues.
        const finalHeaders = new Headers(response.headers);
        finalHeaders.delete('Set-Cookie');

        // Since the third-party proxy handles all content, we don't need our own HTML rewriter.
        return new Response(response.body, {
            status: response.status,
            statusText: response.statusText,
            headers: finalHeaders
        });

    } catch (error) {
        return new Response(`Proxy Error: ${error.message}`, { status: 500 });
    }
}
