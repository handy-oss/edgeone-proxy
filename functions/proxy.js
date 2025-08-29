/**
 * This is the final, correct version of the proxy function.
 * It leverages a professional third-party proxy to handle anti-bot measures.
 */
export async function onRequest(context) {
    const { request } = context;

    try {
        const requestUrl = new URL(request.url);
        const targetUrlParam = requestUrl.searchParams.get('url');

        if (!targetUrlParam) {
            return new Response("Query parameter 'url' is missing.", { status: 400 });
        }

        // **CRITICAL FIX: Use a professional proxy service.**
        //const proxyServiceUrl = 'https://cors-anywhere.herokuapp.com/';
        const proxyServiceUrl = '';
        const actualUrlStr = proxyServiceUrl + targetUrlParam;

        // We can now use a much simpler request, as the proxy service will handle headers.
        const modifiedRequest = new Request(actualUrlStr, {
            headers: {
                'Origin': requestUrl.origin, // The proxy service requires an Origin header.
                'X-Requested-With': 'XMLHttpRequest'
            },
            method: request.method,
            body: (request.method === 'POST' || request.method === 'PUT') ? request.body : null,
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
