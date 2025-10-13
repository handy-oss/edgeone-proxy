/**
 * This is the final, correct version of the proxy function.
 * It leverages a professional third-party proxy to handle anti-bot measures.
 */
export async function onRequest(context) {
    const { request } = context;

    try {
        const requestUrl = new URL(request.url);
        const reg = requestUrl.pathname.match(/^(\/(\w*))?\/(https?:\/\/.*)$/)
        if (!reg) {
            return new Response("Query parameter 'url' does not start with 'http(s)'", { status: 400 });
        }
        const action = reg[2]
        // if (!requestUrl.pathname.startsWith("/https://") && !requestUrl.pathname.startsWith("/http://")) {
        //     return new Response("Query parameter 'url' does not start with 'http(s)'", { status: 400 });
        // }
        // const targetUrlParam = requestUrl.href.substring(requestUrl.origin.length+1);
        const targetUrlParam = reg[3];

        if (!targetUrlParam) {
            return new Response("Query parameter 'url' is missing.", { status: 400 });
        }

        // **CRITICAL FIX: Use a professional proxy service.**
        //const proxyServiceUrl = 'https://cors-anywhere.herokuapp.com/';
        const proxyServiceUrl = '';
        const actualUrlStr = proxyServiceUrl + targetUrlParam;

        // We can now use a much simpler request, as the proxy service will handle headers.
        // const h = new Headers(request.headers)
        // h.delete("Host")
        const modifiedRequest = new Request(actualUrlStr, {
            headers: {
                //'Origin': requestUrl.origin, // The proxy service requires an Origin header.
                //'X-Requested-With': 'XMLHttpRequest',
                'Accept': '*/*',
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/139.0.0.0 Safari/537.36'
            },
            method: request.method,
            body: (request.method === 'POST' || request.method === 'PUT') ? request.body : null,
            redirect: 'follow' // We can let the proxy service handle redirects.
        });

        const response = await fetch(modifiedRequest);

        // We still need to filter Set-Cookie to avoid browser security issues.
        const finalHeaders = new Headers(response.headers);
        finalHeaders.delete('Set-Cookie');
        let body = response.body
        if (action === "base64") {
            function stringToBase64(str) {
                const encoder = new TextEncoder();
                const data = encoder.encode(str);
                return btoa(String.fromCharCode(...data));
            }
            body = stringToBase64(await response.text());
            finalHeaders.delete("Content-Length")
        }

        // Since the third-party proxy handles all content, we don't need our own HTML rewriter.
        return new Response(body, {
            status: response.status,
            statusText: response.statusText,
            headers: finalHeaders
        });

    } catch (error) {
        return new Response(`Proxy Error: ${error.message}`, { status: 500 });
    }
}
