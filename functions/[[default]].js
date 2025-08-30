/**
 * This is the final, correct version of the proxy function.
 * It leverages a professional third-party proxy to handle anti-bot measures.
 */
export async function onRequest(context) {
    const { request } = context;

    try {
        const requestUrl = new URL(request.url);
        if (!requestUrl.pathname.startsWith("/https://") && !requestUrl.pathname.startsWith("/http://")) {
            return new Response("Query parameter 'url' does not start with 'http(s)'", { status: 400 });
        }
        const targetUrlParam = requestUrl.href.substring(requestUrl.origin.length+1);

        if (!targetUrlParam) {
            return new Response("Query parameter 'url' is missing.", { status: 400 });
        }

        // **CRITICAL FIX: Use a professional proxy service.**
        //const proxyServiceUrl = 'https://cors-anywhere.herokuapp.com/';
        const proxyServiceUrl = '';
        const actualUrlStr = proxyServiceUrl + targetUrlParam;

        // We can now use a much simpler request, as the proxy service will handle headers.
        const h = {}
        request.headers.forEach((v,k)=>{
            if (k.toLowerCase() !== "host") {
                h[k] = v
            }
        })
        return new Response("headers:"+JSON.stringify(h), { status: 200 });
        const modifiedRequest = new Request(actualUrlStr, {
            headers: h,
            method: request.method,
            body: (request.method === 'POST' || request.method === 'PUT') ? request.body : null,
            redirect: 'follow' // We can let the proxy service handle redirects.
        });

        const response = await fetch(modifiedRequest);

        // We still need to filter Set-Cookie to avoid browser security issues.
        const finalHeaders = new Headers(response.headers);
        // finalHeaders.delete('Set-Cookie');

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
