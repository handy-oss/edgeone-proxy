/**
 * This is the final, correct version of the proxy function.
 * It leverages a professional third-party proxy to handle anti-bot measures.
 */

//import yaml from 'https://cdn.jsdelivr.net/npm/js-yaml@4.1.0/dist/js-yaml.mjs'

// 将字符串转换为 Uint8Array 再编码
function stringToBase64(str) {
    const encoder = new TextEncoder();
    const data = encoder.encode(str);
    return btoa(String.fromCharCode(...data));
}

// 解码
function base64ToString(base64) {
    const binary = atob(base64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
        bytes[i] = binary.charCodeAt(i);
    }
    return new TextDecoder().decode(bytes);
}

class SubscriptionConverter {
    static yamlToV2ray(yamlData) {
        const config = yaml.load(yamlData);
        const proxies = config.proxies || [];

        const links = proxies.map(proxy => {
            try {
                switch (proxy.type?.toLowerCase()) {
                    case 'vmess':
                        return this.convertVmess(proxy);
                    case 'vless':
                        return this.convertVless(proxy);
                    case 'trojan':
                        return this.convertTrojan(proxy);
                    case 'ss':
                    case 'shadowsocks':
                        return this.convertShadowsocks(proxy);
                    case 'hysteria2':
                        return this.convertHysteria2(proxy);
                    case 'wireguard':
                        return this.convertWireguardToUrl(proxy);
                    case 'tuic':
                        return this.convertTuic(proxy);
                    case 'anytls':
                        return this.convertAnyTLS(proxy);
                    default:
                        console.warn(`不支持的协议类型: ${proxy.type}`);
                        return null;
                }
            } catch (e) {
                return null;
            }
        }).filter(link => link !== null);

        const subscriptionContent = links.join('\n');
        return stringToBase64(subscriptionContent);
    }

    // VMess 转换
    static convertVmess(proxy) {
        const config = {
            v: "2",
            ps: proxy.name || `${proxy.server}:${proxy.port}`,
            add: proxy.server,
            port: proxy.port.toString(),
            id: proxy.uuid,
            aid: proxy.alterId ? proxy.alterId.toString() : "0",
            scy: proxy.cipher || "auto",
            net: proxy.network || "tcp",
            type: proxy.type || "none",
            host: proxy['ws-headers']?.['Host'] || proxy.host || "",
            path: proxy['ws-path'] || proxy.path || "",
            tls: proxy.tls ? "tls" : "",
            sni: proxy.servername || proxy.sni || "",
            alpn: proxy.alpn || ""
        };

        const jsonStr = JSON.stringify(config);
        return `vmess://${btoa(unescape(encodeURIComponent(jsonStr)))}`;
    }

    // VLESS 转换
    static convertVless(proxy) {
        const params = new URLSearchParams();

        // 基础参数
        if (proxy.flow) params.set('flow', proxy.flow);
        params.set('encryption', 'none');

        // 传输层安全
        if (proxy.tls) {
            params.set('security', 'tls');
            if (proxy.servername) params.set('sni', proxy.servername);
            if (proxy.alpn) params.set('alpn', Array.isArray(proxy.alpn) ? proxy.alpn.join(',') : proxy.alpn);
        } else if (proxy.reality) {
            params.set('security', 'reality');
            if (proxy.servername) params.set('sni', proxy.servername);
            if (proxy['reality-opts']?.publicKey) params.set('pbk', proxy['reality-opts'].publicKey);
            if (proxy['reality-opts']?.shortId) params.set('sid', proxy['reality-opts'].shortId);
        } else {
            params.set('security', 'none');
        }

        // 传输协议
        if (proxy.network === 'ws') {
            params.set('type', 'ws');
            if (proxy['ws-path']) params.set('path', proxy['ws-path']);
            if (proxy['ws-headers']?.['Host']) params.set('host', proxy['ws-headers']['Host']);
        } else if (proxy.network === 'grpc') {
            params.set('type', 'grpc');
            if (proxy['grpc-opts']?.['grpc-service-name']) params.set('serviceName', proxy['grpc-opts']['grpc-service-name']);
        } else if (proxy.network === 'h2') {
            params.set('type', 'http');
            if (proxy['h2-opts']?.path) params.set('path', proxy['h2-opts'].path);
            if (proxy['h2-opts']?.host) params.set('host', Array.isArray(proxy['h2-opts'].host) ? proxy['h2-opts'].host.join(',') : proxy['h2-opts'].host);
        }

        // 其他参数
        if (proxy.fingerprint) params.set('fp', proxy.fingerprint);

        return `vless://${proxy.uuid}@${proxy.server}:${proxy.port}?${params.toString()}#${encodeURIComponent(proxy.name || proxy.server)}`;
    }

    // Trojan 转换
    static convertTrojan(proxy) {
        const params = new URLSearchParams();

        // 安全参数
        if (proxy.tls) {
            params.set('security', 'tls');
            if (proxy.servername) params.set('sni', proxy.servername);
            if (proxy.alpn) params.set('alpn', Array.isArray(proxy.alpn) ? proxy.alpn.join(',') : proxy.alpn);
        }

        // 传输协议
        if (proxy.network === 'ws') {
            params.set('type', 'ws');
            if (proxy['ws-path']) params.set('path', proxy['ws-path']);
            if (proxy['ws-headers']?.['Host']) params.set('host', proxy['ws-headers']['Host']);
        } else if (proxy.network === 'grpc') {
            params.set('type', 'grpc');
            if (proxy['grpc-opts']?.['grpc-service-name']) params.set('serviceName', proxy['grpc-opts']['grpc-service-name']);
        }

        // 其他参数
        if (proxy.flow) params.set('flow', proxy.flow);
        if (proxy.fingerprint) params.set('fp', proxy.fingerprint);

        return `trojan://${proxy.password}@${proxy.server}:${proxy.port}?${params.toString()}#${encodeURIComponent(proxy.name || proxy.server)}`;
    }

    // Shadowsocks 转换
    static convertShadowsocks(proxy) {
        const method = proxy.cipher || 'aes-256-gcm';
        const password = proxy.password;
        const encoded = stringToBase64(`${method}:${password}`);

        const params = new URLSearchParams();
        if (proxy.plugin === 'obfs') {
            params.set('plugin', `obfs-local;obfs=${proxy['plugin-opts']?.mode || 'http'}`);
            if (proxy['plugin-opts']?.host) params.set('obfs-host', proxy['plugin-opts'].host);
        } else if (proxy.plugin === 'v2ray-plugin') {
            let pluginStr = 'v2ray-plugin';
            if (proxy['plugin-opts']?.mode) pluginStr += `;mode=${proxy['plugin-opts'].mode}`;
            if (proxy['plugin-opts']?.host) pluginStr += `;host=${proxy['plugin-opts'].host}`;
            if (proxy['plugin-opts']?.path) pluginStr += `;path=${proxy['plugin-opts'].path}`;
            if (proxy['plugin-opts']?.tls) pluginStr += ';tls';
            params.set('plugin', pluginStr);
        }

        const baseUrl = `ss://${encoded}@${proxy.server}:${proxy.port}`;
        return params.toString() ? `${baseUrl}/?${params.toString()}#${encodeURIComponent(proxy.name || proxy.server)}` :
            `${baseUrl}#${encodeURIComponent(proxy.name || proxy.server)}`;
    }

    // Hysteria2 转换
    static convertHysteria2(proxy) {
        const params = new URLSearchParams();

        // 认证方式
        if (proxy.password) {
            params.set('auth', proxy.password);
        }

        // TLS 配置
        if (proxy.sni) params.set('sni', proxy.sni);
        if (proxy['skip-cert-verify'] === true) params.set('insecure', '1');
        if (proxy.alpn) params.set('alpn', Array.isArray(proxy.alpn) ? proxy.alpn.join(',') : proxy.alpn);

        // 传输优化
        if (proxy['obfs']) {
            params.set('obfs', proxy.obfs);
            if (proxy['obfs-password']) params.set('obfs-password', proxy['obfs-password']);
        }

        // 带宽和下载参数
        if (proxy.down) params.set('downmbps', proxy.down.toString());
        if (proxy.up) params.set('upmbps', proxy.up.toString());

        return `hysteria2://${proxy.server}:${proxy.port}?${params.toString()}#${encodeURIComponent(proxy.name || proxy.server)}`;
    }

    static convertWireguardToJson(proxy) {
        const config = {
            privateKey: proxy['private-key'],
            publicKey: proxy['public-key'],
            endpoint: `${proxy.server}:${proxy.port}`,
            dns: proxy.dns || '1.1.1.1',
            allowedIPs: proxy['allowed-ips'] || '0.0.0.0/0,::/0'
        };

        // 添加预共享密钥（如果有）
        if (proxy['preshared-key']) {
            config.presharedKey = proxy['preshared-key'];
        }

        // 添加 MTU（如果有）
        if (proxy.mtu) {
            config.mtu = proxy.mtu.toString();
        }

        const jsonStr = JSON.stringify(config);
        // return `wireguard://${btoa(jsonStr)}#${encodeURIComponent(proxy.name || proxy.server)}`;
        return `wireguard://${stringToBase64(jsonStr)}#${encodeURIComponent(proxy.name || proxy.server)}`;
    }
    // WireGuard 转换（修正版）
    static convertWireguardToUrl(proxy) {
        const params = new URLSearchParams();

        // 必需参数
        if (proxy['private-key']) {
            params.set('privatekey', proxy['private-key']);
        }

        if (proxy['public-key']) {
            params.set('publickey', proxy['public-key']);
        }

        // 可选参数
        if (proxy['preshared-key']) {
            params.set('presharedkey', proxy['preshared-key']);
        }

        if (proxy.mtu) {
            params.set('mtu', proxy.mtu.toString());
        }

        if (proxy.dns) {
            const dnsServers = Array.isArray(proxy.dns) ? proxy.dns.join(',') : proxy.dns;
            params.set('dns', dnsServers);
        }

        if (proxy['allowed-ips']) {
            const allowedIPs = Array.isArray(proxy['allowed-ips']) ? proxy['allowed-ips'].join(',') : proxy['allowed-ips'];
            params.set('allowedips', allowedIPs);
        }

        // 端点地址（服务器和端口）
        const endpoint = proxy.server;
        const port = proxy.port || '51820';

        // 使用私钥作为用户名（这是常见的做法）
        const privateKeyShort = proxy['private-key'] ? proxy['private-key'].substring(0, 8) : 'default';

        return `wireguard://${privateKeyShort}@${endpoint}:${port}?${params.toString()}#${encodeURIComponent(proxy.name || proxy.server)}`;
    }

    // TUIC 转换
    static convertTuic(proxy) {
        const params = new URLSearchParams();

        // 认证信息
        if (proxy.token) {
            params.set('token', proxy.token);
        } else if (proxy.password && proxy.uuid) {
            params.set('password', proxy.password);
            params.set('uuid', proxy.uuid);
        }

        // TLS 配置
        if (proxy.sni) params.set('sni', proxy.sni);
        if (proxy['skip-cert-verify'] === true) params.set('allow_insecure', '1');
        if (proxy.alpn) params.set('alpn', Array.isArray(proxy.alpn) ? proxy.alpn.join(',') : proxy.alpn);

        // 传输参数
        if (proxy['udp-relay-mode']) params.set('udp_relay_mode', proxy['udp-relay-mode']);
        if (proxy['congestion-controller']) params.set('congestion_controller', proxy['congestion-controller']);
        if (proxy.heartbeat) params.set('heartbeat_interval', proxy.heartbeat.toString());

        // 其他参数
        if (proxy.disable_sni) params.set('disable_sni', '1');

        return `tuic://${proxy.server}:${proxy.port}?${params.toString()}#${encodeURIComponent(proxy.name || proxy.server)}`;
    }

    // AnyTLS 转换（假设为自定义 TLS 协议）
    static convertAnyTLS(proxy) {
        const params = new URLSearchParams();

        // 基础连接参数
        if (proxy.username) params.set('username', proxy.username);
        if (proxy.password) params.set('password', proxy.password);

        // TLS 配置
        if (proxy.sni) params.set('sni', proxy.sni);
        if (proxy['skip-cert-verify'] === true) params.set('insecure', '1');
        if (proxy.alpn) params.set('alpn', Array.isArray(proxy.alpn) ? proxy.alpn.join(',') : proxy.alpn);

        // 自定义参数
        if (proxy.protocol) params.set('protocol', proxy.protocol);
        if (proxy.version) params.set('version', proxy.version);

        // 如果有自定义传输参数
        if (proxy['custom-opts']) {
            Object.entries(proxy['custom-opts']).forEach(([key, value]) => {
                params.set(key, value.toString());
            });
        }

        return `anytls://${proxy.server}:${proxy.port}?${params.toString()}#${encodeURIComponent(proxy.name || proxy.server)}`;
    }
}

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
            body = stringToBase64(await response.text());
            finalHeaders.delete("Content-Length")
        } else if (action === "unbase64") {
            body = base64ToString(await response.text());
            finalHeaders.delete("Content-Length")
        } else if (action === "y2v") {
            body = SubscriptionConverter.yamlToV2ray(await response.text());
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
