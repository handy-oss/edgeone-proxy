import * as cheerio from 'cheerio';

const USER_AGENT = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36';
const HOME_URL = 'https://proxy.mill.ip-ddns.com/https://blog.banyunxiaoxi.icu/';

// 将 Response 的 body 读为字符串
async function readBody(response) {
    return await response.text();
}

export async function onRequest(context) {
    const { request } = context;

    try {
        // 第一步：请求首页
        const homeRes = await fetch(HOME_URL, {
            headers: { 'Accept': '*/*', 'User-Agent': USER_AGENT },
            method: "GET",
            redirect: 'follow'
        });

        if (!homeRes.ok) {
            const home = await homeRes.text()
            return new Response(`Request Home Status Fail: ${homeRes.status} content: ${home}`, {
                status: 400,
                headers: { 'Content-Type': 'text/plain; charset=UTF-8' },
            });
        }

        const homeHtml = await readBody(homeRes);

        // 用 cheerio 解析首页
        const $home = cheerio.load(homeHtml);

        // 查找 div.article-panel 内第一个 .a-thumb a 的 href
        const thumb = $home('div.article-panel').first().find('.a-thumb a');
        const href = thumb.attr('href');

        if (!href) {
            return new Response('Not home content Fail', {
                status: 405,
                headers: { 'Content-Type': 'text/plain; charset=UTF-8' },
            });
        }

        // 第二步：请求子页面
        const pageRes = await fetch("https://proxy.mill.ip-ddns.com/" + href, {
            headers: { 'Accept': '*/*', 'User-Agent': USER_AGENT },
            method: "GET",
            redirect: 'follow'
        });

        if (!pageRes.ok) {
            const sub = await pageRes.text()
            return new Response(`Request Sub Status Fail: ${pageRes.status} content: ${sub}`, {
                status: 400,
                headers: { 'Content-Type': 'text/plain; charset=UTF-8' },
            });
        }

        const pageHtml = await readBody(pageRes);
        const $page = cheerio.load(pageHtml);

        // 找到所有 <code> 元素
        const codeEls = $page('code');

        // 解密 Cloudflare 邮箱保护（.__cf_email__）
        codeEls.find('.__cf_email__').each((i, el) => {
            const dataCfemail = $page(el).attr('data-cfemail');
            if (!dataCfemail) return;

            try {
                // 将 hex 字符串解码为字节数组
                const bytes = Buffer.from(dataCfemail, 'hex');
                if (bytes.length === 0) return;

                const key = bytes[0];
                let email = '';
                for (let n = 1; n < bytes.length; n++) {
                    email += String.fromCharCode(bytes[n] ^ key);
                }
                $page(el).text(email);
            } catch {
                // 解码失败则静默跳过
            }
        });

        // 提取所有 <code> 元素的文本内容
        const ips = codeEls.text();

        if (!ips || ips.trim() === '') {
            return new Response('Not Sub Node', {
                status: 200,
                headers: { 'Content-Type': 'application/json; charset=UTF-8' },
            });
        }

        // 与原 Go 代码一致：输出 "star\r\n" + base64(ips)
        const encoded = Buffer.from(ips, 'utf8').toString('base64');

        return new Response(`star\r\n${encoded}`, {
            status: 200,
            headers: { 'Content-Type': 'application/json; charset=UTF-8' },
        });
    } catch (err) {
        return new Response(`Internal Error: ${err.message}`, {
            status: 500,
            headers: { 'Content-Type': 'text/plain; charset=UTF-8' },
        });
    }
}