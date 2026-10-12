import { realFetch } from '@realtls/js';
import * as cheerio from 'cheerio';

const USER_AGENT = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/139.0.0.0 Safari/537.36';
const HOME_URL = 'https://blog.banyunxiaoxi.icu/';

export async function onRequest(context) {
    try {
        // ===== 第一步：请求首页 =====
        const homeRes = await realFetch(HOME_URL, {
            headers: { 'User-Agent': USER_AGENT },
        });

        if (!homeRes.ok) {
            const home = await homeRes.text()
            return new Response(`Request Home Status Fail: ${homeRes.status} content: ${home}`, {
                status: 400,
                headers: { 'Content-Type': 'text/plain; charset=UTF-8' },
            });
        }

        const homeHtml = await homeRes.text();
        const $home = cheerio.load(homeHtml);

        const thumb = $home('div.article-panel').first().find('.a-thumb a');
        const href = thumb.attr('href');

        if (!href) {
            return new Response('Not home content Fail', {
                status: 405,
                headers: { 'Content-Type': 'text/plain; charset=UTF-8' },
            });
        }

        // ===== 第二步：请求子页面 =====
        const pageRes = await realFetch(href, {
            headers: { 'User-Agent': USER_AGENT },
        });

        if (!pageRes.ok) {
            const sub = await pageRes.text()
            return new Response(`Request Sub Status Fail: ${pageRes.status} content: ${sub}`, {
                status: 400,
                headers: { 'Content-Type': 'text/plain; charset=UTF-8' },
            });
        }

        const pageHtml = await pageRes.text();
        const $page = cheerio.load(pageHtml);

        // ===== 第三步：解密 Cloudflare 邮箱保护并提取 code 内容 =====
        const codeEls = $page('code');

        codeEls.find('.__cf_email__').each((i, el) => {
            const dataCfemail = $page(el).attr('data-cfemail');
            if (!dataCfemail) return;

            try {
                const bytes = Buffer.from(dataCfemail, 'hex');
                if (bytes.length === 0) return;

                const key = bytes[0];
                let email = '';
                for (let n = 1; n < bytes.length; n++) {
                    email += String.fromCharCode(bytes[n] ^ key);
                }
                $page(el).text(email);
            } catch {
                // 静默跳过解码失败
            }
        });

        const ips = codeEls.text();

        if (!ips || ips.trim() === '') {
            return new Response('Not Sub Node', {
                status: 200,
                headers: { 'Content-Type': 'application/json; charset=UTF-8' },
            });
        }

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