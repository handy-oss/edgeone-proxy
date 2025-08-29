/**
 * This is the final, correct version of the proxy function.
 * It leverages a professional third-party proxy to handle anti-bot measures.
 */
export async function onRequest(context) {
    const html = `<!DOCTYPE html>
<html lang="zh-CN">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>代理万物 - 现代化代理服务</title>
  <script src="https://cdn.tailwindcss.com"></script>
  <link rel="icon" type="image/png" href="https://s2.hdslb.com/bfs/openplatform/1682b11880f5c53171217a03c8adc9f2e2a27fcf.png@100w.webp">
  <meta name="Description" content="一个基于 EdgeOne Pages 的现代化、快速、可靠的代理服务。">
  <style>
    body {
      -webkit-font-smoothing: antialiased;
      -moz-osx-font-smoothing: grayscale;
    }
    .gradient-bg {
      background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
    }
    .dark .gradient-bg {
      background: linear-gradient(135deg, #1e293b 0%, #334155 100%);
    }
    .card-bg {
      background-color: rgba(255, 255, 255, 0.1);
      backdrop-filter: blur(10px);
      -webkit-backdrop-filter: blur(10px);
      border: 1px solid rgba(255, 255, 255, 0.2);
    }
    .dark .card-bg {
      background-color: rgba(30, 41, 59, 0.5);
      border: 1px solid rgba(255, 255, 255, 0.1);
    }
  </style>
</head>
<body>
  <div class="relative min-h-screen w-full flex items-center justify-center p-4 gradient-bg">
    <div class="w-full max-w-lg">
      <div class="rounded-xl shadow-2xl card-bg">
        <div class="p-8">
          <div class="text-center mb-6">
            <h1 class="text-3xl font-bold text-white">代理万物</h1>
            <p class="text-gray-200 mt-2">一个现代、快速、可靠的代理服务。</p>
          </div>
          <form id="urlForm" onsubmit="redirectToProxy(event)">
            <div class="relative">
              <input type="text" id="targetUrl" required
                class="w-full px-4 py-3 text-lg text-white bg-white/10 rounded-lg border border-transparent focus:border-white/50 focus:ring-0 focus:outline-none transition duration-300"
                placeholder="请输入目标网址...">
            </div>
            <button type="submit"
              class="w-full mt-4 px-4 py-3 text-lg font-semibold text-white bg-indigo-600 rounded-lg hover:bg-indigo-700 focus:outline-none focus:ring-2 focus:ring-indigo-500 focus:ring-opacity-50 transition duration-300">
              开始代理
            </button>
          </form>
        </div>
      </div>
      <footer class="text-center mt-6">
        <p class="text-sm text-white/70">由 EdgeOne Pages 强力驱动。在 GitHub 上 Fork 我。</p>
      </footer>
    </div>
  </div>
  <script>
    function redirectToProxy(event) {
      event.preventDefault();
      const targetUrl = document.getElementById('targetUrl').value.trim();
      if (targetUrl) {
        const proxyUrl = window.location.origin + '/proxy?url=' + encodeURIComponent(targetUrl);
        window.open(proxyUrl, '_blank');
      }
    }
    if (window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches) {
      document.documentElement.classList.add('dark');
    }
  </script>
</body>
</html>`

    const finalHeaders = new Headers({
        'Content-Type': 'text/html'
    });
    return new Response(html, { status: 200 ,headers: finalHeaders});
}
