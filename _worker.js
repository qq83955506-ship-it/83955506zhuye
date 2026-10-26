const KEYS = ['config', 'iconList', 'lineList', 'siteList', 'countList'];

function corsHeaders(origin) {
  return {
    'Access-Control-Allow-Origin': origin || '*',
    'Access-Control-Allow-Credentials': 'true',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization',
    'Access-Control-Allow-Methods': 'GET, PUT, POST, OPTIONS',
    'Vary': 'Origin',
  };
}

function json(data, status = 200, origin = '*') {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      'Content-Type': 'application/json; charset=utf-8',
      ...corsHeaders(origin),
    },
  });
}

function randomToken() {
  const bytes = new Uint8Array(32);
  crypto.getRandomValues(bytes);
  return [...bytes].map(b => b.toString(16).padStart(2, '0')).join('');
}

async function getState(env) {
  const entries = await Promise.all(KEYS.map(async key => [key, await env.KV.get(key, 'json')]));
  const data = {};
  for (const [key, value] of entries) {
    if (value !== null) data[key] = value;
  }
  return data;
}

async function saveState(env, data) {
  for (const key of KEYS) {
    if (Object.prototype.hasOwnProperty.call(data, key)) {
      await env.KV.put(key, JSON.stringify(data[key]));
    }
  }
}

async function requireSession(request, env) {
  const auth = request.headers.get('Authorization') || '';
  const token = auth.startsWith('Bearer ') ? auth.slice(7).trim() : '';
  if (!token) return false;

  const session = await env.KV.get('session:' + token, 'json');
  if (!session || !session.exp || session.exp < Date.now()) {
    if (session) await env.KV.delete('session:' + token);
    return false;
  }
  return true;
}

async function homepage(request, env) {
  const u = new URL(request.url);
  const assetUrl = new URL('/index.html', u);
  const assetRequest = new Request(assetUrl.toString(), request);
  const r = await env.ASSETS.fetch(assetRequest);
  if (!r.ok) return r;

  let html = await r.text();
  html = html.replaceAll('https://workers.83955506.xyz', u.origin);

  return new Response(html, {
    status: r.status,
    headers: {
      'Content-Type': 'text/html; charset=UTF-8',
      'Cache-Control': 'public, max-age=300',
    },
  });
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const origin = request.headers.get('Origin') || url.origin;

    if (url.pathname.startsWith('/api/')) {
      if (request.method === 'OPTIONS') {
        return new Response(null, { status: 204, headers: corsHeaders(origin) });
      }

      if (url.pathname === '/api/login' && request.method === 'POST') {
        let body;
        try {
          body = await request.json();
        } catch {
          return json({ ok: false, error: '请求格式错误' }, 400, origin);
        }

        const username = String(body?.username || '').trim();
        const password = String(body?.password || '');

        if (!env.ADMIN_USER || !env.ADMIN_PASSWORD) {
          return json({ ok: false, error: '后台账号未配置' }, 500, origin);
        }

        if (username !== env.ADMIN_USER || password !== env.ADMIN_PASSWORD) {
          return json({ ok: false, error: '账号或密码错误' }, 401, origin);
        }

        const token = randomToken();
        const expiresAt = Date.now() + 7 * 24 * 60 * 60 * 1000;

        await env.KV.put(
          'session:' + token,
          JSON.stringify({ username, exp: expiresAt }),
          { expirationTtl: 7 * 24 * 60 * 60 }
        );

        return json({ ok: true, token, expiresAt }, 200, origin);
      }

      if (url.pathname === '/api/state' && request.method === 'GET') {
        return json({ ok: true, data: await getState(env) }, 200, origin);
      }

      if (url.pathname === '/api/state' && request.method === 'PUT') {
        if (!(await requireSession(request, env))) {
          return json({ ok: false, error: '未登录或登录已过期' }, 401, origin);
        }

        let data;
        try {
          data = await request.json();
        } catch {
          return json({ ok: false, error: '数据格式错误' }, 400, origin);
        }

        if (!data || typeof data !== 'object') {
          return json({ ok: false, error: '数据格式错误' }, 400, origin);
        }

        await saveState(env, data);
        return json({ ok: true }, 200, origin);
      }

      if (url.pathname === '/api/logout' && request.method === 'POST') {
        const auth = request.headers.get('Authorization') || '';
        const token = auth.startsWith('Bearer ') ? auth.slice(7).trim() : '';
        if (token) await env.KV.delete('session:' + token);
        return json({ ok: true }, 200, origin);
      }

      return json({ ok: false, error: 'Not Found' }, 404, origin);
    }

    if (url.pathname === '/' || url.pathname === '/index.html') {
      return homepage(request, env);
    }

    return env.ASSETS.fetch(request);
  },
};