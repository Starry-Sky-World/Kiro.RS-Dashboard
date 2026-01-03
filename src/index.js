import { handleAuth, validateSession, hashPassword } from './auth.js';
import { handleAPI } from './api.js';
import { renderUI } from './ui.js';

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);

    // CORS 预检
    if (request.method === 'OPTIONS') {
      return new Response(null, {
        headers: corsHeaders(),
      });
    }

    try {
      // 初始化检查
      const initialized = await env.KV.get('system:initialized');
      if (!initialized && url.pathname !== '/setup' && url.pathname !== '/api/setup') {
        return Response.redirect(new URL('/setup', request.url).toString(), 302);
      }

      // 路由分发
      // 公开 API (Shell 调用)
      if (url.pathname === '/api/credentials' && request.method === 'GET') {
        const authHeader = request.headers.get('Authorization') || '';
        if (authHeader.startsWith('Bearer ')) {
          return await handleShellCredentials(request, env);
        }
      }

      if (url.pathname === '/api/health') {
        return jsonResponse({ status: 'ok', time: new Date().toISOString() });
      }

      // 初始化设置
      if (url.pathname === '/setup') {
        return renderUI('setup', { initialized: !!initialized });
      }

      if (url.pathname === '/api/setup' && request.method === 'POST') {
        return await handleSetup(request, env);
      }

      // 登录
      if (url.pathname === '/login') {
        return renderUI('login', {});
      }

      if (url.pathname === '/api/login' && request.method === 'POST') {
        return await handleAuth(request, env);
      }

      if (url.pathname === '/api/logout' && request.method === 'POST') {
        return await handleLogout(request, env);
      }

      // 需要登录的页面
      const session = await validateSession(request, env);
      if (!session) {
        if (url.pathname.startsWith('/api/')) {
          return jsonResponse({ error: 'Unauthorized' }, 401);
        }
        return Response.redirect(new URL('/login', request.url).toString(), 302);
      }

      // 管理页面
      if (url.pathname === '/' || url.pathname === '/dashboard') {
        return renderUI('dashboard', { session });
      }

      if (url.pathname === '/credentials') {
        return renderUI('credentials', { session });
      }

      if (url.pathname === '/settings') {
        return renderUI('settings', { session });
      }

      // 管理 API
      if (url.pathname.startsWith('/api/')) {
        return await handleAPI(request, env, session);
      }

      return new Response('Not Found', { status: 404 });
    } catch (error) {
      console.error('Error:', error);
      return jsonResponse({ error: error.message }, 500);
    }
  },
};

// 初始化设置
async function handleSetup(request, env) {
  const initialized = await env.KV.get('system:initialized');
  if (initialized) {
    return jsonResponse({ error: 'Already initialized' }, 400);
  }

  const body = await request.json();
  const { adminPassword, encryptionKey, shellToken } = body;

  if (!adminPassword || adminPassword.length < 8) {
    return jsonResponse({ error: '管理密码至少8位' }, 400);
  }

  if (!encryptionKey || encryptionKey.length !== 64) {
    return jsonResponse({ error: '加密密钥必须是64位十六进制' }, 400);
  }

  if (!shellToken || shellToken.length < 16) {
    return jsonResponse({ error: 'Shell Token 至少16位' }, 400);
  }

  // 保存配置
  const passwordHash = await hashPassword(adminPassword);
  await env.KV.put('system:admin_password', passwordHash);
  await env.KV.put('system:encryption_key', encryptionKey);
  await env.KV.put('system:shell_token', shellToken);
  await env.KV.put('system:initialized', 'true');
  await env.KV.put('credentials:list', JSON.stringify([]));

  return jsonResponse({ success: true, message: '初始化成功' });
}

// Shell 获取凭据
async function handleShellCredentials(request, env) {
  const authHeader = request.headers.get('Authorization');
  if (!authHeader) {
    return jsonResponse({ error: 'Missing Authorization' }, 401);
  }

  const token = authHeader.replace('Bearer ', '');
  const shellToken = await env.KV.get('system:shell_token');

  if (token !== shellToken) {
    return jsonResponse({ error: 'Invalid token' }, 401);
  }

  // 获取加密密钥和凭据
  const encryptionKey = await env.KV.get('system:encryption_key');
  const credentialsList = JSON.parse(await env.KV.get('credentials:list') || '[]');

  // 只获取启用的凭据
  const enabledCredentials = [];
  for (const id of credentialsList) {
    const cred = JSON.parse(await env.KV.get(`credentials:${id}`) || 'null');
    if (cred && cred.enabled) {
      enabledCredentials.push({
        refreshToken: cred.refreshToken,
        accessToken: cred.accessToken || '',
        expiresAt: cred.expiresAt,
        authMethod: cred.authMethod,
        clientId: cred.clientId || '',
        clientSecret: cred.clientSecret || '',
        priority: cred.priority || 0,
      });
    }
  }

  // 按优先级排序
  enabledCredentials.sort((a, b) => a.priority - b.priority);

  // 加密凭据
  const { encrypted, iv } = await encryptAES(JSON.stringify(enabledCredentials), encryptionKey);

  return jsonResponse({
    encrypted,
    iv,
    count: enabledCredentials.length,
    version: 1,
  });
}

// 登出
async function handleLogout(request, env) {
  const cookie = request.headers.get('Cookie') || '';
  const sessionId = cookie.match(/session=([^;]+)/)?.[1];

  if (sessionId) {
    await env.KV.delete(`session:${sessionId}`);
  }

  return new Response(JSON.stringify({ success: true }), {
    headers: {
      'Content-Type': 'application/json',
      'Set-Cookie': 'session=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0',
    },
  });
}

// AES 加密
async function encryptAES(plaintext, keyHex) {
  const key = await crypto.subtle.importKey(
    'raw',
    hexToBytes(keyHex),
    { name: 'AES-CBC' },
    false,
    ['encrypt']
  );

  const iv = crypto.getRandomValues(new Uint8Array(16));
  const encoder = new TextEncoder();
  const data = encoder.encode(plaintext);

  const encrypted = await crypto.subtle.encrypt(
    { name: 'AES-CBC', iv },
    key,
    data
  );

  return {
    encrypted: btoa(String.fromCharCode(...new Uint8Array(encrypted))),
    iv: btoa(String.fromCharCode(...iv)),
  };
}

function hexToBytes(hex) {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(hex.substr(i * 2, 2), 16);
  }
  return bytes;
}

function jsonResponse(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      'Content-Type': 'application/json',
      ...corsHeaders(),
    },
  });
}

function corsHeaders() {
  return {
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization',
  };
}
