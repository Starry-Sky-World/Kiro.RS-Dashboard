// 密码哈希
export async function hashPassword(password) {
  const encoder = new TextEncoder();
  const data = encoder.encode(password + 'kiro-salt-2024');
  const hash = await crypto.subtle.digest('SHA-256', data);
  return btoa(String.fromCharCode(...new Uint8Array(hash)));
}

// 验证密码
export async function verifyPassword(password, hash) {
  const inputHash = await hashPassword(password);
  return inputHash === hash;
}

// 生成会话 ID
function generateSessionId() {
  const bytes = crypto.getRandomValues(new Uint8Array(32));
  return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

// 登录处理
export async function handleAuth(request, env) {
  const body = await request.json();
  const { password } = body;

  const storedHash = await env.KV.get('system:admin_password');
  if (!storedHash) {
    return new Response(JSON.stringify({ error: 'System not initialized' }), {
      status: 400,
      headers: { 'Content-Type': 'application/json' },
    });
  }

  const valid = await verifyPassword(password, storedHash);
  if (!valid) {
    return new Response(JSON.stringify({ error: '密码错误' }), {
      status: 401,
      headers: { 'Content-Type': 'application/json' },
    });
  }

  // 创建会话
  const sessionId = generateSessionId();
  const sessionData = {
    createdAt: Date.now(),
    expiresAt: Date.now() + 24 * 60 * 60 * 1000, // 24小时
  };

  await env.KV.put(`session:${sessionId}`, JSON.stringify(sessionData), {
    expirationTtl: 86400, // 24小时后自动删除
  });

  return new Response(JSON.stringify({ success: true }), {
    headers: {
      'Content-Type': 'application/json',
      'Set-Cookie': `session=${sessionId}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=86400`,
    },
  });
}

// 验证会话
export async function validateSession(request, env) {
  const cookie = request.headers.get('Cookie') || '';
  const sessionId = cookie.match(/session=([^;]+)/)?.[1];

  if (!sessionId) {
    return null;
  }

  const sessionData = await env.KV.get(`session:${sessionId}`);
  if (!sessionData) {
    return null;
  }

  const session = JSON.parse(sessionData);
  if (Date.now() > session.expiresAt) {
    await env.KV.delete(`session:${sessionId}`);
    return null;
  }

  return { id: sessionId, ...session };
}
