// API 路由处理
export async function handleAPI(request, env, session) {
  const url = new URL(request.url);
  const path = url.pathname;
  const method = request.method;

  // 凭据 API
  if (path === '/api/credentials') {
    if (method === 'GET') return await listCredentials(env);
    if (method === 'POST') return await addCredential(request, env);
  }

  if (path.match(/^\/api\/credentials\/[\w-]+$/)) {
    const id = path.split('/').pop();
    if (method === 'GET') return await getCredential(id, env);
    if (method === 'PUT') return await updateCredential(id, request, env);
    if (method === 'DELETE') return await deleteCredential(id, env);
  }

  if (path.match(/^\/api\/credentials\/[\w-]+\/toggle$/)) {
    const id = path.split('/')[3];
    if (method === 'POST') return await toggleCredential(id, env);
  }

  // 设置 API
  if (path === '/api/settings') {
    if (method === 'GET') return await getSettings(env);
    if (method === 'PUT') return await updateSettings(request, env);
  }

  if (path === '/api/settings/password') {
    if (method === 'PUT') return await changePassword(request, env);
  }

  if (path === '/api/settings/regenerate-key') {
    if (method === 'POST') return await regenerateKey(env);
  }

  if (path === '/api/settings/regenerate-token') {
    if (method === 'POST') return await regenerateToken(env);
  }

  // 统计 API
  if (path === '/api/stats') {
    if (method === 'GET') return await getStats(env);
  }

  return jsonResponse({ error: 'Not Found' }, 404);
}

// ============ 凭据管理 ============

async function listCredentials(env) {
  const list = JSON.parse(await env.KV.get('credentials:list') || '[]');
  const credentials = [];

  for (const id of list) {
    const cred = JSON.parse(await env.KV.get(`credentials:${id}`) || 'null');
    if (cred) {
      credentials.push({
        id,
        name: cred.name,
        authMethod: cred.authMethod,
        enabled: cred.enabled,
        priority: cred.priority,
        createdAt: cred.createdAt,
        updatedAt: cred.updatedAt,
        // 不返回敏感信息
        hasRefreshToken: !!cred.refreshToken,
        hasAccessToken: !!cred.accessToken,
      });
    }
  }

  credentials.sort((a, b) => a.priority - b.priority);
  return jsonResponse({ credentials });
}

async function addCredential(request, env) {
  const body = await request.json();
  const { name, refreshToken, accessToken, expiresAt, authMethod, clientId, clientSecret, priority } = body;

  if (!name || !refreshToken || !authMethod) {
    return jsonResponse({ error: '缺少必填字段' }, 400);
  }

  if (!['social', 'idc'].includes(authMethod.toLowerCase())) {
    return jsonResponse({ error: '无效的认证方式' }, 400);
  }

  const id = crypto.randomUUID();
  const credential = {
    name,
    refreshToken,
    accessToken: accessToken || '',
    expiresAt: expiresAt || new Date().toISOString(),
    authMethod: authMethod.toLowerCase(),
    clientId: clientId || '',
    clientSecret: clientSecret || '',
    priority: priority || 0,
    enabled: true,
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString(),
  };

  await env.KV.put(`credentials:${id}`, JSON.stringify(credential));

  const list = JSON.parse(await env.KV.get('credentials:list') || '[]');
  list.push(id);
  await env.KV.put('credentials:list', JSON.stringify(list));

  return jsonResponse({ success: true, id });
}

async function getCredential(id, env) {
  const cred = JSON.parse(await env.KV.get(`credentials:${id}`) || 'null');
  if (!cred) {
    return jsonResponse({ error: '凭据不存在' }, 404);
  }

  return jsonResponse({
    id,
    ...cred,
    // 部分隐藏敏感信息
    refreshToken: maskToken(cred.refreshToken),
    accessToken: cred.accessToken ? maskToken(cred.accessToken) : '',
    clientSecret: cred.clientSecret ? maskToken(cred.clientSecret) : '',
  });
}

async function updateCredential(id, request, env) {
  const existing = JSON.parse(await env.KV.get(`credentials:${id}`) || 'null');
  if (!existing) {
    return jsonResponse({ error: '凭据不存在' }, 404);
  }

  const body = await request.json();
  const updated = {
    ...existing,
    name: body.name ?? existing.name,
    priority: body.priority ?? existing.priority,
    expiresAt: body.expiresAt ?? existing.expiresAt,
    authMethod: body.authMethod ?? existing.authMethod,
    clientId: body.clientId ?? existing.clientId,
    updatedAt: new Date().toISOString(),
  };

  // 只有明确提供新值时才更新敏感字段
  if (body.refreshToken && !body.refreshToken.includes('***')) {
    updated.refreshToken = body.refreshToken;
  }
  if (body.accessToken && !body.accessToken.includes('***')) {
    updated.accessToken = body.accessToken;
  }
  if (body.clientSecret && !body.clientSecret.includes('***')) {
    updated.clientSecret = body.clientSecret;
  }

  await env.KV.put(`credentials:${id}`, JSON.stringify(updated));
  return jsonResponse({ success: true });
}

async function deleteCredential(id, env) {
  await env.KV.delete(`credentials:${id}`);

  const list = JSON.parse(await env.KV.get('credentials:list') || '[]');
  const newList = list.filter(i => i !== id);
  await env.KV.put('credentials:list', JSON.stringify(newList));

  return jsonResponse({ success: true });
}

async function toggleCredential(id, env) {
  const cred = JSON.parse(await env.KV.get(`credentials:${id}`) || 'null');
  if (!cred) {
    return jsonResponse({ error: '凭据不存在' }, 404);
  }

  cred.enabled = !cred.enabled;
  cred.updatedAt = new Date().toISOString();
  await env.KV.put(`credentials:${id}`, JSON.stringify(cred));

  return jsonResponse({ success: true, enabled: cred.enabled });
}

// ============ 设置管理 ============

async function getSettings(env) {
  const encryptionKey = await env.KV.get('system:encryption_key');
  const shellToken = await env.KV.get('system:shell_token');

  return jsonResponse({
    encryptionKey: maskKey(encryptionKey),
    shellToken: maskToken(shellToken),
  });
}

async function updateSettings(request, env) {
  const body = await request.json();

  if (body.encryptionKey && body.encryptionKey.length === 64 && !body.encryptionKey.includes('*')) {
    await env.KV.put('system:encryption_key', body.encryptionKey);
  }

  if (body.shellToken && body.shellToken.length >= 16 && !body.shellToken.includes('*')) {
    await env.KV.put('system:shell_token', body.shellToken);
  }

  return jsonResponse({ success: true });
}

async function changePassword(request, env) {
  const body = await request.json();
  const { currentPassword, newPassword } = body;

  if (!currentPassword || !newPassword) {
    return jsonResponse({ error: '缺少必填字段' }, 400);
  }

  if (newPassword.length < 8) {
    return jsonResponse({ error: '新密码至少8位' }, 400);
  }

  const storedHash = await env.KV.get('system:admin_password');
  const { verifyPassword, hashPassword } = await import('./auth.js');

  const valid = await verifyPassword(currentPassword, storedHash);
  if (!valid) {
    return jsonResponse({ error: '当前密码错误' }, 401);
  }

  const newHash = await hashPassword(newPassword);
  await env.KV.put('system:admin_password', newHash);

  return jsonResponse({ success: true });
}

async function regenerateKey(env) {
  const bytes = crypto.getRandomValues(new Uint8Array(32));
  const newKey = Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
  await env.KV.put('system:encryption_key', newKey);
  return jsonResponse({ success: true, key: newKey });
}

async function regenerateToken(env) {
  const bytes = crypto.getRandomValues(new Uint8Array(32));
  const newToken = Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
  await env.KV.put('system:shell_token', newToken);
  return jsonResponse({ success: true, token: newToken });
}

// ============ 统计 ============

async function getStats(env) {
  const list = JSON.parse(await env.KV.get('credentials:list') || '[]');
  let enabled = 0;
  let disabled = 0;

  for (const id of list) {
    const cred = JSON.parse(await env.KV.get(`credentials:${id}`) || 'null');
    if (cred) {
      if (cred.enabled) enabled++;
      else disabled++;
    }
  }

  return jsonResponse({
    total: list.length,
    enabled,
    disabled,
  });
}

// ============ 工具函数 ============

function maskToken(token) {
  if (!token || token.length < 10) return '***';
  return token.substring(0, 6) + '***' + token.substring(token.length - 4);
}

function maskKey(key) {
  if (!key || key.length < 16) return '***';
  return key.substring(0, 8) + '***' + key.substring(key.length - 8);
}

function jsonResponse(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json' },
  });
}
