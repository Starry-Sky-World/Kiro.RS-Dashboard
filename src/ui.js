// Web UI 渲染
export function renderUI(page, data) {
  const html = generateHTML(page, data);
  return new Response(html, {
    headers: { 'Content-Type': 'text/html; charset=utf-8' },
  });
}

function generateHTML(page, data) {
  const styles = getStyles();
  const scripts = getScripts();

  let content = '';
  let title = 'Kiro Worker';

  switch (page) {
    case 'setup':
      title = '初始化设置 - Kiro Worker';
      content = setupPage();
      break;
    case 'login':
      title = '登录 - Kiro Worker';
      content = loginPage();
      break;
    case 'dashboard':
      title = '仪表板 - Kiro Worker';
      content = dashboardPage();
      break;
    case 'credentials':
      title = '凭据管理 - Kiro Worker';
      content = credentialsPage();
      break;
    case 'settings':
      title = '系统设置 - Kiro Worker';
      content = settingsPage();
      break;
  }

  return `<!DOCTYPE html>
<html lang="zh">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>${title}</title>
    <style>${styles}</style>
</head>
<body>
    ${content}
    <script>${scripts}</script>
</body>
</html>`;
}

function getStyles() {
  return `
    * { box-sizing: border-box; margin: 0; padding: 0; }

    :root {
      --bg-primary: #0f172a;
      --bg-secondary: #1e293b;
      --bg-tertiary: #334155;
      --text-primary: #f1f5f9;
      --text-secondary: #94a3b8;
      --accent: #3b82f6;
      --accent-hover: #2563eb;
      --success: #22c55e;
      --warning: #f59e0b;
      --danger: #ef4444;
      --border: #475569;
    }

    body {
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
      background: var(--bg-primary);
      color: var(--text-primary);
      min-height: 100vh;
    }

    /* 布局 */
    .layout {
      display: flex;
      min-height: 100vh;
    }

    .sidebar {
      width: 250px;
      background: var(--bg-secondary);
      padding: 20px;
      border-right: 1px solid var(--border);
    }

    .logo {
      font-size: 24px;
      font-weight: bold;
      color: var(--accent);
      margin-bottom: 30px;
      display: flex;
      align-items: center;
      gap: 10px;
    }

    .nav-item {
      display: flex;
      align-items: center;
      gap: 10px;
      padding: 12px 15px;
      color: var(--text-secondary);
      text-decoration: none;
      border-radius: 8px;
      margin-bottom: 5px;
      transition: all 0.2s;
    }

    .nav-item:hover, .nav-item.active {
      background: var(--bg-tertiary);
      color: var(--text-primary);
    }

    .main {
      flex: 1;
      padding: 30px;
      overflow-y: auto;
    }

    .header {
      display: flex;
      justify-content: space-between;
      align-items: center;
      margin-bottom: 30px;
    }

    .header h1 {
      font-size: 28px;
    }

    /* 卡片 */
    .card {
      background: var(--bg-secondary);
      border-radius: 12px;
      padding: 24px;
      margin-bottom: 20px;
      border: 1px solid var(--border);
    }

    .card-header {
      display: flex;
      justify-content: space-between;
      align-items: center;
      margin-bottom: 20px;
    }

    .card-title {
      font-size: 18px;
      font-weight: 600;
    }

    /* 统计卡片 */
    .stats-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
      gap: 20px;
      margin-bottom: 30px;
    }

    .stat-card {
      background: var(--bg-secondary);
      border-radius: 12px;
      padding: 20px;
      border: 1px solid var(--border);
    }

    .stat-value {
      font-size: 36px;
      font-weight: bold;
      color: var(--accent);
    }

    .stat-label {
      color: var(--text-secondary);
      margin-top: 5px;
    }

    /* 表格 */
    .table {
      width: 100%;
      border-collapse: collapse;
    }

    .table th, .table td {
      padding: 12px 15px;
      text-align: left;
      border-bottom: 1px solid var(--border);
    }

    .table th {
      color: var(--text-secondary);
      font-weight: 500;
      font-size: 14px;
    }

    .table tr:hover {
      background: var(--bg-tertiary);
    }

    /* 表单 */
    .form-group {
      margin-bottom: 20px;
    }

    .form-label {
      display: block;
      margin-bottom: 8px;
      color: var(--text-secondary);
      font-size: 14px;
    }

    .form-input {
      width: 100%;
      padding: 12px 15px;
      background: var(--bg-tertiary);
      border: 1px solid var(--border);
      border-radius: 8px;
      color: var(--text-primary);
      font-size: 14px;
      font-family: monospace;
    }

    .form-input:focus {
      outline: none;
      border-color: var(--accent);
    }

    .form-input::placeholder {
      color: var(--text-secondary);
    }

    textarea.form-input {
      min-height: 100px;
      resize: vertical;
    }

    .form-hint {
      font-size: 12px;
      color: var(--text-secondary);
      margin-top: 5px;
    }

    /* 按钮 */
    .btn {
      padding: 10px 20px;
      border: none;
      border-radius: 8px;
      cursor: pointer;
      font-size: 14px;
      font-weight: 500;
      transition: all 0.2s;
      display: inline-flex;
      align-items: center;
      gap: 8px;
    }

    .btn-primary {
      background: var(--accent);
      color: white;
    }

    .btn-primary:hover {
      background: var(--accent-hover);
    }

    .btn-success {
      background: var(--success);
      color: white;
    }

    .btn-danger {
      background: var(--danger);
      color: white;
    }

    .btn-secondary {
      background: var(--bg-tertiary);
      color: var(--text-primary);
    }

    .btn-sm {
      padding: 6px 12px;
      font-size: 12px;
    }

    /* 徽章 */
    .badge {
      padding: 4px 10px;
      border-radius: 20px;
      font-size: 12px;
      font-weight: 500;
    }

    .badge-success {
      background: rgba(34, 197, 94, 0.2);
      color: var(--success);
    }

    .badge-warning {
      background: rgba(245, 158, 11, 0.2);
      color: var(--warning);
    }

    .badge-danger {
      background: rgba(239, 68, 68, 0.2);
      color: var(--danger);
    }

    /* 开关 */
    .toggle {
      position: relative;
      width: 44px;
      height: 24px;
    }

    .toggle input {
      opacity: 0;
      width: 0;
      height: 0;
    }

    .toggle-slider {
      position: absolute;
      cursor: pointer;
      top: 0;
      left: 0;
      right: 0;
      bottom: 0;
      background: var(--bg-tertiary);
      border-radius: 24px;
      transition: 0.3s;
    }

    .toggle-slider:before {
      position: absolute;
      content: "";
      height: 18px;
      width: 18px;
      left: 3px;
      bottom: 3px;
      background: white;
      border-radius: 50%;
      transition: 0.3s;
    }

    .toggle input:checked + .toggle-slider {
      background: var(--success);
    }

    .toggle input:checked + .toggle-slider:before {
      transform: translateX(20px);
    }

    /* 模态框 */
    .modal {
      display: none;
      position: fixed;
      top: 0;
      left: 0;
      width: 100%;
      height: 100%;
      background: rgba(0, 0, 0, 0.7);
      z-index: 1000;
      justify-content: center;
      align-items: center;
    }

    .modal.active {
      display: flex;
    }

    .modal-content {
      background: var(--bg-secondary);
      border-radius: 12px;
      padding: 30px;
      width: 100%;
      max-width: 500px;
      max-height: 90vh;
      overflow-y: auto;
    }

    .modal-header {
      display: flex;
      justify-content: space-between;
      align-items: center;
      margin-bottom: 20px;
    }

    .modal-close {
      background: none;
      border: none;
      color: var(--text-secondary);
      font-size: 24px;
      cursor: pointer;
    }

    /* 登录/设置页 */
    .auth-container {
      min-height: 100vh;
      display: flex;
      justify-content: center;
      align-items: center;
      padding: 20px;
    }

    .auth-card {
      background: var(--bg-secondary);
      border-radius: 16px;
      padding: 40px;
      width: 100%;
      max-width: 400px;
      border: 1px solid var(--border);
    }

    .auth-title {
      font-size: 28px;
      text-align: center;
      margin-bottom: 10px;
    }

    .auth-subtitle {
      color: var(--text-secondary);
      text-align: center;
      margin-bottom: 30px;
    }

    /* 提示 */
    .alert {
      padding: 12px 15px;
      border-radius: 8px;
      margin-bottom: 20px;
      font-size: 14px;
    }

    .alert-error {
      background: rgba(239, 68, 68, 0.2);
      color: var(--danger);
      border: 1px solid var(--danger);
    }

    .alert-success {
      background: rgba(34, 197, 94, 0.2);
      color: var(--success);
      border: 1px solid var(--success);
    }

    /* 复制框 */
    .copy-box {
      display: flex;
      gap: 10px;
      align-items: center;
    }

    .copy-box input {
      flex: 1;
    }

    /* 响应式 */
    @media (max-width: 768px) {
      .layout {
        flex-direction: column;
      }

      .sidebar {
        width: 100%;
        border-right: none;
        border-bottom: 1px solid var(--border);
      }

      .stats-grid {
        grid-template-columns: 1fr;
      }
    }
  `;
}

function getScripts() {
  return `
    // API 请求封装
    async function api(path, options = {}) {
      const response = await fetch(path, {
        headers: {
          'Content-Type': 'application/json',
          ...options.headers,
        },
        ...options,
      });
      return response.json();
    }

    // 显示提示
    function showAlert(message, type = 'error') {
      const existing = document.querySelector('.alert');
      if (existing) existing.remove();

      const alert = document.createElement('div');
      alert.className = 'alert alert-' + type;
      alert.textContent = message;

      const form = document.querySelector('form') || document.querySelector('.card');
      if (form) {
        form.insertBefore(alert, form.firstChild);
      }

      if (type === 'success') {
        setTimeout(() => alert.remove(), 3000);
      }
    }

    // 复制到剪贴板
    async function copyToClipboard(text) {
      await navigator.clipboard.writeText(text);
      showAlert('已复制到剪贴板', 'success');
    }

    // 生成随机字符串
    function generateRandom(length) {
      const bytes = new Uint8Array(length);
      crypto.getRandomValues(bytes);
      return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
    }

    // 初始化设置
    async function handleSetup(e) {
      e.preventDefault();
      const form = e.target;
      const data = {
        adminPassword: form.adminPassword.value,
        encryptionKey: form.encryptionKey.value,
        shellToken: form.shellToken.value,
      };

      const result = await api('/api/setup', {
        method: 'POST',
        body: JSON.stringify(data),
      });

      if (result.error) {
        showAlert(result.error);
      } else {
        window.location.href = '/login';
      }
    }

    // 登录
    async function handleLogin(e) {
      e.preventDefault();
      const form = e.target;

      const result = await api('/api/login', {
        method: 'POST',
        body: JSON.stringify({ password: form.password.value }),
      });

      if (result.error) {
        showAlert(result.error);
      } else {
        window.location.href = '/dashboard';
      }
    }

    // 登出
    async function handleLogout() {
      await api('/api/logout', { method: 'POST' });
      window.location.href = '/login';
    }

    // 加载统计
    async function loadStats() {
      const stats = await api('/api/stats');
      if (stats.total !== undefined) {
        document.getElementById('statTotal').textContent = stats.total;
        document.getElementById('statEnabled').textContent = stats.enabled;
        document.getElementById('statDisabled').textContent = stats.disabled;
      }
    }

    // 加载凭据列表
    async function loadCredentials() {
      const result = await api('/api/credentials');
      const tbody = document.getElementById('credentialsTable');
      if (!tbody || !result.credentials) return;

      tbody.innerHTML = result.credentials.map(cred => \`
        <tr>
          <td>\${cred.name}</td>
          <td><span class="badge badge-\${cred.authMethod === 'social' ? 'success' : 'warning'}">\${cred.authMethod}</span></td>
          <td>\${cred.priority}</td>
          <td>
            <label class="toggle">
              <input type="checkbox" \${cred.enabled ? 'checked' : ''} onchange="toggleCredential('\${cred.id}')">
              <span class="toggle-slider"></span>
            </label>
          </td>
          <td>
            <button class="btn btn-secondary btn-sm" onclick="editCredential('\${cred.id}')">编辑</button>
            <button class="btn btn-danger btn-sm" onclick="deleteCredential('\${cred.id}')">删除</button>
          </td>
        </tr>
      \`).join('');
    }

    // 切换凭据状态
    async function toggleCredential(id) {
      await api('/api/credentials/' + id + '/toggle', { method: 'POST' });
    }

    // 删除凭据
    async function deleteCredential(id) {
      if (!confirm('确定要删除这个凭据吗？')) return;
      await api('/api/credentials/' + id, { method: 'DELETE' });
      loadCredentials();
      showAlert('凭据已删除', 'success');
    }

    // 显示添加凭据模态框
    function showAddModal() {
      document.getElementById('modalTitle').textContent = '添加凭据';
      document.getElementById('credentialForm').reset();
      document.getElementById('credentialId').value = '';
      document.getElementById('credentialModal').classList.add('active');
    }

    // 编辑凭据
    async function editCredential(id) {
      const result = await api('/api/credentials/' + id);
      if (result.error) {
        showAlert(result.error);
        return;
      }

      document.getElementById('modalTitle').textContent = '编辑凭据';
      document.getElementById('credentialId').value = id;
      document.getElementById('credName').value = result.name;
      document.getElementById('credRefreshToken').value = result.refreshToken;
      document.getElementById('credAccessToken').value = result.accessToken;
      document.getElementById('credExpiresAt').value = result.expiresAt;
      document.getElementById('credAuthMethod').value = result.authMethod;
      document.getElementById('credClientId').value = result.clientId;
      document.getElementById('credClientSecret').value = result.clientSecret;
      document.getElementById('credPriority').value = result.priority;
      document.getElementById('credentialModal').classList.add('active');
    }

    // 关闭模态框
    function closeModal() {
      document.getElementById('credentialModal').classList.remove('active');
    }

    // 保存凭据
    async function saveCredential(e) {
      e.preventDefault();
      const form = e.target;
      const id = document.getElementById('credentialId').value;

      const data = {
        name: form.credName.value,
        refreshToken: form.credRefreshToken.value,
        accessToken: form.credAccessToken.value,
        expiresAt: form.credExpiresAt.value,
        authMethod: form.credAuthMethod.value,
        clientId: form.credClientId.value,
        clientSecret: form.credClientSecret.value,
        priority: parseInt(form.credPriority.value) || 0,
      };

      const url = id ? '/api/credentials/' + id : '/api/credentials';
      const method = id ? 'PUT' : 'POST';

      const result = await api(url, {
        method,
        body: JSON.stringify(data),
      });

      if (result.error) {
        showAlert(result.error);
      } else {
        closeModal();
        loadCredentials();
        showAlert('凭据已保存', 'success');
      }
    }

    // 加载设置
    async function loadSettings() {
      const result = await api('/api/settings');
      if (result.encryptionKey) {
        document.getElementById('encryptionKey').value = result.encryptionKey;
        document.getElementById('shellToken').value = result.shellToken;
      }
    }

    // 重新生成密钥
    async function regenerateKey() {
      if (!confirm('重新生成密钥后，所有 Shell 都需要更新配置。确定继续？')) return;
      const result = await api('/api/settings/regenerate-key', { method: 'POST' });
      if (result.key) {
        document.getElementById('encryptionKey').value = result.key;
        showAlert('密钥已重新生成，请更新所有 Shell 的配置', 'success');
      }
    }

    // 重新生成 Token
    async function regenerateToken() {
      if (!confirm('重新生成 Token 后，所有 Shell 都需要更新配置。确定继续？')) return;
      const result = await api('/api/settings/regenerate-token', { method: 'POST' });
      if (result.token) {
        document.getElementById('shellToken').value = result.token;
        showAlert('Token 已重新生成，请更新所有 Shell 的配置', 'success');
      }
    }

    // 修改密码
    async function changePassword(e) {
      e.preventDefault();
      const form = e.target;

      if (form.newPassword.value !== form.confirmPassword.value) {
        showAlert('两次输入的密码不一致');
        return;
      }

      const result = await api('/api/settings/password', {
        method: 'PUT',
        body: JSON.stringify({
          currentPassword: form.currentPassword.value,
          newPassword: form.newPassword.value,
        }),
      });

      if (result.error) {
        showAlert(result.error);
      } else {
        form.reset();
        showAlert('密码已修改', 'success');
      }
    }

    // 页面初始化
    document.addEventListener('DOMContentLoaded', () => {
      if (document.getElementById('statTotal')) loadStats();
      if (document.getElementById('credentialsTable')) loadCredentials();
      if (document.getElementById('encryptionKey')) loadSettings();
    });
  `;
}

function setupPage() {
  return `
    <div class="auth-container">
      <div class="auth-card">
        <h1 class="auth-title">🔐 Kiro Worker</h1>
        <p class="auth-subtitle">首次使用，请完成初始化设置</p>

        <form onsubmit="handleSetup(event)">
          <div class="form-group">
            <label class="form-label">管理密码</label>
            <input type="password" name="adminPassword" class="form-input" placeholder="至少8位" required minlength="8">
          </div>

          <div class="form-group">
            <label class="form-label">加密密钥 (64位十六进制)</label>
            <div class="copy-box">
              <input type="text" name="encryptionKey" class="form-input" placeholder="点击生成按钮自动生成" required pattern="[a-fA-F0-9]{64}">
              <button type="button" class="btn btn-secondary" onclick="this.previousElementSibling.value = generateRandom(32)">生成</button>
            </div>
            <p class="form-hint">用于加密凭据，请妥善保存</p>
          </div>

          <div class="form-group">
            <label class="form-label">Shell 认证 Token</label>
            <div class="copy-box">
              <input type="text" name="shellToken" class="form-input" placeholder="点击生成按钮自动生成" required minlength="16">
              <button type="button" class="btn btn-secondary" onclick="this.previousElementSibling.value = generateRandom(32)">生成</button>
            </div>
            <p class="form-hint">Shell 端使用此 Token 获取凭据</p>
          </div>

          <button type="submit" class="btn btn-primary" style="width: 100%;">完成初始化</button>
        </form>
      </div>
    </div>
  `;
}

function loginPage() {
  return `
    <div class="auth-container">
      <div class="auth-card">
        <h1 class="auth-title">🔐 Kiro Worker</h1>
        <p class="auth-subtitle">请输入管理密码登录</p>

        <form onsubmit="handleLogin(event)">
          <div class="form-group">
            <label class="form-label">管理密码</label>
            <input type="password" name="password" class="form-input" placeholder="请输入密码" required>
          </div>

          <button type="submit" class="btn btn-primary" style="width: 100%;">登录</button>
        </form>
      </div>
    </div>
  `;
}

function dashboardPage() {
  return `
    <div class="layout">
      ${sidebar('dashboard')}

      <div class="main">
        <div class="header">
          <h1>仪表板</h1>
        </div>

        <div class="stats-grid">
          <div class="stat-card">
            <div class="stat-value" id="statTotal">-</div>
            <div class="stat-label">总凭据数</div>
          </div>
          <div class="stat-card">
            <div class="stat-value" id="statEnabled">-</div>
            <div class="stat-label">已启用</div>
          </div>
          <div class="stat-card">
            <div class="stat-value" id="statDisabled">-</div>
            <div class="stat-label">已禁用</div>
          </div>
        </div>

        <div class="card">
          <div class="card-header">
            <h2 class="card-title">快速开始</h2>
          </div>
          <p style="color: var(--text-secondary); line-height: 1.8;">
            1. 在 <a href="/credentials" style="color: var(--accent);">凭据管理</a> 中添加你的 Kiro 凭据<br>
            2. 在 <a href="/settings" style="color: var(--accent);">系统设置</a> 中获取 Shell 配置信息<br>
            3. 部署 Shell 端到 HF Space 或其他平台<br>
            4. 配置 Shell 端的环境变量后启动
          </p>
        </div>

        <div class="card">
          <div class="card-header">
            <h2 class="card-title">API 端点</h2>
          </div>
          <table class="table">
            <tr>
              <td><code>GET /api/credentials</code></td>
              <td>Shell 获取加密凭据</td>
            </tr>
            <tr>
              <td><code>GET /api/health</code></td>
              <td>健康检查</td>
            </tr>
          </table>
        </div>
      </div>
    </div>
  `;
}

function credentialsPage() {
  return `
    <div class="layout">
      ${sidebar('credentials')}

      <div class="main">
        <div class="header">
          <h1>凭据管理</h1>
          <button class="btn btn-primary" onclick="showAddModal()">+ 添加凭据</button>
        </div>

        <div class="card">
          <table class="table">
            <thead>
              <tr>
                <th>名称</th>
                <th>认证方式</th>
                <th>优先级</th>
                <th>状态</th>
                <th>操作</th>
              </tr>
            </thead>
            <tbody id="credentialsTable">
              <tr>
                <td colspan="5" style="text-align: center; color: var(--text-secondary);">加载中...</td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>
    </div>

    <!-- 添加/编辑凭据模态框 -->
    <div class="modal" id="credentialModal">
      <div class="modal-content">
        <div class="modal-header">
          <h2 id="modalTitle">添加凭据</h2>
          <button class="modal-close" onclick="closeModal()">&times;</button>
        </div>

        <form id="credentialForm" onsubmit="saveCredential(event)">
          <input type="hidden" id="credentialId">

          <div class="form-group">
            <label class="form-label">名称 *</label>
            <input type="text" id="credName" name="credName" class="form-input" placeholder="如：账户1" required>
          </div>

          <div class="form-group">
            <label class="form-label">认证方式 *</label>
            <select id="credAuthMethod" name="credAuthMethod" class="form-input" required>
              <option value="social">Social (GitHub/Google 登录)</option>
              <option value="idc">IdC (企业登录)</option>
            </select>
          </div>

          <div class="form-group">
            <label class="form-label">Refresh Token *</label>
            <textarea id="credRefreshToken" name="credRefreshToken" class="form-input" placeholder="aorAAAAA..." required></textarea>
          </div>

          <div class="form-group">
            <label class="form-label">Access Token (可选)</label>
            <textarea id="credAccessToken" name="credAccessToken" class="form-input" placeholder="aoaAAAAA..."></textarea>
          </div>

          <div class="form-group">
            <label class="form-label">过期时间</label>
            <input type="text" id="credExpiresAt" name="credExpiresAt" class="form-input" placeholder="2025-01-01T00:00:00.000Z">
          </div>

          <div class="form-group">
            <label class="form-label">Client ID (IdC 登录需要)</label>
            <input type="text" id="credClientId" name="credClientId" class="form-input">
          </div>

          <div class="form-group">
            <label class="form-label">Client Secret (IdC 登录需要)</label>
            <input type="text" id="credClientSecret" name="credClientSecret" class="form-input">
          </div>

          <div class="form-group">
            <label class="form-label">优先级</label>
            <input type="number" id="credPriority" name="credPriority" class="form-input" value="0" min="0">
            <p class="form-hint">数字越小优先级越高</p>
          </div>

          <div style="display: flex; gap: 10px; justify-content: flex-end;">
            <button type="button" class="btn btn-secondary" onclick="closeModal()">取消</button>
            <button type="submit" class="btn btn-primary">保存</button>
          </div>
        </form>
      </div>
    </div>
  `;
}

function settingsPage() {
  return `
    <div class="layout">
      ${sidebar('settings')}

      <div class="main">
        <div class="header">
          <h1>系统设置</h1>
        </div>

        <div class="card">
          <div class="card-header">
            <h2 class="card-title">Shell 配置信息</h2>
          </div>
          <p style="color: var(--text-secondary); margin-bottom: 20px;">
            将以下信息配置到 Shell 端的环境变量中
          </p>

          <div class="form-group">
            <label class="form-label">Worker URL</label>
            <div class="copy-box">
              <input type="text" class="form-input" value="${typeof location !== 'undefined' ? location.origin : 'https://your-worker.workers.dev'}" readonly id="workerUrl">
              <button type="button" class="btn btn-secondary" onclick="copyToClipboard(document.getElementById('workerUrl').value)">复制</button>
            </div>
          </div>

          <div class="form-group">
            <label class="form-label">Shell Token (AUTH_TOKEN)</label>
            <div class="copy-box">
              <input type="text" id="shellToken" class="form-input" readonly>
              <button type="button" class="btn btn-secondary" onclick="copyToClipboard(document.getElementById('shellToken').value)">复制</button>
              <button type="button" class="btn btn-danger" onclick="regenerateToken()">重新生成</button>
            </div>
          </div>

          <div class="form-group">
            <label class="form-label">加密密钥 (ENCRYPTION_KEY)</label>
            <div class="copy-box">
              <input type="text" id="encryptionKey" class="form-input" readonly>
              <button type="button" class="btn btn-secondary" onclick="copyToClipboard(document.getElementById('encryptionKey').value)">复制</button>
              <button type="button" class="btn btn-danger" onclick="regenerateKey()">重新生成</button>
            </div>
            <p class="form-hint">⚠️ 重新生成后，所有 Shell 都需要更新配置</p>
          </div>
        </div>

        <div class="card">
          <div class="card-header">
            <h2 class="card-title">修改密码</h2>
          </div>

          <form onsubmit="changePassword(event)">
            <div class="form-group">
              <label class="form-label">当前密码</label>
              <input type="password" name="currentPassword" class="form-input" required>
            </div>

            <div class="form-group">
              <label class="form-label">新密码</label>
              <input type="password" name="newPassword" class="form-input" required minlength="8">
            </div>

            <div class="form-group">
              <label class="form-label">确认新密码</label>
              <input type="password" name="confirmPassword" class="form-input" required minlength="8">
            </div>

            <button type="submit" class="btn btn-primary">修改密码</button>
          </form>
        </div>
      </div>
    </div>
  `;
}

function sidebar(active) {
  const items = [
    { id: 'dashboard', icon: '📊', label: '仪表板', href: '/dashboard' },
    { id: 'credentials', icon: '🔑', label: '凭据管理', href: '/credentials' },
    { id: 'settings', icon: '⚙️', label: '系统设置', href: '/settings' },
  ];

  return `
    <div class="sidebar">
      <div class="logo">🔐 Kiro Worker</div>
      <nav>
        ${items.map(item => `
          <a href="${item.href}" class="nav-item ${active === item.id ? 'active' : ''}">
            <span>${item.icon}</span>
            <span>${item.label}</span>
          </a>
        `).join('')}
      </nav>
      <div style="margin-top: auto; padding-top: 20px; border-top: 1px solid var(--border);">
        <a href="#" class="nav-item" onclick="handleLogout(); return false;">
          <span>🚪</span>
          <span>退出登录</span>
        </a>
      </div>
    </div>
  `;
}
