const {
  BUNDLED_PORTFOLIO,
  verifyAdminPassword,
  issueAdminToken,
  verifyAdminRequest,
  readStorageFile,
  writeStorageFile
} = require('./_lib/security');

const loginAttempts = new Map();

module.exports = async function handler(req, res) {
  res.setHeader('Cache-Control', 'no-store, max-age=0');

  if (req.method === 'GET') {
    if (!verifyAdminRequest(req)) {
      return res.status(401).json({ error: 'No autorizado' });
    }
    const raw = await readStorageFile('api/_lib/portfolio.json', BUNDLED_PORTFOLIO);
    const portfolio = raw && raw.profile ? raw : BUNDLED_PORTFOLIO;
    const rawMsgs = await readStorageFile('api/_lib/messages.json', []);
    const messages = Array.isArray(rawMsgs) ? rawMsgs : [];
    return res.status(200).json({ portfolio, messages });
  }

  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  const body = typeof req.body === 'string' ? JSON.parse(req.body) : (req.body || {});
  const action = body.action;

  if (action === 'login') {
    const ip = (req.headers['x-forwarded-for'] || req.socket?.remoteAddress || 'unknown').split(',')[0].trim();
    const now = Date.now();
    const state = loginAttempts.get(ip) || { fails: 0, until: 0 };

    if (state.until > now) {
      const waitSec = Math.ceil((state.until - now) / 1000);
      return res.status(429).json({ error: `Demasiados intentos. Bloqueado por ${waitSec}s.` });
    }

    if (!verifyAdminPassword(body.password || '')) {
      state.fails += 1;
      if (state.fails >= 5) {
        state.until = now + 60 * 1000;
      }
      loginAttempts.set(ip, state);
      return res.status(401).json({
        error: state.until > now
          ? 'Demasiados intentos fallidos. Bloqueado por 60s.'
          : `Contraseña incorrecta (${state.fails}/5).`
      });
    }

    loginAttempts.delete(ip);
    const token = issueAdminToken();
    res.setHeader(
      'Set-Cookie',
      `qh_admin_session=${encodeURIComponent(token)}; Path=/; HttpOnly; SameSite=Strict; Max-Age=28800; Secure`
    );

    const raw = await readStorageFile('api/_lib/portfolio.json', BUNDLED_PORTFOLIO);
    const portfolio = raw && raw.profile ? raw : BUNDLED_PORTFOLIO;
    const rawMsgs = await readStorageFile('api/_lib/messages.json', []);
    const messages = Array.isArray(rawMsgs) ? rawMsgs : [];
    return res.status(200).json({ ok: true, token, portfolio, messages });
  }

  if (!verifyAdminRequest(req)) {
    return res.status(401).json({ error: 'Sesión expirada o no autorizada' });
  }

  if (action === 'logout') {
    res.setHeader('Set-Cookie', 'qh_admin_session=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0');
    return res.status(200).json({ ok: true });
  }

  if (action === 'save_portfolio') {
    const newPortfolio = body.portfolio;
    if (!newPortfolio || typeof newPortfolio !== 'object') {
      return res.status(400).json({ error: 'Datos inválidos' });
    }
    delete newPortfolio.messages;
    newPortfolio.schemaVersion = 3;
    newPortfolio.updatedAt = Math.max(Date.now(), Number(newPortfolio.updatedAt) || 0);
    const result = await writeStorageFile('api/_lib/portfolio.json', newPortfolio);
    return res.status(200).json({ ok: true, portfolio: newPortfolio, updatedAt: newPortfolio.updatedAt, ...result });
  }

  if (action === 'delete_message') {
    const msgId = Number(body.id);
    const rawMsgs = await readStorageFile('api/_lib/messages.json', []);
    const messages = (Array.isArray(rawMsgs) ? rawMsgs : []).filter(m => Number(m.id) !== msgId);
    await writeStorageFile('api/_lib/messages.json', messages);
    return res.status(200).json({ ok: true, messages });
  }

  if (action === 'clear_messages') {
    await writeStorageFile('api/_lib/messages.json', []);
    return res.status(200).json({ ok: true, messages: [] });
  }

  return res.status(400).json({ error: 'Acción desconocida' });
};
