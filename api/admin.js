const {
  BUNDLED_PORTFOLIO,
  StorageError,
  ConfigError,
  verifyAdminPassword,
  issueAdminToken,
  verifyAdminRequest,
  readStorageFile,
  writeStorageFile,
  listStorageVersions,
  readStorageVersion,
  uploadImageDataUrl,
  uploadPdfDataUrl,
  externalizeImages,
  listMessages,
  deleteMessage,
  clearMessages,
  isAllowedOrigin,
  isAiOrScraperBot,
  parseBody,
  clientIp,
  loginGuardStatus,
  loginGuardFail,
  loginGuardReset,
  GUARD_GLOBAL_SLOW
} = require('./_lib/security');

const PORTFOLIO_PATH = 'api/_lib/portfolio.json';
const MAX_PORTFOLIO_BYTES = 1024 * 1024; // sin imágenes en base64 el JSON pesa pocos KB
const loginAttempts = new Map();

async function loadPortfolio() {
  const raw = await readStorageFile(PORTFOLIO_PATH, BUNDLED_PORTFOLIO);
  if (!raw || typeof raw !== 'object' || !raw.profile) {
    throw new StorageError('Los datos guardados no tienen un formato válido');
  }
  return raw;
}

function isValidPortfolio(p) {
  return (
    p && typeof p === 'object' &&
    p.profile && typeof p.profile === 'object' &&
    ['projects', 'events', 'certifications', 'technologies'].every(k => p[k] === undefined || Array.isArray(p[k]))
  );
}

function sendError(res, err) {
  if (err instanceof ConfigError) {
    console.error('[admin] config:', err.message);
    return res.status(500).json({ error: err.message, code: 'CONFIG' });
  }
  if (err instanceof StorageError) {
    console.error('[admin] storage:', err.message, err.cause || '');
    return res.status(503).json({
      error: 'La base de datos no respondió. No se modificó nada; intenta de nuevo en unos segundos.',
      detail: err.message,
      code: 'STORAGE'
    });
  }
  console.error('[admin] unexpected:', err);
  return res.status(500).json({ error: 'Error interno del servidor', code: 'INTERNAL' });
}

module.exports = async function handler(req, res) {
  res.setHeader('Cache-Control', 'no-store, max-age=0');
  res.setHeader('X-Robots-Tag', 'noindex, nofollow, noarchive');

  if (isAiOrScraperBot(req)) return res.status(403).json({ error: 'Acceso denegado' });
  if (!isAllowedOrigin(req)) return res.status(403).json({ error: 'Origen no autorizado' });

  try {
    if (req.method === 'GET') {
      if (!verifyAdminRequest(req)) return res.status(401).json({ error: 'No autorizado' });
      const [portfolio, messages] = await Promise.all([loadPortfolio(), listMessages()]);
      return res.status(200).json({ portfolio, messages, version: Number(portfolio.updatedAt) || 0 });
    }

    if (req.method !== 'POST') return res.status(405).json({ error: 'Method not allowed' });

    const body = parseBody(req);
    if (!body) return res.status(400).json({ error: 'Petición inválida' });
    const action = body.action;

    if (action === 'login') {
      const ip = clientIp(req);
      const now = Date.now();
      const state = loginAttempts.get(ip) || { fails: 0, until: 0 };

      if (state.until > now) {
        const waitSec = Math.ceil((state.until - now) / 1000);
        return res.status(429).json({ error: `Demasiados intentos. Intenta de nuevo en ${Math.ceil(waitSec / 60)} min.` });
      }

      // Bloqueo persistente (compartido entre instancias). Si Blob falla, sigue el de memoria.
      const guard = await loginGuardStatus(ip).catch(() => null);
      if (guard && guard.blocked) {
        return res.status(429).json({ error: `Demasiados intentos fallidos. Intenta de nuevo en ${Math.ceil(guard.retryAfterSec / 60)} min.` });
      }

      if (!verifyAdminPassword(body.password || '')) {
        state.fails += 1;
        if (state.fails >= 5) state.until = now + 15 * 60 * 1000;
        loginAttempts.set(ip, state);
        await loginGuardFail(ip).catch(() => {});
        const fails = Math.max(state.fails, ((guard && guard.ipFails) || 0) + 1);
        // Muchos fallos desde muchas IPs: respuestas más lentas (frena ataques repartidos)
        const slow = guard && guard.globalFails >= GUARD_GLOBAL_SLOW ? 2500 : 600;
        await new Promise(r => setTimeout(r, slow));
        return res.status(fails >= 5 ? 429 : 401).json({
          error: fails >= 5
            ? 'Demasiados intentos fallidos. Intenta de nuevo en 15 min.'
            : `Contraseña incorrecta (${fails}/5).`
        });
      }

      loginAttempts.delete(ip);
      loginGuardReset(ip).catch(() => {});
      const token = issueAdminToken(); // lanza ConfigError si falta ADMIN_SECRET
      // Si la base de datos no responde NO se abre el panel: así nunca se edita
      // (y luego se guarda) una copia vieja encima de los datos buenos.
      const [portfolio, messages] = await Promise.all([loadPortfolio(), listMessages()]);
      res.setHeader(
        'Set-Cookie',
        `qh_admin_session=${encodeURIComponent(token)}; Path=/; HttpOnly; SameSite=Strict; Max-Age=28800; Secure`
      );
      return res.status(200).json({ ok: true, token, portfolio, messages, version: Number(portfolio.updatedAt) || 0 });
    }

    if (!verifyAdminRequest(req)) {
      return res.status(401).json({ error: 'Sesión expirada o no autorizada', code: 'AUTH' });
    }

    if (action === 'logout') {
      res.setHeader('Set-Cookie', 'qh_admin_session=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0; Secure');
      return res.status(200).json({ ok: true });
    }

    if (action === 'save_portfolio') {
      const incoming = body.portfolio;
      if (!isValidPortfolio(incoming)) return res.status(400).json({ error: 'Datos inválidos' });

      // Control de concurrencia optimista: solo se guarda si el cliente editó
      // sobre la versión más reciente. Evita que una pestaña vieja (o datos
      // cargados antes de un fallo) sobrescriba cambios más nuevos.
      const current = await loadPortfolio();
      const currentVersion = Number(current.updatedAt) || 0;
      const baseVersion = Number(body.baseVersion);
      if (!Number.isFinite(baseVersion) || baseVersion < currentVersion) {
        return res.status(409).json({
          error: 'Hay una versión más reciente guardada (¿otra pestaña o dispositivo?).',
          code: 'CONFLICT',
          portfolio: current,
          version: currentVersion
        });
      }

      delete incoming.messages;
      await externalizeImages(incoming); // red de seguridad: ninguna imagen base64 llega al JSON
      incoming.schemaVersion = Math.min(Math.max(3, Number(incoming.schemaVersion) || 3, Number(current.schemaVersion) || 3), 99);
      incoming.updatedAt = Math.max(Date.now(), currentVersion + 1);

      if (Buffer.byteLength(JSON.stringify(incoming)) > MAX_PORTFOLIO_BYTES) {
        return res.status(413).json({ error: 'El portafolio es demasiado grande' });
      }

      await writeStorageFile(PORTFOLIO_PATH, incoming);
      return res.status(200).json({ ok: true, portfolio: incoming, version: incoming.updatedAt });
    }

    if (action === 'upload_document') {
      const url = await uploadPdfDataUrl(body.dataUrl);
      return res.status(200).json({ ok: true, url });
    }

    if (action === 'upload_image') {
      const url = await uploadImageDataUrl(body.dataUrl);
      return res.status(200).json({ ok: true, url });
    }

    if (action === 'list_versions') {
      const versions = await listStorageVersions(PORTFOLIO_PATH);
      return res.status(200).json({ ok: true, versions });
    }

    if (action === 'restore_version') {
      const snapshot = await readStorageVersion(PORTFOLIO_PATH, body.versionId);
      if (!isValidPortfolio(snapshot)) return res.status(400).json({ error: 'La versión está dañada' });
      const current = await loadPortfolio();
      snapshot.updatedAt = Math.max(Date.now(), (Number(current.updatedAt) || 0) + 1);
      // Restaurar es fiel al contenido: no se re-aplican migraciones sobre lo restaurado
      snapshot.schemaVersion = Math.max(Number(snapshot.schemaVersion) || 3, Number(current.schemaVersion) || 3);
      await writeStorageFile(PORTFOLIO_PATH, snapshot);
      return res.status(200).json({ ok: true, portfolio: snapshot, version: snapshot.updatedAt });
    }

    if (action === 'delete_message') {
      await deleteMessage(body.id);
      return res.status(200).json({ ok: true, messages: await listMessages() });
    }

    if (action === 'clear_messages') {
      await clearMessages();
      return res.status(200).json({ ok: true, messages: [] });
    }

    return res.status(400).json({ error: 'Acción desconocida' });
  } catch (err) {
    return sendError(res, err);
  }
};
