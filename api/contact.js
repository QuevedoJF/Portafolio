const {
  addMessage,
  isAiOrScraperBot,
  isAllowedOrigin,
  sanitizeString,
  parseBody,
  clientIp
} = require('./_lib/security');

const rateMap = new Map();
const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/;

module.exports = async function handler(req, res) {
  res.setHeader('Cache-Control', 'no-store, max-age=0');

  if (isAiOrScraperBot(req)) {
    return res.status(403).json({ error: 'Acceso denegado a sistemas de scraping o entrenamiento de IA.' });
  }
  if (!isAllowedOrigin(req)) return res.status(403).json({ error: 'Origen no autorizado.' });
  if (req.method !== 'POST') return res.status(405).json({ error: 'Method not allowed' });

  const ip = clientIp(req);
  const now = Date.now();
  const entry = rateMap.get(ip) || { count: 0, resetAt: now + 10 * 60 * 1000 };
  if (now > entry.resetAt) {
    entry.count = 0;
    entry.resetAt = now + 10 * 60 * 1000;
  }
  entry.count += 1;
  rateMap.set(ip, entry);
  if (entry.count > 5) {
    return res.status(429).json({ error: 'Demasiados mensajes enviados. Intenta más tarde.' });
  }

  const body = parseBody(req);
  if (!body) return res.status(400).json({ error: 'Petición inválida' });

  // Honeypot silencioso para bots
  if (body._hp_security_check) return res.status(200).json({ ok: true });

  const name = sanitizeString(body.name || '', 100);
  const email = sanitizeString(body.email || '', 150);
  const message = sanitizeString(body.message || '', 2000);

  if (!name || !message || !EMAIL_RE.test(email)) {
    return res.status(400).json({ error: 'Revisa tu nombre, correo y mensaje.' });
  }

  const newMsg = {
    id: now,
    name,
    email,
    message,
    date: new Date().toLocaleString('es-MX', { dateStyle: 'medium', timeStyle: 'short', timeZone: 'America/Mexico_City' })
  };

  let stored = false;
  try {
    await addMessage(newMsg);
    stored = true;
  } catch (err) {
    console.error('[contact] storage:', err && err.message);
  }

  let forwarded = false;
  if (process.env.FORMSPREE_ENDPOINT) {
    try {
      const r = await fetch(process.env.FORMSPREE_ENDPOINT, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
        body: JSON.stringify({ name, email, message })
      });
      forwarded = r.ok;
    } catch {}
  }

  // Solo se confirma al visitante si el mensaje realmente quedó guardado o reenviado.
  if (!stored && !forwarded) {
    return res.status(503).json({ error: 'No se pudo enviar el mensaje. Intenta de nuevo o escríbeme por correo.' });
  }
  return res.status(200).json({ ok: true });
};
