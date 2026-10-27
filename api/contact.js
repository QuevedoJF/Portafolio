const {
  readStorageFile,
  writeStorageFile,
  isAiOrScraperBot,
  isAllowedOrigin,
  sanitizeString
} = require('./_lib/security');

const rateMap = new Map();

module.exports = async function handler(req, res) {
  if (isAiOrScraperBot(req)) {
    return res.status(403).json({ error: 'Acceso denegado a sistemas de scraping o entrenamiento de IA.' });
  }

  if (!isAllowedOrigin(req)) {
    return res.status(403).json({ error: 'Origen no autorizado.' });
  }

  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  const ip = (req.headers['x-forwarded-for'] || req.socket?.remoteAddress || 'unknown').split(',')[0].trim();
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

  try {
    const body = typeof req.body === 'string' ? JSON.parse(req.body) : (req.body || {});

    // Silent honeypot check for bots
    if (body._hp_security_check) {
      return res.status(200).json({ ok: true });
    }

    const name = sanitizeString(body.name || '', 100);
    const email = sanitizeString(body.email || '', 150);
    const message = sanitizeString(body.message || '', 2000);

    if (!name || !email || !message || !email.includes('@')) {
      return res.status(400).json({ error: 'Datos de contacto inválidos.' });
    }

    const newMsg = {
      id: Date.now(),
      name,
      email,
      message,
      date: new Date().toLocaleString('es-MX', { dateStyle: 'medium', timeStyle: 'short' })
    };

    const currentMessages = await readStorageFile('api/_lib/messages.json', []);
    const list = Array.isArray(currentMessages) ? currentMessages : [];
    list.unshift(newMsg);
    await writeStorageFile('api/_lib/messages.json', list.slice(0, 200));

    if (process.env.FORMSPREE_ENDPOINT) {
      await fetch(process.env.FORMSPREE_ENDPOINT, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
        body: JSON.stringify({ name, email, message })
      }).catch(() => {});
    }

    return res.status(200).json({ ok: true });
  } catch {
    return res.status(500).json({ error: 'No se pudo procesar el mensaje en el servidor.' });
  }
};
