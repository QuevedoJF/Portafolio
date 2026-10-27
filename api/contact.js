const {
  readStorageFile,
  writeStorageFile,
  encryptServerPayload,
  decryptServerPayload
} = require('./_lib/security');

const rateMap = new Map();

module.exports = async function handler(req, res) {
  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  // Server-side IP rate limiting (max 5 messages per 10 minutes per IP)
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
    const name = String(body.name || '').trim().slice(0, 100);
    const email = String(body.email || '').trim().slice(0, 150);
    const message = String(body.message || '').trim().slice(0, 2000);

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

    // 1. Read encrypted inbox on server, append message, and re-encrypt with AES-256-GCM
    const existingEnvelope = await readStorageFile('data/messages.enc.json', null);
    const currentMessages = decryptServerPayload(existingEnvelope);
    currentMessages.unshift(newMsg);
    const newEnvelope = encryptServerPayload(currentMessages.slice(0, 200));
    await writeStorageFile('data/messages.enc.json', newEnvelope, 'chore: new encrypted contact message');

    // 2. Optional server-side email forwarding (keeps destination email & API keys 100% hidden from F12)
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
