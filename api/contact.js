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

const escapeHtml = s => String(s).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

async function notifyByEmail(msg) {
  const r = await fetch('https://api.resend.com/emails', {
    method: 'POST',
    headers: { Authorization: 'Bearer ' + process.env.RESEND_API_KEY, 'Content-Type': 'application/json' },
    body: JSON.stringify({
      from: process.env.CONTACT_FROM_EMAIL || 'Portafolio <onboarding@resend.dev>',
      to: [process.env.CONTACT_NOTIFY_EMAIL],
      reply_to: msg.email, // "Responder" en tu correo le contesta directo al visitante
      subject: `Nuevo mensaje de ${msg.name.slice(0, 60)} (portafolio)`,
      text: `${msg.name} <${msg.email}> te escribió desde tu portafolio:\n\n${msg.message}\n\n— ${msg.date}`,
      html: `<p><strong>${escapeHtml(msg.name)}</strong> &lt;${escapeHtml(msg.email)}&gt; te escribió desde tu portafolio:</p>
<blockquote style="border-left:3px solid #ccc;margin:0;padding:.5em 1em;white-space:pre-wrap">${escapeHtml(msg.message)}</blockquote>
<p style="color:#666;font-size:12px">${escapeHtml(msg.date)} · Responde a este correo para contestarle directamente.</p>`
    })
  });
  if (!r.ok) throw new Error('Resend HTTP ' + r.status);
  return true;
}

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

  // Aviso inmediato al dueño (no bloquea si falla): así ningún cliente se pierde
  // aunque nadie abra el admin. Requiere RESEND_API_KEY y CONTACT_NOTIFY_EMAIL en Vercel.
  let notified = false;
  if (process.env.RESEND_API_KEY && process.env.CONTACT_NOTIFY_EMAIL) {
    notified = await notifyByEmail(newMsg).catch(err => {
      console.error('[contact] email:', err && err.message);
      return false;
    });
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
  if (!stored && !forwarded && !notified) {
    return res.status(503).json({ error: 'No se pudo enviar el mensaje. Intenta de nuevo o escríbeme por correo.' });
  }
  return res.status(200).json({ ok: true });
};
