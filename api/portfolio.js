const { BUNDLED_PORTFOLIO, readStorageFile, toPublicPortfolio, isAiOrScraperBot, isAllowedOrigin } = require('./_lib/security');

module.exports = async function handler(req, res) {
  res.setHeader('X-Robots-Tag', 'noindex, nofollow, noarchive');

  if (isAiOrScraperBot(req)) {
    return res.status(403).json({ error: 'Acceso denegado a sistemas de scraping o entrenamiento de IA.' });
  }
  if (!isAllowedOrigin(req)) return res.status(403).json({ error: 'Origen no autorizado.' });
  if (req.method !== 'GET') return res.status(405).json({ error: 'Method not allowed' });

  try {
    const raw = await readStorageFile('api/_lib/portfolio.json', BUNDLED_PORTFOLIO);
    const source = raw && raw.profile ? raw : BUNDLED_PORTFOLIO;
    // Sin caché: los cambios del admin se ven de inmediato.
    res.setHeader('Cache-Control', 'no-store, max-age=0');
    return res.status(200).json(toPublicPortfolio(source));
  } catch (err) {
    // Si la base de datos falla, se responde error (el navegador usa su última
    // copia en caché) en lugar de mostrar datos viejos como si fueran actuales.
    console.error('[portfolio] storage:', err && err.message);
    res.setHeader('Cache-Control', 'no-store, max-age=0');
    return res.status(503).json({ error: 'Datos no disponibles temporalmente.' });
  }
};
