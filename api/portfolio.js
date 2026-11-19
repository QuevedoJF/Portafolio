const { BUNDLED_PORTFOLIO, readStorageFile, toPublicPortfolio, isAiOrScraperBot, isAllowedOrigin } = require('./_lib/security');

// Caché en memoria de la instancia (solo para lectura pública; el admin siempre lee directo).
const MEMORY_TTL_MS = 10 * 1000;
let memo = null; // { at, body }

module.exports = async function handler(req, res) {
  res.setHeader('X-Robots-Tag', 'noindex, nofollow, noarchive');

  if (isAiOrScraperBot(req)) {
    return res.status(403).json({ error: 'Acceso denegado a sistemas de scraping o entrenamiento de IA.' });
  }
  if (!isAllowedOrigin(req)) return res.status(403).json({ error: 'Origen no autorizado.' });
  if (req.method !== 'GET') return res.status(405).json({ error: 'Method not allowed' });

  // ?fresh=… lo usa el admin ("Ver portafolio") para ver al instante lo recién guardado.
  const wantsFresh = Boolean(req.query && req.query.fresh);

  try {
    let body;
    if (!wantsFresh && memo && Date.now() - memo.at < MEMORY_TTL_MS) {
      body = memo.body;
    } else {
      const raw = await readStorageFile('api/_lib/portfolio.json', BUNDLED_PORTFOLIO);
      const source = raw && raw.profile ? raw : BUNDLED_PORTFOLIO;
      body = toPublicPortfolio(source);
      memo = { at: Date.now(), body };
    }

    // Visitantes: el CDN de Vercel responde desde el borde (rápido) y se actualiza en
    // segundo plano; los cambios del admin se ven en ~1 minuto como máximo.
    res.setHeader(
      'Cache-Control',
      wantsFresh ? 'no-store, max-age=0' : 'public, max-age=0, s-maxage=60, stale-while-revalidate=86400'
    );
    return res.status(200).json(body);
  } catch (err) {
    // Si la base de datos falla se responde error (el navegador usa su copia en caché)
    // en lugar de mostrar datos viejos como si fueran actuales.
    console.error('[portfolio] storage:', err && err.message);
    res.setHeader('Cache-Control', 'no-store, max-age=0');
    return res.status(503).json({ error: 'Datos no disponibles temporalmente.' });
  }
};
