const { BUNDLED_PORTFOLIO, readStorageFile, toPublicPortfolio, isAiOrScraperBot, isAllowedOrigin } = require('./_lib/security');

module.exports = async function handler(req, res) {
  res.setHeader('Cache-Control', 'no-store, max-age=0');
  res.setHeader('X-Robots-Tag', 'noindex, nofollow, noai, noimageai, noarchive');

  if (isAiOrScraperBot(req)) {
    return res.status(403).json({ error: 'Acceso denegado a sistemas de scraping o entrenamiento de IA.' });
  }

  if (!isAllowedOrigin(req)) {
    return res.status(403).json({ error: 'Origen no autorizado.' });
  }

  if (req.method !== 'GET') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  try {
    const raw = await readStorageFile('api/_lib/portfolio.json', BUNDLED_PORTFOLIO);
    const source = raw && raw.profile ? raw : BUNDLED_PORTFOLIO;
    const publicData = toPublicPortfolio(source);
    return res.status(200).json(publicData);
  } catch {
    return res.status(200).json(toPublicPortfolio(BUNDLED_PORTFOLIO));
  }
};
