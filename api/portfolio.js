const { BUNDLED_PORTFOLIO, readStorageFile, toPublicPortfolio } = require('./_lib/security');

module.exports = async function handler(req, res) {
  res.setHeader('Cache-Control', 'no-store, max-age=0');
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
