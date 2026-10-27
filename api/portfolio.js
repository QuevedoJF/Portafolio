const { readStorageFile, toPublicPortfolio } = require('./_lib/security');

module.exports = async function handler(req, res) {
  res.setHeader('Cache-Control', 'no-store, max-age=0');
  if (req.method !== 'GET') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  try {
    const raw = await readStorageFile('data/portfolio.json', {});
    const publicData = toPublicPortfolio(raw);
    return res.status(200).json(publicData);
  } catch {
    return res.status(500).json({ error: 'Failed to load portfolio' });
  }
};
