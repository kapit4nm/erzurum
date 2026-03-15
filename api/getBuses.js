// api/getBuses.js
export default async function handler(req, res) {
  const routeCode = req.query.routeCode || 'B2%2FA';
  const apiUrl = `https://service.kentkart.com/rl1/api/info/announce?region=038&version=iOS_1.1.5(30)_18.6_iPhone+15_com.kentkart.erzurumkart&authType=4&accuracy=0&lat=36.91218785979264&lng=30.650134073584624&lang=tr&displayRouteCode=${routeCode}`;

  const bearerToken = process.env.KENTKART_TOKEN; 
  const cookieStr = process.env.KENTKART_COOKIE;

  try {
    const response = await fetch(apiUrl, {
      method: 'GET',
      headers: {
        'Host': 'service.kentkart.com',
        'Accept': 'application/json, text/plain, */*',
        'Accept-Language': 'tr-TR,tr;q=0.9',
        'Accept-Encoding': 'gzip, deflate, br',
        'User-Agent': 'Erzurum/30 CFNetwork/3826.600.41 Darwin/24.6.0',
        'Connection': 'keep-alive',
        'no_loading': 'true',
        'Authorization': `Bearer ${bearerToken}`,
        'Cookie': cookieStr
      }
    });

    if (!response.ok) {
      throw new Error(`API Hatası: ${response.status} - ${response.statusText}`);
    }

    const data = await response.json();
    res.status(200).json(data);

  } catch (error) {
    console.error("Vercel Sunucu Hatası:", error);
    res.status(500).json({ error: 'Otobüs verilerine ulaşılamadı.', details: error.message });
  }
}
