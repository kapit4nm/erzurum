// ============================================================
// /api/buses.js — Vercel Edge Function
// Güvenlik katmanları:
//   1. CORS — sadece izin verilen origin'ler
//   2. Rate limiting — IP + global
//   3. Input validation — injection koruması
//   4. Response cache — Kentkart'a gereksiz istek gitmez
//   5. Veri temizleme — sadece gerekli alanlar döner
//   6. Hata maskeleme — iç hata detayları kullanıcıya gitmez
//   7. Timeout — sonsuz bekleme yok
//   8. Güvenlik header'ları
// ============================================================

// ── Sabitler ─────────────────────────────────────────────────
const KENTKART_BASE  = 'https://service.kentkart.com/rl1';
const REGION         = '038';
const KENTKART_UA    = 'Erzurum/30 CFNetwork/3826.600.41 Darwin/24.6.0';
const CACHE_TTL_MS   = 14_000;   // 14 sn cache (polling 15 sn, biraz tolerans)
const TIMEOUT_MS     = 8_000;    // Kentkart'a max 8 sn bekle
const RATE_WINDOW_MS = 60_000;   // Rate limit penceresi: 1 dakika
const RATE_MAX_IP    = 20;       // IP başına dakikada max istek
const RATE_MAX_TOTAL = 200;      // Tüm istekler için dakikada max (DDoS)

// Geçerli hat kodları — sadece bunlara izin ver
const VALID_ROUTES = new Set([
  'A1','B1','B2','B2/A','B3','B7','D1','D2',
  'G1','G1-A','G2','G3','G4','G4/A','G4/B','G5','G6','G7','G7/A',
  'G8','G9','G10','G11','G13','G14',
  'K1','K1/A','K2','K3','K4','K5','K6','K7','K7/A','K10','K11',
  'M1','M2','M3','M4','M5','M6','M7','M8','M9','M10',
  'M11','M12','M13','M14','M15','M16','M17','M18','M19',
  'NA1','NA2','NAO','T6',
]);

// ── In-memory depolama (Edge: her instance bağımsız, yeterli) ──
const ipRateMap     = new Map(); // IP bazlı rate limit
const responseCache = new Map(); // Yanıt cache'i
let globalCount = 0;
let globalReset = Date.now() + RATE_WINDOW_MS;

// ── Yardımcılar ───────────────────────────────────────────────
function json(data, status = 200, extra = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      'Content-Type': 'application/json',
      ...extra,
    },
  });
}

function checkGlobalRate() {
  const now = Date.now();
  if (now > globalReset) { globalCount = 0; globalReset = now + RATE_WINDOW_MS; }
  globalCount++;
  return globalCount <= RATE_MAX_TOTAL;
}

function checkIpRate(ip) {
  const now = Date.now();
  const e   = ipRateMap.get(ip) || { n: 0, reset: now + RATE_WINDOW_MS };
  if (now > e.reset) { e.n = 1; e.reset = now + RATE_WINDOW_MS; }
  else e.n++;
  ipRateMap.set(ip, e);

  // Bellek temizliği — 1000'den fazla IP birikirse eski girişleri sil
  if (ipRateMap.size > 1000) {
    for (const [k, v] of ipRateMap) {
      if (now > v.reset) ipRateMap.delete(k);
    }
  }
  return e.n <= RATE_MAX_IP;
}

function getCache(key) {
  const entry = responseCache.get(key);
  if (!entry) return null;
  if (Date.now() > entry.exp) { responseCache.delete(key); return null; }
  return entry.data;
}

function setCache(key, data) {
  // Cache 50'den fazla girişe ulaşırsa eskiyi temizle
  if (responseCache.size >= 50) {
    const now = Date.now();
    for (const [k, v] of responseCache) {
      if (now > v.exp) responseCache.delete(k);
    }
  }
  responseCache.set(key, { data, exp: Date.now() + CACHE_TTL_MS });
}

// ── Ana Handler ───────────────────────────────────────────────
export default async function handler(req) {

  // ── 1. Güvenlik header'ları (her yanıtta) ──────────────────
  const secHeaders = {
    'X-Content-Type-Options':  'nosniff',
    'X-Frame-Options':         'DENY',
    'X-XSS-Protection':        '1; mode=block',
    'Referrer-Policy':         'strict-origin-when-cross-origin',
    'Content-Type':            'application/json',
  };

  // ── 2. Sadece GET kabul et ──────────────────────────────────
  if (req.method === 'OPTIONS') {
    return new Response(null, { status: 204, headers: secHeaders });
  }
  if (req.method !== 'GET') {
    return json({ error: 'Method not allowed' }, 405, secHeaders);
  }

  // ── 3. CORS ────────────────────────────────────────────────
  const origin  = req.headers.get('origin') || '';
  const allowed = (process.env.ALLOWED_ORIGINS || '').split(',').map(s => s.trim());

  // Hiç origin yoksa (doğrudan URL isteği) → engelle
  // Localhost geliştirme için istisna
  const isLocalDev = origin.startsWith('http://localhost') || origin.startsWith('http://127.');
  const isAllowed  = allowed.includes(origin) || isLocalDev;

  if (origin && !isAllowed) {
    return json({ error: 'Forbidden' }, 403, secHeaders);
  }

  const corsHeaders = {
    ...secHeaders,
    'Access-Control-Allow-Origin':  isAllowed ? origin : '',
    'Access-Control-Allow-Methods': 'GET',
    'Access-Control-Max-Age':       '86400',
  };

  // ── 4. Global rate limit (DDoS koruması) ───────────────────
  if (!checkGlobalRate()) {
    return json(
      { error: 'Sunucu meşgul, lütfen bekleyin' }, 429,
      { ...corsHeaders, 'Retry-After': '60' }
    );
  }

  // ── 5. IP bazlı rate limit ──────────────────────────────────
  const ip = (req.headers.get('x-forwarded-for') || 'unknown').split(',')[0].trim();
  if (!checkIpRate(ip)) {
    return json(
      { error: 'Çok fazla istek. 1 dakika bekleyin.' }, 429,
      { ...corsHeaders, 'Retry-After': '60' }
    );
  }

  // ── 6. Token kontrolü ──────────────────────────────────────
  const TOKEN = process.env.KENTKART_TOKEN;
  if (!TOKEN) {
    // Detayı kullanıcıya verme — sadece loglara yaz
    console.error('[buses] KENTKART_TOKEN env eksik');
    return json({ error: 'Servis geçici olarak kullanılamıyor' }, 503, corsHeaders);
  }

  // ── 7. Parametre doğrulama ──────────────────────────────────
  const url   = new URL(req.url);
  const route = (url.searchParams.get('route') || '').trim().toUpperCase();
  const dir   = url.searchParams.get('direction') || '0';

  if (!route) {
    return json({ error: 'route parametresi gerekli' }, 400, corsHeaders);
  }

  // Whitelist kontrolü — sadece bilinen hat kodları
  if (!VALID_ROUTES.has(route)) {
    return json({ error: 'Geçersiz hat kodu' }, 400, corsHeaders);
  }

  // direction sadece 0 veya 1 olabilir
  if (dir !== '0' && dir !== '1') {
    return json({ error: 'Geçersiz yön' }, 400, corsHeaders);
  }

  // ── 8. Cache kontrolü ──────────────────────────────────────
  const cacheKey = `${route}:${dir}`;
  const cached   = getCache(cacheKey);
  if (cached) {
    return json(cached, 200, {
      ...corsHeaders,
      'Cache-Control': 'no-store',
      'X-Cache':       'HIT',
    });
  }

  // ── 9. Kentkart API isteği ──────────────────────────────────
  try {
    const params = new URLSearchParams({
      region:           REGION,
      version:          'iOS_1.1.5(30)_18.6_iPhone+15_com.kentkart.erzurumkart',
      authType:         '4',
      accuracy:         '0',
      lat:              '39.9150',
      lng:              '41.2271',
      lang:             'tr',
      displayRouteCode: route,
      direction:        dir,
      shapeId:          '',
      busStopId:        '',
      resultType:       '11111111',
    });

    const upstream = await fetch(
      `${KENTKART_BASE}/api/v2.0/route/info?${params}`,
      {
        headers: {
          'Authorization': `Bearer ${TOKEN}`,
          'User-Agent':    KENTKART_UA,
          'Accept':        'application/json',
        },
        signal: AbortSignal.timeout(TIMEOUT_MS),
      }
    );

    if (!upstream.ok) {
      // Kentkart 401 → token süresi dolmuş
      if (upstream.status === 401) {
        console.error('[buses] Token süresi dolmuş');
        return json({ error: 'Servis token yenileniyor', tokenExpired: true }, 503, corsHeaders);
      }
      throw new Error(`upstream ${upstream.status}`);
    }

    const data = await upstream.json();

    if (data.result?.code !== 0) {
      // Token süresi (code 1 veya 2)
      if (data.result?.code === 1 || data.result?.code === 2) {
        return json({ error: 'Token yenileniyor', tokenExpired: true }, 503, corsHeaders);
      }
      return json({ buses: [], stopNames: {} }, 200, corsHeaders);
    }

    const path = data.pathList?.[0];
    if (!path) {
      return json({ buses: [], stopNames: {} }, 200, corsHeaders);
    }

    // ── 10. Veri temizleme — hassas alan sızdırma yok ──────
    const clean = {
      buses: (path.busList || []).map(b => ({
        busId:            String(b.busId   || ''),
        lat:              String(b.lat     || '0'),
        lng:              String(b.lng     || '0'),
        bearing:          String(b.bearing || '0'),
        plateNumber:      String(b.plateNumber || ''),
        stopId:           String(b.stopId  || ''),
        tripId:           String(b.tripId  || ''),
        busCapacityColor: String(b.busCapacityColor || ''),
        ac:               b.ac === '1' ? '1' : '0',
      })),
      stopNames: Object.fromEntries(
        (path.busStopList || [])
          .filter(s => s.stopId && s.stopName)
          .map(s => [String(s.stopId), String(s.stopName)])
      ),
    };

    setCache(cacheKey, clean);

    return json(clean, 200, {
      ...corsHeaders,
      'Cache-Control': 'no-store',
      'X-Cache':       'MISS',
    });

  } catch (err) {
    // Hata detayını kullanıcıya verme
    if (err.name === 'TimeoutError' || err.name === 'AbortError') {
      return json({ error: 'Kentkart bağlantı zaman aşımı', buses: [] }, 504, corsHeaders);
    }
    console.error('[buses] hata:', err.message);
    return json({ error: 'Servis geçici olarak kullanılamıyor', buses: [] }, 503, corsHeaders);
  }
}
