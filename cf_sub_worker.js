/**
 * xray-cf-lite 私人 Cloudflare Worker 订阅服务端（单文件 · ES Module · 零外部依赖）
 *
 * 用途：
 *   把本文件整段粘贴到 Cloudflare Dashboard 的 Worker 编辑器即可部署，
 *   为 v2rayN / Shadowrocket / NekoBox 等客户端提供在线 Base64 订阅。
 *   每次客户端点「更新订阅」时，Worker 会并发拉取多个第三方优选 IP 源，
 *   清洗、去重后套用 xray_cf_lite.sh 完全相同的节点 URI 模板。
 *
 * 与 xray_cf_lite.sh 生成的订阅链接兼容：
 *   GET https://<worker>/<uid>/sub?domain=<domain>&path=<path>&ev=yes&et=yes&mess=yes
 *
 * 可选 Worker 环境变量：
 *   TOKEN      非空时强制鉴权，支持 Authorization: Bearer <TOKEN> 或 ?token=<TOKEN>
 *   IP_URLS    自定义优选源（逗号 / 换行 / 空格分隔），非空时覆盖 DEFAULT_IP_URLS
 *   PORT_MODE  "all_tls"（默认）或 "only_443"
 *
 * 注意：Cloudflare Worker 的 btoa() 不能直接编码中文，本文件统一使用
 *       utf8ToBase64()，避免备注含中文时抛 InvalidCharacterError 导致 500。
 */

// ─────────────────────────────────────────────────────────────
// 可编辑默认配置区（不配置环境变量时直接改这里即可）
// ─────────────────────────────────────────────────────────────

// 默认优选 IP / 域名源，必须与 xray_cf_lite.sh 的 DEFAULT_IP_URLS 保持一致
const DEFAULT_IP_URLS = [
  "https://raw.githubusercontent.com/gshtwy/CF-DNS-Clone/refs/heads/main/wetest-cloudflare-v4.txt",
  "https://edt-aio-nav.pages.dev/cm/ct_50.txt",
  "https://edt-aio-nav.pages.dev/wetest/ipv4.txt",
  "https://edt-aio-nav.pages.dev/domain/all.txt",
];

// 默认端口策略：all_tls = 保留 CF 全部 TLS 端口；only_443 = 仅保留 443
const DEFAULT_PORT_MODE = "all_tls";

// 默认订阅名 / 节点备注前缀（仅在显式传入 ?name= 时启用，避免破坏与本地订阅的一致性）
const DEFAULT_SUB_NAME = "xray-cf-lite";

// 默认 WS 路径
const DEFAULT_PATH = "/";

// 原生基准节点固定使用的端口
const NATIVE_PORT = "443";

// 单个优选源拉取超时（毫秒）
const FETCH_TIMEOUT_MS = 8000;

// 单个优选源响应体上限（2 MiB），超过即中止并跳过该源
const MAX_SOURCE_BYTES = 2 * 1024 * 1024;

// 跟随重定向的最大跳数；每一跳都会重新做 SSRF 校验
const MAX_REDIRECTS = 3;

// 单次订阅最多拉取的源数量
const MAX_IP_SOURCES = 32;

// Cloudflare 官方 TLS 端口集合
const TLS_PORTS = new Set(["443", "2053", "2083", "2087", "2096", "8443"]);

// 健康检查 / 根路径固定返回文本（绝不回显任何敏感配置）
const HEALTH_TEXT = "xray-cf-lite sub worker ok";

// 让客户端能正常显示流量与到期时间，避免报「订阅无效」
const SUBSCRIPTION_USERINFO = "upload=0; download=0; total=10737418240000; expire=253402271999";

// ─────────────────────────────────────────────────────────────
// 基础工具
// ─────────────────────────────────────────────────────────────

/**
 * UTF-8 安全 Base64 编码。
 * btoa() 只接受 Latin-1，直接传入中文会抛 InvalidCharacterError；
 * 这里先用 TextEncoder 转成字节，再分块拼成二进制串交给 btoa()。
 */
function utf8ToBase64(str) {
  const bytes = new TextEncoder().encode(String(str));
  const CHUNK_SIZE = 8192;
  let binary = "";
  for (let i = 0; i < bytes.length; i += CHUNK_SIZE) {
    binary += String.fromCharCode.apply(null, bytes.subarray(i, i + CHUNK_SIZE));
  }
  return btoa(binary);
}

/**
 * 恒定时间字符串比较，降低 TOKEN 被时序侧信道猜解的风险。
 * 先比较长度，再逐字节异或累加，不提前 return。
 */
function timingSafeEqual(a, b) {
  const left = new TextEncoder().encode(String(a));
  const right = new TextEncoder().encode(String(b));
  if (left.length !== right.length) return false;
  let diff = 0;
  for (let i = 0; i < left.length; i += 1) {
    diff |= left[i] ^ right[i];
  }
  return diff === 0;
}

/**
 * 把逗号 / 换行 / 空格 / 制表符分隔的列表拆成数组。
 */
function splitList(raw) {
  if (raw === null || raw === undefined) return [];
  return String(raw)
    .split(/[\s,]+/)
    .map((item) => item.trim())
    .filter(Boolean);
}

/**
 * 清洗订阅名：去控制字符、制表符，并限制长度。
 */
function sanitizeName(value) {
  return String(value)
    .replace(/\t/g, " ")
    .replace(/[\u0000-\u001F\u007F]/g, "")
    .trim()
    .slice(0, 48);
}

/**
 * 清洗节点备注：制表符转空格，剔除控制字符，空备注使用兜底值。
 */
function cleanRemark(raw, fallback) {
  const cleaned = String(raw)
    .replace(/\t/g, " ")
    .replace(/[\u0000-\u001F\u007F]/g, "")
    .trim();
  return cleaned || fallback;
}

// ─────────────────────────────────────────────────────────────
// 地址校验与解析
// ─────────────────────────────────────────────────────────────

/**
 * 判断是否为合法 IPv4（四段，每段 0-255）。
 */
function isIPv4(host) {
  const match = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(host);
  if (!match) return false;
  for (let i = 1; i <= 4; i += 1) {
    if (Number(match[i]) > 255) return false;
  }
  return true;
}

/**
 * 判断方括号内的 IPv6 字面量是否合法：
 * 仅允许 [0-9a-fA-F:]，且至少包含 2 个冒号。
 */
function isIPv6(raw) {
  if (!/^[0-9a-fA-F:]+$/.test(raw)) return false;
  const colonCount = (raw.match(/:/g) || []).length;
  return colonCount >= 2;
}

/**
 * 判断是否为合法域名：必须含点、至少一个字母字符，且以字母或数字开头结尾。
 * 拒绝纯数字与点组成的串（如 999.999.999.999、1.2.3.999），
 * 避免把非法 IPv4 当成域名生成连不上的节点。
 */
function isDomainName(host) {
  if (!host || host.length > 253 || !host.includes(".")) return false;
  if (!/[a-zA-Z]/.test(host)) return false;
  return /^[a-zA-Z0-9]([a-zA-Z0-9.-]*[a-zA-Z0-9])?$/.test(host);
}

/**
 * 解析 ?domain= 参数，返回统一的 host 结构。
 * 支持域名、IPv4、[IPv6]、裸 IPv6。
 */
function parseHostValue(value) {
  if (typeof value !== "string") return null;
  const input = value.trim();
  if (!input) return null;

  if (input.startsWith("[")) {
    const match = /^\[([0-9a-fA-F:]+)\]$/.exec(input);
    if (!match) return null;
    const raw = match[1];
    if (!isIPv6(raw)) return null;
    return { kind: "ipv6", raw, display: `[${raw}]` };
  }

  if (isIPv4(input)) {
    return { kind: "ipv4", raw: input, display: input };
  }

  if (isIPv6(input)) {
    return { kind: "ipv6", raw: input, display: `[${input}]` };
  }

  if (input.includes(":")) return null;
  if (!isDomainName(input)) return null;
  return { kind: "domain", raw: input, display: input };
}

/**
 * 解析优选列表中的一条地址（可能是 host、host:port、[IPv6]、[IPv6]:port）。
 * 返回 null 表示地址或端口不合法 / 被端口策略过滤。
 */
function parsePreferredEndpoint(addrPart, portMode) {
  let rawHost = "";
  let isV6 = false;
  let port = NATIVE_PORT;

  if (addrPart.startsWith("[")) {
    // [IPv6]:port 或 [IPv6]
    const match = /^\[([0-9a-fA-F:]+)\](?::([0-9]+))?$/.exec(addrPart);
    if (!match) return null;
    rawHost = match[1];
    isV6 = true;
    if (match[2] !== undefined) port = match[2];
  } else {
    // host:port
    const match = /^([^:]+):([0-9]+)$/.exec(addrPart);
    if (match) {
      rawHost = match[1];
      port = match[2];
    } else if (addrPart.includes(":")) {
      // 裸 IPv6 或畸形地址（优选列表要求 IPv6 必须带方括号）
      return null;
    } else {
      rawHost = addrPart;
    }
  }

  if (isV6) {
    if (!isIPv6(rawHost)) return null;
  } else if (!isIPv4(rawHost) && !isDomainName(rawHost)) {
    return null;
  }

  if (!/^\d+$/.test(port)) return null;
  const portNumber = Number(port);
  if (!Number.isInteger(portNumber) || portNumber < 1 || portNumber > 65535) return null;
  const portText = String(portNumber);

  // 端口策略过滤
  if (portMode === "only_443") {
    if (portText !== "443") return null;
  } else if (!TLS_PORTS.has(portText)) {
    return null;
  }

  const displayHost = isV6 ? `[${rawHost}]` : rawHost;
  return {
    isIPv6: isV6,
    rawHost,
    displayHost,
    port: portText,
    // 去重键：host 统一小写，IPv6 自然归一化
    hostKey: `${rawHost.toLowerCase()}:${portText}`,
  };
}

// ─────────────────────────────────────────────────────────────
// 优选源 URL 安全校验（SSRF 防护）
// ─────────────────────────────────────────────────────────────

/**
 * 判断 IPv4 是否属于私有 / 环回 / 链路本地 / 保留 / 组播网段。
 */
function isPrivateIPv4(host) {
  const match = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(host);
  if (!match) return false;
  const a = Number(match[1]);
  const b = Number(match[2]);
  return (
    a === 0 ||
    a === 10 ||
    a === 127 ||
    (a === 169 && b === 254) ||
    (a === 172 && b >= 16 && b <= 31) ||
    (a === 192 && b === 168) ||
    (a === 100 && b >= 64 && b <= 127) ||
    (a === 198 && (b === 18 || b === 19)) ||
    a >= 224
  );
}

/**
 * 判断 IPv6 是否属于环回 / 未指定 / 链路本地 / ULA / IPv4 映射 / 过渡地址。
 * 依赖 WHATWG URL 对 IPv6 的规范化（如 0:0:0:0:0:0:0:1 -> ::1）。
 */
function isPrivateIPv6(host) {
  if (!host.includes(":")) return false;
  if (host === "::" || host === "::1") return true;
  // fe80::/10 链路本地 + fec0::/10 站点本地
  if (/^fe[89ab]/.test(host) || /^fe[c-f]/.test(host)) return true;
  // fc00::/7 唯一本地地址
  if (/^f[cd]/.test(host)) return true;
  // ::ffff:0:0/96 IPv4 映射地址（可能绕过 IPv4 检查）
  if (host.startsWith("::ffff:")) return true;
  // 2002::/16 6to4
  if (host.startsWith("2002:")) return true;
  // 2001:0000::/32 Teredo（可能被压缩为 2001::/32）
  if (host.startsWith("2001:0:") || host.startsWith("2001::") || host === "2001:0") return true;
  // 64:ff9b::/96 NAT64
  if (host.startsWith("64:ff9b:")) return true;
  return false;
}

/**
 * 仅校验 scheme 是否为 http / https（用于受信任的环境变量源）。
 */
function isHttpUrl(raw) {
  try {
    const parsed = new URL(String(raw));
    return parsed.protocol === "http:" || parsed.protocol === "https:";
  } catch {
    return false;
  }
}

// 已知会解析到回环 / 内网地址的域名后缀，一律拒绝（含其子域）
const BLOCKED_DOMAIN_SUFFIXES = [
  "localhost",
  "local",
  "internal",
  "home.arpa",
  "lan",
  "localtest.me",
  "lvh.me",
  "nip.io",
  "sslip.io",
  "xip.io",
  "traefik.me",
  "vcap.me",
  "lacolhost.com",
];

/**
 * 判断 host 是否等于 suffix 或为其子域。
 */
function matchesDomainSuffix(host, suffix) {
  return host === suffix || host.endsWith(`.${suffix}`);
}

/**
 * 完整校验优选源 URL：
 * 只允许 http/https；拒绝 localhost / 单标签主机名、私有网段、环回、链路本地、
 * 已知回环别名后缀，以及 6to4 / Teredo / NAT64 / IPv4-mapped 等过渡地址。
 * 注意：Workers 没有 DNS 解析 API，本函数只能做字面量判断。
 */
function isSafeSourceUrl(raw) {
  let parsed;
  try {
    parsed = new URL(String(raw));
  } catch {
    return false;
  }
  if (parsed.protocol !== "http:" && parsed.protocol !== "https:") return false;

  let host = parsed.hostname.toLowerCase();
  const isBracketed = host.startsWith("[") && host.endsWith("]");
  if (isBracketed) host = host.slice(1, -1);
  if (host.endsWith(".")) host = host.slice(0, -1);
  if (!host) return false;

  // IPv6 字面量
  if (isBracketed) {
    return !isPrivateIPv6(host);
  }

  // IPv4 字面量
  if (isIPv4(host)) {
    return !isPrivateIPv4(host);
  }

  // 单标签主机名（无点、非 IP）一律拒绝，覆盖 localhost 及其变体
  if (!host.includes(".")) return false;

  for (const suffix of BLOCKED_DOMAIN_SUFFIXES) {
    if (matchesDomainSuffix(host, suffix)) return false;
  }

  if (!isDomainName(host)) return false;
  return true;
}

// ─────────────────────────────────────────────────────────────
// 并发拉取与文本清洗
// ─────────────────────────────────────────────────────────────

/**
 * 构造超时信号：
 * 优先使用 AbortSignal.timeout()；运行时不支持时降级为 AbortController + setTimeout。
 */
function createTimeoutSignal(timeoutMs) {
  if (typeof AbortSignal !== "undefined" && typeof AbortSignal.timeout === "function") {
    return { signal: AbortSignal.timeout(timeoutMs), cancel: null };
  }
  const controller = new AbortController();
  const timer = setTimeout(() => {
    try {
      controller.abort();
    } catch {
      // 忽略 abort 异常
    }
  }, timeoutMs);
  return {
    signal: controller.signal,
    cancel: () => clearTimeout(timer),
  };
}

/**
 * 读取响应体并施加字节上限：
 * 先用 Content-Length 预判，再按流累计字节；超限立即 cancel 并返回空串。
 */
async function readLimitedText(response, maxBytes) {
  const contentLength = response.headers.get("content-length");
  if (contentLength) {
    const declared = Number(contentLength);
    if (Number.isFinite(declared) && declared > maxBytes) return "";
  }

  if (!response.body || typeof response.body.getReader !== "function") {
    const text = await response.text();
    return new TextEncoder().encode(text).length > maxBytes ? "" : text;
  }

  const reader = response.body.getReader();
  const chunks = [];
  let total = 0;
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      if (!value) continue;
      total += value.byteLength;
      if (total > maxBytes) {
        try {
          await reader.cancel();
        } catch {
          // 忽略取消失败
        }
        return "";
      }
      chunks.push(value);
    }
  } catch {
    try {
      await reader.cancel();
    } catch {
      // 忽略取消失败
    }
    return "";
  }

  const merged = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    merged.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return new TextDecoder().decode(merged);
}

/**
 * 拉取单个优选源，任何失败 / 超时 / 非 2xx / 超限都返回空串，绝不向上抛异常。
 * 重定向使用 manual，最多跟随 MAX_REDIRECTS 跳，且每一跳都重新做 SSRF 校验。
 */
async function fetchSource(sourceUrl, timeoutMs) {
  const { signal, cancel } = createTimeoutSignal(timeoutMs);
  try {
    let current = String(sourceUrl);
    for (let hop = 0; hop <= MAX_REDIRECTS; hop += 1) {
      if (!isSafeSourceUrl(current)) return "";
      const response = await fetch(current, {
        signal,
        redirect: "manual",
        headers: {
          Accept: "text/plain, */*",
          "User-Agent": "xray-cf-lite-sub-worker/1.0",
        },
      });
      if (!response) return "";
      if (response.status >= 300 && response.status < 400) {
        const location = response.headers.get("location");
        if (!location) return "";
        try {
          current = new URL(location, current).toString();
        } catch {
          return "";
        }
        continue;
      }
      if (response.ok === false) return "";
      return await readLimitedText(response, MAX_SOURCE_BYTES);
    }
    return "";
  } catch {
    return "";
  } finally {
    if (cancel) cancel();
  }
}

/**
 * 按 xray_cf_lite.sh 的 fetch_and_clean_preferred_ips 规则清洗一个源的内容：
 * 注释行跳过、首个 # 分备注、广告行跳过、CSV 取首列、端口过滤、host:port 去重。
 */
function collectEndpoints(text, portMode, seen, output) {
  const lines = String(text).replace(/\r/g, "").split("\n");

  for (let line of lines) {
    line = line.trim();
    if (!line) continue;
    if (line.startsWith("#") || line.startsWith("//")) continue;

    let addrPart = line;
    let remark = "";
    const hashIndex = line.indexOf("#");
    if (hashIndex !== -1) {
      addrPart = line.slice(0, hashIndex);
      // 只按第一个 # 拆分，备注保留后续整段内容
      remark = line.slice(hashIndex + 1);
    }
    addrPart = addrPart.trim();
    remark = remark.trim();

    if (!addrPart) continue;
    // 带 scheme 的伪节点（例如 https://xxx:443）属于广告
    if (addrPart.includes("://")) continue;
    // 广告横幅行
    if (
      remark.includes("▼") ||
      remark.includes("▲") ||
      remark.includes("分享优选网") ||
      remark.includes("分享免费优选网")
    ) {
      continue;
    }
    // CSV 行只取第一列
    if (addrPart.includes(",")) {
      addrPart = addrPart.split(",")[0].trim();
      if (!addrPart) continue;
    }

    const endpoint = parsePreferredEndpoint(addrPart, portMode);
    if (!endpoint) continue;
    if (seen.has(endpoint.hostKey)) continue;
    seen.add(endpoint.hostKey);

    endpoint.remark = cleanRemark(remark, `${endpoint.displayHost}:${endpoint.port}`);
    output.push(endpoint);
  }
}

/**
 * 汇总要拉取的源：鉴权通过后传入的 ?ip_urls= 非空时覆盖默认源，
 * 否则回退环境变量 IP_URLS，最后回退 DEFAULT_IP_URLS。
 */
function buildSourceList(env, querySources) {
  if (Array.isArray(querySources) && querySources.length > 0) {
    return querySources.slice(0, MAX_IP_SOURCES);
  }
  const envSources = splitList(env.IP_URLS).filter(isHttpUrl);
  const list = envSources.length > 0 ? envSources.slice() : DEFAULT_IP_URLS.slice();
  return Array.from(new Set(list)).slice(0, MAX_IP_SOURCES);
}

// ─────────────────────────────────────────────────────────────
// 节点 URI 生成（与 xray_cf_lite.sh 输出保持一致）
// ─────────────────────────────────────────────────────────────

/**
 * 生成 VLESS WS TLS 节点 URI。
 */
function buildVlessUri(uid, domain, path, endpoint, remark) {
  const uriHost = endpoint.isIPv6 ? `[${endpoint.rawHost}]` : endpoint.rawHost;
  return (
    `vless://${uid}@${uriHost}:${endpoint.port}` +
    `?encryption=none&security=tls&sni=${encodeURIComponent(domain)}` +
    `&fp=chrome&type=ws&host=${encodeURIComponent(domain)}` +
    `&path=${encodeURIComponent(path)}#${encodeURIComponent(remark)}`
  );
}

/**
 * 生成 Trojan WS TLS 节点 URI。
 */
function buildTrojanUri(uid, domain, path, endpoint, remark) {
  const uriHost = endpoint.isIPv6 ? `[${endpoint.rawHost}]` : endpoint.rawHost;
  return (
    `trojan://${uid}@${uriHost}:${endpoint.port}` +
    `?security=tls&sni=${encodeURIComponent(domain)}` +
    `&fp=chrome&type=ws&host=${encodeURIComponent(domain)}` +
    `&path=${encodeURIComponent(path)}#${encodeURIComponent(remark)}`
  );
}

/**
 * 生成 VMess WS TLS 节点 URI（JSON 内容整体做 UTF-8 安全 Base64）。
 * vmess 的 add 字段必须是纯 IPv6（不带方括号）。
 */
function buildVmessUri(uid, domain, path, endpoint, remark) {
  const payload = {
    v: "2",
    ps: `${remark}-VMess-WS-TLS`,
    add: endpoint.rawHost,
    port: String(endpoint.port),
    id: uid,
    aid: "0",
    scy: "auto",
    net: "ws",
    type: "none",
    host: domain,
    path: path,
    tls: "tls",
    sni: domain,
    fp: "chrome",
  };
  return `vmess://${utf8ToBase64(JSON.stringify(payload))}`;
}

// ─────────────────────────────────────────────────────────────
// HTTP 响应与鉴权
// ─────────────────────────────────────────────────────────────

/**
 * 订阅响应固定头，保证各客户端能正常识别、显示流量并禁用缓存。
 */
function subscriptionHeaders() {
  return {
    "Content-Type": "text/plain; charset=utf-8",
    "Cache-Control": "no-store",
    "Profile-Update-Interval": "12",
    "Subscription-Userinfo": SUBSCRIPTION_USERINFO,
  };
}

/**
 * 统一响应构造器；HEAD 请求不返回 body。
 */
function respond(request, body, status, extraHeaders) {
  const headers = Object.assign(
    {
      "Content-Type": "text/plain; charset=utf-8",
      "Cache-Control": "no-store",
    },
    extraHeaders || {}
  );
  const finalBody = request && request.method === "HEAD" ? null : body;
  return new Response(finalBody, { status: status || 200, headers });
}

/**
 * 鉴权：env.TOKEN 为空时放行；否则接受 Bearer 或 ?token=，恒定时间比较。
 */
function isAuthorized(request, url, env) {
  const expected = typeof env.TOKEN === "string" ? env.TOKEN : "";
  if (!expected) return true;

  const candidates = [];
  const authorization = (request.headers.get("Authorization") || "").trim();
  const bearerMatch = /^Bearer\s+(.+)$/i.exec(authorization);
  if (bearerMatch) candidates.push(bearerMatch[1].trim());

  const queryToken = url.searchParams.get("token");
  if (queryToken !== null) candidates.push(queryToken);

  let matched = false;
  for (const candidate of candidates) {
    if (timingSafeEqual(candidate, expected)) matched = true;
  }
  return matched;
}

/**
 * 归一化端口策略，非法值返回 null。
 */
function normalizePortMode(value) {
  if (value === "only_443" || value === "all_tls") return value;
  return null;
}

// ─────────────────────────────────────────────────────────────
// 主处理流程
// ─────────────────────────────────────────────────────────────

/**
 * 处理一次 Worker 请求，返回 Response。
 */
async function handleRequest(request, env) {
  const url = new URL(request.url);
  const pathname = url.pathname;

  // 只接受 GET / HEAD
  if (request.method !== "GET" && request.method !== "HEAD") {
    return respond(request, "method not allowed", 405);
  }

  // 健康检查与 favicon：返回固定文本，绝不泄露 TOKEN / IP_URLS
  if (pathname === "/" || pathname === "/health" || pathname === "/favicon.ico") {
    return respond(request, HEALTH_TEXT, 200);
  }

  // 订阅路由：/<uid>/sub
  const routeMatch = /^\/([^/]+)\/sub\/?$/.exec(pathname);
  if (!routeMatch) {
    return respond(request, "not found", 404);
  }

  // 先鉴权，避免未授权者探测 uid / domain 的校验结果
  if (!isAuthorized(request, url, env)) {
    return respond(request, "forbidden", 403);
  }

  // 鉴权通过后才解析 ?ip_urls=，仅接受 https 且通过安全校验的源，去重后最多 32 条
  const querySources = Array.from(
    new Set(
      splitList(url.searchParams.get("ip_urls"))
        .filter((item) => item.startsWith("https://") && isSafeSourceUrl(item))
    )
  );

  // uid 基本校验：8-64 位，仅字母、数字、连字符
  let uid = "";
  try {
    uid = decodeURIComponent(routeMatch[1]);
  } catch {
    return respond(request, "invalid uid", 400);
  }
  if (!/^[A-Za-z0-9-]{8,64}$/.test(uid)) {
    return respond(request, "invalid uid", 400);
  }

  // domain 必填，且必须是合法域名 / IP
  const domainRaw = url.searchParams.get("domain");
  if (domainRaw === null) {
    return respond(request, "missing domain", 400);
  }
  const domain = domainRaw.trim();
  const baseHost = parseHostValue(domain);
  if (!baseHost) {
    return respond(request, "invalid domain", 400);
  }

  // path 归一化：默认 /，缺少前导斜杠时自动补上，剔除控制字符
  let path = url.searchParams.get("path");
  if (path === null) path = DEFAULT_PATH;
  path = path.replace(/[\u0000-\u001F\u007F]/g, "");
  if (!path) path = DEFAULT_PATH;
  if (!path.startsWith("/")) path = `/${path}`;

  // 协议开关：三者都未出现时默认全开，兼容旧客户端；
  // 只要出现任意一个，就按 "yes" 精确判断。
  const hasProtoFlag =
    url.searchParams.has("ev") || url.searchParams.has("et") || url.searchParams.has("mess");
  const enableVless = hasProtoFlag ? url.searchParams.get("ev") === "yes" : true;
  const enableTrojan = hasProtoFlag ? url.searchParams.get("et") === "yes" : true;
  const enableVmess = hasProtoFlag ? url.searchParams.get("mess") === "yes" : true;

  // 三者都显式传了开关却全部未启用（如 ev=no&et=no&mess=no）时明确报错，
  // 避免客户端收到 200 + 空订阅而误判为「订阅失效」。
  if (!enableVless && !enableTrojan && !enableVmess) {
    return respond(request, "no protocol enabled", 400);
  }

  // 端口策略：?port_mode= 优先，其次 env.PORT_MODE，最后默认值
  const portMode =
    normalizePortMode(url.searchParams.get("port_mode")) ||
    normalizePortMode(env.PORT_MODE) ||
    DEFAULT_PORT_MODE;

  // 可选备注前缀：只有显式传入 ?name= 时才加，保证默认输出与本地订阅一致
  const nameParam = url.searchParams.get("name");
  let remarkPrefix = "";
  if (nameParam !== null) {
    const subName = sanitizeName(nameParam) || DEFAULT_SUB_NAME;
    if (subName) remarkPrefix = `${subName}-`;
  }

  // 第一条固定插入原生基准节点
  const endpoints = [];
  const seen = new Set();
  const nativeKey = `${baseHost.raw.toLowerCase()}:${NATIVE_PORT}`;
  seen.add(nativeKey);
  endpoints.push({
    isIPv6: baseHost.kind === "ipv6",
    rawHost: baseHost.raw,
    displayHost: baseHost.display,
    port: NATIVE_PORT,
    hostKey: nativeKey,
    remark: `原生地址-${domain}`,
  });

  // 并发拉取所有源；单源失败 / 超时只跳过，不影响整体
  const sources = buildSourceList(env, querySources);
  if (sources.length > 0) {
    const results = await Promise.allSettled(
      sources.map((sourceUrl) => fetchSource(sourceUrl, FETCH_TIMEOUT_MS))
    );
    for (const result of results) {
      if (result.status === "fulfilled" && result.value) {
        collectEndpoints(result.value, portMode, seen, endpoints);
      }
    }
  }

  // 按协议外层、节点内层的顺序生成，与脚本的协议文件拼接顺序一致
  const uris = [];
  const protocolOrder = [];
  if (enableVless) protocolOrder.push("vless");
  if (enableTrojan) protocolOrder.push("trojan");
  if (enableVmess) protocolOrder.push("vmess");

  for (const protocol of protocolOrder) {
    for (const endpoint of endpoints) {
      const remark = remarkPrefix ? `${remarkPrefix}${endpoint.remark}` : endpoint.remark;
      if (protocol === "vless") {
        uris.push(buildVlessUri(uid, domain, path, endpoint, remark));
      } else if (protocol === "trojan") {
        uris.push(buildTrojanUri(uid, domain, path, endpoint, remark));
      } else if (protocol === "vmess") {
        uris.push(buildVmessUri(uid, domain, path, endpoint, remark));
      }
    }
  }

  const plainText = uris.join("\n");

  // raw=1 或 format=raw：直接返回纯文本 URI 列表，便于排障
  const wantRaw = url.searchParams.get("raw") === "1" || url.searchParams.get("format") === "raw";
  if (wantRaw) {
    return respond(request, plainText, 200, subscriptionHeaders());
  }

  // 标准订阅：整份列表做一次 UTF-8 安全 Base64，单行返回
  return respond(request, utf8ToBase64(plainText), 200, subscriptionHeaders());
}

// ─────────────────────────────────────────────────────────────
// Worker 入口
// ─────────────────────────────────────────────────────────────

export default {
  /**
   * Cloudflare Worker 入口。
   * 顶层 try/catch 保证除显式 400/403/404/405 外不会因异常返回 500。
   */
  async fetch(request, env, ctx) {
    try {
      return await handleRequest(request, env || {});
    } catch {
      // 兜底返回空订阅，避免客户端收到 500
      return respond(request, utf8ToBase64(""), 200, subscriptionHeaders());
    }
  },
};
