#!/usr/bin/env python3
"""VPS 直连订阅兜底服务（仅标准库）。每次请求读取 state.json，链接不变即生效。"""
import argparse, base64, json, os, re, socket, sys, threading, time, urllib.request
from concurrent.futures import ThreadPoolExecutor
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, quote, unquote, urlparse
TLS_PORTS = {"443", "2053", "2083", "2087", "2096", "8443"}
CACHE, CACHE_LOCK = {}, threading.Lock()
STATE_PATH, FALLBACK_TOKEN = "/etc/xray-cf-lite/state.json", ""
def read_state():
    with open(STATE_PATH, encoding="utf-8") as fh: return json.load(fh)
def port_allowed(port, mode):
    return port == "443" if mode == "only_443" else port in TLS_PORTS
def parse_endpoint(addr):
    if addr.startswith("["):
        match = re.match(r"^\[([0-9a-fA-F:]+)\](?::(\d+))?$", addr)
        if not match: return None
        host, port = match.group(1), match.group(2) or "443"
        display = f"[{host}]"
    else:
        match = re.match(r"^([^:]+):(\d+)$", addr)
        if match: host, port = match.group(1), match.group(2)
        elif ":" in addr: return None
        else: host, port = addr, "443"
        display = host
    if not host or not port.isdigit() or not 1 <= int(port) <= 65535: return None
    return host, str(int(port)), display
def clean_text(text):
    result = []
    for line in text.replace("\r", "").split("\n"):
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("//"): continue
        addr, _, remark = line.partition("#")
        addr, remark = addr.strip(), remark.strip()
        if not addr or "://" in addr: continue
        if any(mark in remark for mark in ("▼", "▲", "分享优选网", "分享免费优选网")): continue
        addr = addr.split(",")[0].strip()
        endpoint = parse_endpoint(addr) if addr else None
        if endpoint:
            host, port, display = endpoint
            result.append((host, port, display, remark or f"{display}:{port}"))
    return result
def fetch_one(url):
    try:
        request = urllib.request.Request(url, headers={"User-Agent": "xray-cf-lite-local-sub/1.0"})
        with urllib.request.urlopen(request, timeout=8) as response:
            return response.read(2 * 1024 * 1024).decode("utf-8", "ignore")
    except Exception as exc:
        print(f"[error] 拉取失败 {url}: {exc}", file=sys.stderr)
        return ""
def get_endpoints(urls):
    key, now = tuple(urls), time.time()
    with CACHE_LOCK:
        hit = CACHE.get(key)
        if hit and now - hit[0] < 300: return hit[1]
    texts = []
    if urls:
        with ThreadPoolExecutor(max_workers=min(8, len(urls))) as pool:
            texts = list(pool.map(fetch_one, urls))
    seen, endpoints = set(), []
    for text in texts:
        for host, port, display, remark in clean_text(text):
            host_key = f"{host.lower()}:{port}"
            if host_key not in seen:
                seen.add(host_key)
                endpoints.append((host, port, display, remark))
    with CACHE_LOCK: CACHE[key] = (now, endpoints)
    return endpoints
def build_uri(proto, uid, domain, path, endpoint):
    host, port, display, remark = endpoint
    query = f"security=tls&sni={domain}&fp=chrome&type=ws&host={domain}&path={quote(path, safe='')}"
    if proto == "vless":
        return f"vless://{uid}@{display}:{port}?encryption=none&{query}#{quote(remark)}"
    if proto == "trojan":
        return f"trojan://{uid}@{display}:{port}?{query}#{quote(remark)}"
    payload = {"v": "2", "ps": f"{remark}-VMess-WS-TLS", "add": host, "port": port, "id": uid,
               "aid": "0", "scy": "auto", "net": "ws", "type": "none", "host": domain,
               "path": path, "tls": "tls", "sni": domain, "fp": "chrome"}
    return "vmess://" + base64.b64encode(json.dumps(payload, ensure_ascii=False).encode()).decode()
class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args): pass
    def reply(self, status, body):
        data = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)
    def do_GET(self):
        parsed = urlparse(self.path)
        match = re.match(r"^/([^/]+)/sub/?$", parsed.path)
        if not match: return self.reply(404, "not found")
        try: state = read_state()
        except Exception as exc:
            print(f"[error] 读取 state 失败: {exc}", file=sys.stderr)
            return self.reply(500, "state error")
        expected = state.get("sub_token") or FALLBACK_TOKEN
        if not expected:
            return self.reply(403, "未设置订阅密钥: 请运行 x 进入 9 -> 4 设置，或使用 --token / LOCAL_SUB_TOKEN")
        if unquote(match.group(1)) != expected: return self.reply(403, "forbidden")
        query, routes = parse_qs(parsed.query), state.get("routes") or []
        paths = {r.get("protocol"): r.get("path") or "/" for r in routes}
        requested = query.get("proto", [""])[0]
        if requested in ("vless", "trojan", "vmess"): protos = [requested]
        elif requested in ("", "all"):
            protos = [r.get("protocol") for r in routes if r.get("protocol")] or ["vless", "trojan", "vmess"]
        else: return self.reply(400, "invalid proto")
        domain, uid = state.get("domain"), state.get("uuid")
        if not domain or not uid: return self.reply(500, "state missing domain/uuid")
        mode = state.get("port_mode") or "all_tls"
        native_key = f"{domain.lower()}:443"
        endpoints = [(domain, "443", domain, f"原生地址-{domain}")]
        endpoints += [item for item in get_endpoints(state.get("ip_urls") or [])
                      if port_allowed(item[1], mode) and f"{item[0].lower()}:{item[1]}" != native_key]
        lines = [build_uri(proto, uid, domain, paths.get(proto, "/"), item)
                 for proto in protos for item in endpoints]
        text = "\n".join(lines)
        if query.get("raw", [""])[0] == "1": return self.reply(200, text)
        return self.reply(200, base64.b64encode(text.encode()).decode())
def port_in_use(port):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        try: sock.bind(("0.0.0.0", port))
        except OSError: return True
    return False
def main():
    global STATE_PATH, FALLBACK_TOKEN
    parser = argparse.ArgumentParser(description="xray-cf-lite VPS 直连订阅服务")
    parser.add_argument("--port", type=int, default=int(os.environ.get("LOCAL_SUB_PORT", "18080")))
    parser.add_argument("--state", default=os.environ.get("XRAY_CF_LITE_STATE_FILE", "/etc/xray-cf-lite/state.json"))
    parser.add_argument("--token", default=os.environ.get("LOCAL_SUB_TOKEN", ""))
    args = parser.parse_args()
    STATE_PATH, FALLBACK_TOKEN = args.state, args.token
    if port_in_use(args.port):
        print(f"[error] 端口 {args.port} 已被占用，请更换 --port 后重试", file=sys.stderr)
        return 1
    server = ThreadingHTTPServer(("0.0.0.0", args.port), Handler)
    server.daemon_threads = True
    print(f"local_sub_server 已启动: http://0.0.0.0:{args.port}/<token>/sub (state={STATE_PATH})")
    try: server.serve_forever()
    except KeyboardInterrupt: print("local_sub_server 已停止")
    finally: server.server_close()
    return 0
if __name__ == "__main__":
    sys.exit(main())
