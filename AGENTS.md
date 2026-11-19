# AGENTS.md

供 AI / 维护者使用的技术说明。**用户文档在 README.md，不要往 README 里塞实现细节。**

## 仓库结构

- `xray_cf_lite.sh`：主脚本，单文件 Bash，Linux 端运行
- `cf_sub_worker.js`：可选的 Cloudflare Worker 订阅服务，ES Module 单文件
- `README.md`：面向用户的安装与使用说明
- `docs/reviews/REV-00{1..4}.md`：历史独立审查报告

## 运行约束

- 主脚本必须保持纯 LF，UTF-8 无 BOM
- 支持四种启动方式：`bash x.sh`、`bash <(curl ...)`、`bash -s < x.sh`、`curl ... | bash`
- 入口守卫使用 `${BASH_SOURCE[0]:-$0}`，以兼容 `set -u`

## 关键状态文件

- `/etc/xray-cf-lite/state.json`（600）：`domain` `zone_id` `uuid` `short_id` `net_mode` `routes[]`（`protocol`/`listen_port`/`cf_port`/`path`）`managed_dns_record_id` `dns_backup` `ssl_backup` `origin_rules_backup` `security_backup` `links{}` `sub_base` `sub_token` `port_mode` `ip_urls[]` `local_sub_count` `local_sub_updated_at` `local_sub_url`
- `/etc/xray-cf-lite/cf_account.json`（600）：`email` `api_key`
- `/etc/xray-cf-lite/local_sub/`（700）：`nodes_all.txt` `sub_all_base64.txt` `nodes_<proto>.txt` `sub_<proto>_base64.txt`
- `./cf_lite_last_links.txt`（600）：订阅链接快照

**红线**：任何写回 `state.json` 的路径都必须保留 `dns_backup` / `ssl_backup` / `origin_rules_backup` / `security_backup`，否则卸载无法回滚 Cloudflare。

## 菜单结构

主菜单：1 安装 / 2 卸载 / 3 查看订阅 / 4 修改配置 / 5 查看当前配置 / 6 更新外部端口 / 7 重启 xray / 8 切换网络模式 / 9 订阅与优选 IP 管理 / 0 退出

菜单 9 子项：1 立即拉取优选 IP / 2 管理优选源 / 3 切换端口策略 / 4 更换远程订阅地址与密钥 / 5 固化或更新快捷命令 x / 0 返回

菜单 9 全部分支**不得**调用 `cf_call`、`cf_call_raw`、`load_cf_account`（免 CF API 的约定）。

## 默认优选源

1. https://raw.githubusercontent.com/gshtwy/CF-DNS-Clone/refs/heads/main/wetest-cloudflare-v4.txt
2. https://edt-aio-nav.pages.dev/cm/ct_50.txt
3. https://edt-aio-nav.pages.dev/wetest/ipv4.txt
4. https://edt-aio-nav.pages.dev/domain/all.txt

行格式兼容：`IP:port#备注`、`域名:port#备注`、`[IPv6]:port`、CSV 首列、无端口默认 443。
清洗：跳过空行/`#` 与 `//` 注释/含 `://` 的广告行/含 `▼▲`、`分享优选网` 的横幅行；按 `host:port` 去重。
端口策略：`all_tls` = 443/2053/2083/2087/2096/8443；`only_443` = 仅 443。

## 订阅链接契约

`<sub_base>/<uuid>/sub?domain=<domain>&ev=<yes|no>&et=<yes|no>&mess=<yes|no>&path=<urlencoded>&port_mode=<all_tls|only_443>[&ip_urls=<urlencoded 逗号分隔>][&token=<urlencoded>]`

`epd/epi/egi/dkby` 已不再生成。
`ip_urls` 仅在鉴权通过后生效，覆盖 Worker 默认源；`port_mode` 查询参数优先于环境变量。
节点模板：统一 TLS + WS，`sni`/`host` = 域名，端口来自优选源；VMess 的 `add` 不带 IPv6 方括号。

## Worker 说明

- 路由 `/<uid>/sub`；`/`、`/health`、`/favicon.ico` 返回固定文本且不得泄露 `TOKEN`
- 鉴权：`Authorization: Bearer <TOKEN>` 或 `?token=`，恒定时间比较
- 源列表默认来自 `DEFAULT_IP_URLS` 或 `env.IP_URLS`；鉴权通过后可由 `?ip_urls=` 覆盖（仅 https、过 `isSafeSourceUrl`、去重、上限 32 条）
- `redirect: "manual"`，每跳复检，最多 3 跳
- 拒绝私网/环回/链路本地/保留地址与回环别名域名
- 单源响应体上限 2 MiB；`Promise.allSettled` 单源失败不影响其余
- `ev/et/mess` 全缺省 = 三协议全开；显式全为 `no` = 400

## 门禁命令

- `bash -n xray_cf_lite.sh`
- `node --check cf_sub_worker.js`（ESM）
- `git diff --check`
- 沙盒测试使用 `XRAY_CF_LITE_STATE_DIR` / `XRAY_CF_LITE_LAST_LINKS_PATH` / `XRAY_CF_LITE_SHORTCUT_PATH` / `XRAY_CF_LITE_RAW_URL`，禁止写系统 `/etc`、`/usr/local`

## 文档约定

- `README.md` 只写用户视角：装什么、跑什么、看到什么。禁止出现函数名、内部参数名、第三方源 URL、状态字段名
- 技术细节一律写入本文件
- 新增功能先更新本文件，再决定 README 是否需要一句话提及

## VPS 直连订阅
- `local_sub_server.py`：仅标准库、每请求重读 state.json；默认端口 18080；token 取 state.sub_token，缺省用 `--token` / `LOCAL_SUB_TOKEN`
- 端点按源列表元组缓存，TTL 300s，端口过滤在渲染时执行；`local_sub_server.service.example` 为 systemd 模板
- Worker 的 `?ip_urls=` 在鉴权通过后生效（仅 https、过 `isSafeSourceUrl`、上限 32），非空时覆盖 env.IP_URLS 与默认源

## 一键订阅服务
- `install_local_sub_server`：菜单 9→6，装 python3、下载/复制 py、写 systemd/OpenRC、启动、自检并打印订阅地址
- 端口存 `sub_serve_port`（缺省 18080），服务名 `cflite-sub`；测试用 `XRAY_CF_LITE_SYSTEMD_DIR` / `XRAY_CF_LITE_INITD_DIR` / `XRAY_CF_LITE_SKIP_SERVICE=1` 重定向并跳过 systemctl/rc-*
