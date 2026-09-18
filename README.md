# CF RU Proxy Collector

从 FOFA 搜索结果中收集俄罗斯 Cloudflare 反向代理节点，并自动验证可用性。

## 工作流程

1. **抓取** — `parsefofahtml_ru.py` 通过 FOFA 网页搜索（HTML 抓取，不消耗 F 点），多轮排除已抓 IP，每轮 50 条，默认 5 轮 = 250 条
2. **验证** — `cfproxiesvalidator.py` 用 `curl --resolve` 向每个 IP 发 HTTPS 请求到 `/cdn-cgi/trace`，检测是否为可用 CF 反代
3. **输出** — 验证通过的代理写入 `https_proxy.txt`，中转代理写入 `middle_proxy.txt`，详细数据写入 `fofa_results_ru.csv`

## FOFA 查询条件

```
server=="cloudflare" && country=="RU" && region!="HK" && region!="MO"
&& region!="TW" && asn!="209242" && is_domain=false && status_code="403"
&& (tls.version=="TLS 1.3" || tls.version=="TLS 1.2")
```

筛选逻辑：
- `country=="RU"` — 俄罗斯节点
- `server=="cloudflare"` — CF 反代
- `asn!="209242"` — 排除 Cloudflare 自有 ASN
- `is_domain=false` — 只要 IP，不要域名
- `status_code="403"` — CF 默认拦截页
- `tls.version` — TLS 1.2/1.3 节点（HTTPS 端口）

## GitHub Actions

仓库包含定时 workflow（`.github/workflows/collect.yml`）：
- **定时触发**：每天 UTC 04:00（北京时间 12:00）
- **手动触发**：Actions 页面点 "Run workflow"
- **输出**：结果自动 commit 到 `results/` 目录

## Secrets 配置

需要在仓库 Settings → Secrets 中设置：

| Secret | 说明 |
|--------|------|
| `FOFA_COOKIE` | FOFA 登录 Cookie（从浏览器复制完整的 Cookie 头） |

## 本地运行

```bash
# 安装依赖
pip install -r requirements.txt

# 把 FOFA Cookie 写入 cookie.txt
echo "你的FOFA_COOKIE值" > cookie.txt

# 抓取 5 轮（约 250 条）
python3 parsefofahtml_ru.py --rounds 5

# 验证
python3 cfproxiesvalidator.py
```

## 输出文件

| 文件 | 格式 | 说明 |
|------|------|------|
| `ips_ru.txt` | `IP:port:https` | 抓到的全部 IP，供验证器使用 |
| `fofa_results_ru.csv` | CSV | 详细字段（IP、端口、地理位置、ASN、组织、TLS、Header） |
| `https_proxy.txt` | `IP:port` | 验证通过的可代理 |
| `middle_proxy.txt` | 文本 | 中转代理（入口 IP ≠ 落地 IP） |
