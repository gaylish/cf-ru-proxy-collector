#!/usr/bin/env python3
"""
FOFA 搜索结果 HTML 解析器（俄罗斯节点）

从 FOFA 网页搜索结果中提取 IP、端口、地理位置、ASN、组织、TLS 版本、Header 等字段。
FOFA 使用 Nuxt SSR，HTML 中包含完整渲染数据，无需 JS 执行。

多轮抓取策略：
  每轮把已抓到的 IP 加入查询条件排除掉（ip!="x.x.x.x"），重新搜索拿到新数据。
  这样始终请求第 1 页，避免翻页问题，且每轮都能拿到全新的 IP。

用法:
  python3 parsefofahtml_ru.py                            # 默认查询，1轮
  python3 parsefofahtml_ru.py --rounds 10                # 抓10轮（约500条）
  python3 parsefofahtml_ru.py --query 'server=="cloudflare"' --rounds 5
  python3 parsefofahtml_ru.py --output ips_ru.txt        # 指定输出文件

Cookie 来源（按优先级）:
  1. 环境变量 FOFA_COOKIE — GitHub Actions 使用此方式
  2. cookie.txt 文件 — 本地使用
"""

import argparse
import base64
import csv
import os
import re
import sys
import time

import requests
from bs4 import BeautifulSoup

# ===== 默认配置 =====
DEFAULT_QUERY = (
    'server=="cloudflare" && country=="RU" && region!="HK" && region!="MO" '
    '&& region!="TW" && asn!="209242" && is_domain=false && status_code="403" '
    '&& (tls.version=="TLS 1.3" || tls.version=="TLS 1.2")'
)
DEFAULT_ROUNDS = 1
DEFAULT_OUTPUT = "ips_ru.txt"
COOKIE_FILE = "cookie.txt"
PAGE_SIZE = 50          # FOFA 网页每页 50 条
MAX_QUERY_LEN = 5000    # FOFA 限制原始查询长度（解码后）约 5000 字符，非 base64 或 URL 长度
SLEEP_BETWEEN = 10      # 每轮间隔秒数


def read_cookie(path=COOKIE_FILE):
    """从环境变量或文件读取 Cookie"""
    # 优先读环境变量（GitHub Actions）
    env_cookie = os.environ.get("FOFA_COOKIE", "").strip()
    if env_cookie:
        return env_cookie
    # 退回文件
    if not os.path.exists(path):
        print(f"[!] 找不到 {path}，且环境变量 FOFA_COOKIE 未设置")
        sys.exit(1)
    with open(path, "r", encoding="utf-8") as f:
        cookie = f.read().strip()
    if not cookie:
        print(f"[!] {path} 内容为空")
        sys.exit(1)
    return cookie


def build_url(query):
    """构建 FOFA 搜索 URL（始终第 1 页）"""
    qbase64 = base64.b64encode(query.encode("utf-8")).decode("utf-8")
    return f"https://fofa.info/result?qbase64={qbase64}"


def build_query_with_exclusions(base_query, seen_ips):
    """
    在基础查询上追加 IP 排除条件。
    例: ... && ip!="1.2.3.4" && ip!="5.6.7.8"
    """
    if not seen_ips:
        return base_query
    exclusions = " && ".join(f'ip!="{ip}"' for ip in sorted(seen_ips))
    return f"{base_query} && {exclusions}"


def fetch_page(url, cookie, max_retries=3):
    """请求 FOFA 页面，返回 HTML 文本。带限流检测和重试。"""
    headers = {
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "zh-CN,zh;q=0.9,en-US;q=0.8,en;q=0.7",
        "Cache-Control": "no-cache",
        "Connection": "keep-alive",
        "DNT": "1",
        "User-Agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/153.0.0.0 Safari/537.36"
        ),
        "Cookie": cookie,
    }
    for attempt in range(1, max_retries + 1):
        try:
            resp = requests.get(url, headers=headers, timeout=30)
            if resp.status_code == 200:
                # 检测限流: FOFA 返回 "[45012] 请求速度过快"
                if "45012" in resp.text or "请求速度过快" in resp.text:
                    wait = 15 * attempt
                    print(f"  [!] FOFA 限流，等待 {wait}s 后重试 ({attempt}/{max_retries})")
                    time.sleep(wait)
                    continue
                return resp.text
            elif resp.status_code == 429:
                wait = 15 * attempt
                print(f"  [!] HTTP 429 限流，等待 {wait}s 后重试 ({attempt}/{max_retries})")
                time.sleep(wait)
                continue
            elif resp.status_code == 403:
                print(f"  [!] 403 被拒绝（Cookie 可能失效）")
            else:
                print(f"  [!] HTTP {resp.status_code}")
        except requests.exceptions.RequestException as e:
            wait = 10 * attempt
            print(f"  [!] 请求失败 ({attempt}/{max_retries}): {e}")
            if attempt < max_retries:
                print(f"  等待 {wait}s 后重试...")
                time.sleep(wait)
    return ""


def parse_html(html):
    """
    解析 FOFA SSR HTML，提取每条结果的字段。

    FOFA 使用 Nuxt SSR，结果在 <div class="hsxa-meta-data-item"> 中。
    """
    soup = BeautifulSoup(html, "html.parser")
    items = soup.find_all("div", class_="hsxa-meta-data-item")
    results = []

    for item in items:
        # IP: .hsxa-ip a.hsxa-jump-a
        ip_tag = item.select_one(".hsxa-ip a.hsxa-jump-a")
        ip = ip_tag.get_text(strip=True) if ip_tag else ""

        # 端口: .hsxa-port
        port_tag = item.select_one(".hsxa-port")
        port = port_tag.get_text(strip=True) if port_tag else ""

        # 地理位置: .hsxa-one-line a.hsxa-jump-a (href 含 country/region/city 的 base64)
        country = region = city = ""
        for a in item.select(".hsxa-one-line a.hsxa-jump-a"):
            href = a.get("href", "")
            text = a.get_text(strip=True)
            if "Y291bnRye" in href:      # country=
                country = text
            elif "cmVnaW9u" in href:      # region=
                region = text
            elif "Y2l0eQ" in href:        # city=
                city = text

        # ASN: a[href*="YXNu"]  (YXNu = base64("asn"))
        asn_tag = item.select_one('a[href*="YXNu"]')
        asn = asn_tag.get_text(strip=True) if asn_tag else ""

        # 组织: a[href*="b3Jn"]  (b3Jn = base64("org"))
        org_tag = item.select_one('a[href*="b3Jn"]')
        org = org_tag.get_text(strip=True) if org_tag else ""

        # TLS 版本: a[href*="dGxzLnZlcnNpb24"]  (dGxzLnZlcnNpb24 = base64("tls.version"))
        tls_tag = item.select_one('a[href*="dGxzLnZlcnNpb24"]')
        tls = tls_tag.get_text(strip=True) if tls_tag else ""

        # Header: .hsxa-body-content span
        header_tag = item.select_one(".hsxa-body-content span")
        header = header_tag.get_text(strip=True) if header_tag else ""

        # 产品/组件: .hsxa-list-span span
        product_spans = item.select(".hsxa-list-span span")
        products = [s.get_text(strip=True) for s in product_spans if s.get_text(strip=True)]

        # 协议判断: FOFA 查询已筛选 TLS 1.2/1.3 节点，这些节点是 HTTPS 端口
        # 之前误判为 http 导致验证器发 HTTP 到 HTTPS 端口，全部 400 失败
        proto = "https"

        if ip and port:
            results.append({
                "ip": ip,
                "port": port,
                "proto": proto,
                "country": country,
                "region": region,
                "city": city,
                "asn": asn,
                "org": org,
                "tls": tls,
                "products": ",".join(products),
                "header": header,
            })

    return results


def dedup(results):
    """按 ip:port 去重"""
    seen = {}
    for r in results:
        key = f'{r["ip"]}:{r["port"]}'
        if key not in seen:
            seen[key] = r
    return list(seen.values())


def write_ips_txt(results, path):
    """写入 ips.txt，格式: ip:port:proto（供 cfproxiesvalidator.py 使用）"""
    with open(path, "w", encoding="utf-8") as f:
        for r in results:
            f.write(f'{r["ip"]}:{r["port"]}:{r["proto"]}\n')
    print(f"[+] 已写入 {len(results)} 条到 {path} (格式: ip:port:proto)")


def write_csv(results, path):
    """写入详细 CSV"""
    fields = ["ip", "port", "proto", "country", "region", "city", "asn", "org", "tls", "products", "header"]
    with open(path, "w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        writer.writerows(results)
    print(f"[+] 已写入详细信息到 {path}")


def main():
    parser = argparse.ArgumentParser(description="FOFA HTML 解析器（俄罗斯节点，多轮排除抓取）")
    parser.add_argument("--query", default=DEFAULT_QUERY, help="FOFA 基础查询语句")
    parser.add_argument("--rounds", type=int, default=DEFAULT_ROUNDS,
                        help=f"抓取轮数，每轮把已抓 IP 排除后重新搜（默认 {DEFAULT_ROUNDS}）")
    parser.add_argument("--output", default=DEFAULT_OUTPUT, help="输出 ips_ru.txt 路径")
    parser.add_argument("--csv", default="fofa_results_ru.csv", help="输出 CSV 路径")
    parser.add_argument("--sleep", type=float, default=SLEEP_BETWEEN, help="每轮间隔秒数")
    args = parser.parse_args()

    cookie = read_cookie()
    base_query = args.query

    print(f"[*] 基础查询: {base_query}")
    print(f"[*] 抓取轮数: {args.rounds}")
    print(f"[*] 策略: 每轮把已抓 IP 加入排除条件，重新搜第 1 页拿新数据\n")

    all_results = []
    seen_ips = set()       # 用于排除的 IP 集合
    seen_keys = set()      # 用于去重的 ip:port 集合

    for rnd in range(1, args.rounds + 1):
        # 构建带排除条件的查询
        query = build_query_with_exclusions(base_query, seen_ips)

        # 检查查询长度
        if len(query) > MAX_QUERY_LEN:
            print(f"[!] 第 {rnd} 轮: 查询长度 {len(query)} 超过上限 {MAX_QUERY_LEN}，停止")
            break

        url = build_url(query)
        print(f"[+] 第 {rnd}/{args.rounds} 轮 | 已排除 {len(seen_ips)} 个 IP | 查询长度 {len(query)}")

        html = fetch_page(url, cookie)
        if not html:
            print(f"  [!] 无内容，跳过")
            break

        results = parse_html(html)
        print(f"  解析出 {len(results)} 条")

        if not results:
            print(f"  [!] 无新数据，停止")
            break

        # 累积结果 + 更新排除集
        new_count = 0
        for r in results:
            key = f'{r["ip"]}:{r["port"]}'
            if key not in seen_keys:
                seen_keys.add(key)
                all_results.append(r)
                new_count += 1
            seen_ips.add(r["ip"])

        print(f"  新增 {new_count} 条，累计 {len(all_results)} 条，排除 {len(seen_ips)} 个 IP")

        if rnd < args.rounds:
            time.sleep(args.sleep)

    if not all_results:
        print("[!] 未解析到任何结果")
        return

    print(f"\n[+] 总计 {len(all_results)} 条（去重后）")

    # 输出
    write_ips_txt(all_results, args.output)
    write_csv(all_results, args.csv)

    # 终端预览
    print(f"\n{'#':<4} {'IP':<18} {'Port':<7} {'Location':<20} {'ASN':<7} {'TLS':<8} {'Org'}")
    print("-" * 100)
    for i, r in enumerate(all_results[:30]):
        loc = f'{r["country"]} / {r["region"]} / {r["city"]}'
        print(f'{i+1:<4} {r["ip"]:<18} {r["port"]:<7} {loc:<20} {r["asn"]:<7} {r["tls"]:<8} {r["org"]}')
    if len(all_results) > 30:
        print(f"... 还有 {len(all_results) - 30} 条，详见 {args.csv}")


if __name__ == "__main__":
    main()
