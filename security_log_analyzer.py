from collections import defaultdict
import matplotlib.pyplot as plt
import re

# =========================
# 設定
# =========================
LOG_FILE = "/var/log/nginx/access.log"
OUTPUT_FILE = "/var/www/html/index.html"
TOP_N = 10


# =========================
# 集計用データ
# =========================
ip_count = defaultdict(int)
ip_score = defaultdict(int)
status_count = defaultdict(int)
attack_patterns = defaultdict(int)


# =========================
# ログ解析
# =========================
log_pattern = re.compile(
    r'(\S+) .*?"\S+ (.*?) HTTP/.*?" (\d{3})'
)


with open(LOG_FILE) as f:
    for line in f:
        parts = line.split()

        match = log_pattern.match(line)
        if not match:
            continue

        ip = match.group(1)
        url = match.group(2)
        status = match.group(3)

        # =========================
        # 基本アクセス
        # =========================
        ip_count[ip] += 1

        # =========================
        # スコア（重要）
        # =========================
        ip_score[ip] += 1

        if status == "404":
            ip_score[ip] += 2

        if "cgi-bin" in url or "xmlrpc" in url or "env" in url:
            ip_score[ip] += 5

        if "phpunit" in url:
            ip_score[ip] += 10

        # =========================
        # ステータス集計
        # =========================
        status_count[status] += 1

        # ========================
        # 攻撃パターン分類
        # =========================
        if "phpunit" in url:
            attack_patterns["phpunit"] += 1

        elif "laravel" in url:
            attack_patterns["laravel"] += 1

        elif any(x in url for x in ["wp-", "wordpress", "wp-login", "wp-admin"]):
            attack_patterns["wordpress"] += 1

        elif any(x in url for x in ["admin", "login"]):
            attack_patterns["scan"] += 1

        elif any(x in url for x in ["cgi-bin", "xmlrpc", ".env", ".git", "config", "backup"]):
            attack_patterns["scan"] += 1
    
        elif any(x in url for x in [".png", ".jpg", ".css", ".js", "favicon"]):
            continue

        else:
            attack_patterns["unknown"] += 1

 


# =========================
# エラー率計算
# =========================
total = sum(status_count.values())
error = status_count.get("404", 0) + status_count.get("500", 0)
error_rate = (error / total * 100) if total > 0 else 0


# =========================
# スコア正規化（0〜100）
# =========================
max_score = max(ip_score.values()) if ip_score else 1

normalized_scores = {
    ip: int(score / max_score * 100)
    for ip, score in ip_score.items()
}


# =========================
# ランキング作成
# =========================
top_ips = sorted(ip_count.items(), key=lambda x: x[1], reverse=True)[:TOP_N]

attack_ips = sorted(
    ip_score.items(),
    key=lambda x: x[1],
    reverse=True
)[:TOP_N]


# =========================
# グラフ作成
# =========================
ips = [ip for ip, count in top_ips]
counts = [count for ip, count in top_ips]

plt.figure(figsize=(8, 4))
plt.bar(ips, counts)

plt.title("Top IP Access")
plt.xlabel("IP Address")
plt.ylabel("Access Count")

plt.xticks(rotation=45)

plt.tight_layout()
plt.savefig("/var/www/html/ip_chart.png")
plt.close()


# =========================
# HTML生成
# =========================
html = """
<h1>Log Dashboard</h1>

<h2>Top IP Access</h2>
"""

for ip, count in top_ips:
    html += f"<p>{ip} : {count}</p>"


# =========================
# 攻撃IPランキング（スコア）
# =========================
html += "<h2>Top Attack IPs (Risk Score)</h2>"

for ip, score in attack_ips:
    if score >= 80:
        html += f'<p style="color:red; font-weight:bold;">{ip} : {score} (CRITICAL)</p>'
    elif score >= 50:
        html += f'<p style="color:orange;">{ip} : {score} (HIGH)</p>'
    else:
        html += f"<p>{ip} : {score}</p>"


# =========================
# 攻撃パターン分析
# =========================
html += "<h2>Attack Pattern Analysis</h2>"

for pattern, count in attack_patterns.items():
    if count >= 20:
        html += f'<p style="color:red; font-weight:bold;">{pattern} : {count} (HIGH)</p>'
    elif count >= 10:
        html += f'<p style="color:orange;">{pattern} : {count} (MID)</p>'
    else:
        html += f"<p>{pattern} : {count}</p>"


# =========================
# グラフ
# =========================
html += "<h2>IP Access Graph</h2>"
html += '<img src="ip_chart.png" width="600">'


# =========================
# ステータスコード
# =========================
html += "<h2>Status Code Summary</h2>"

for status, count in sorted(status_count.items()):
    if status == "404":
        html += f'<p style="color:red; font-weight:bold;">{status} : {count}</p>'
    else:
        html += f"<p>{status} : {count}</p>"


# =========================
# エラー率
# =========================
if error_rate >= 10:
    html += f'<h2 style="color:red;">Error Rate: {error_rate:.2f}% (CRITICAL)</h2>'
elif error_rate >= 5:
    html += f'<h2 style="color:orange;">Error Rate: {error_rate:.2f}% (WARNING)</h2>'
else:
    html += f'<h2>Error Rate: {error_rate:.2f}%</h2>'


# =========================
# 出力
# =========================
with open(OUTPUT_FILE, "w") as f:
    f.write(html)
