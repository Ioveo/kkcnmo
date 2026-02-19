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
#  SYSTEM ASSET INTEGRITY AUDITOR (SAIA) v15.0
# ============================================================

# --- 路径与系统配置文件 (已更名) ---
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
STATE_FILE = os.path.join(BASE_DIR, "sys_audit_state.json")
LOG_FILE = os.path.join(BASE_DIR, "sys_audit_events.log")
REPORT_FILE = os.path.join(BASE_DIR, "audit_report.log")
NODE_FILE = os.path.join(BASE_DIR, "nodes.list")  # 对应原来的 IP.TXT
TOKEN_FILE = os.path.join(BASE_DIR, "tokens.list")  # 对应原来的 pass.txt
GUARDIAN_STATE_FILE = os.path.join(BASE_DIR, "sys_guardian_state.json")
DEFAULT_PORTS = "1080-1090,1111,2222,3333,4444,5555,6666,7777,8888,9999"

# --- 视觉配置 (采用稳重的企业蓝绿配色) ---
C_BOLD, C_W = "\033[1m", "\033[0m"
C_BLUE = "\033[38;5;33m"  # 稳定蓝
C_CYAN = "\033[38;5;51m"  # 亮青
C_PROC = "\033[38;5;42m"  # 审计绿
C_FIND = "\033[38;5;220m"  # 节点金
C_SUCC = "\033[38;5;46m"  # 验证绿
C_Y = "\033[38;5;226m"  # 警示黄
C_DIM = "\033[2m"
C_HIDE, C_SHOW = "\033[?25l", "\033[?25h"

# ==================== 状态同步引擎 (去敏感化) ====================


def now_ts() -> float:
    return time.time()


async def close_writer(writer) -> None:
    if writer is None:
        return
    writer.close()
    try:
        await writer.wait_closed()
    except OSError:
        pass


def fmt_time(ts: float) -> str:
    try:
        return datetime.fromtimestamp(float(ts)).strftime("%Y-%m-%d %H:%M:%S")
    except (TypeError, ValueError, OSError):
        return "-"


def load_sys_state() -> dict:
    if not os.path.exists(STATE_FILE):
        return {}
    try:
        with open(STATE_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except (OSError, json.JSONDecodeError):
        return {}


def load_guardian_state() -> dict:
    if not os.path.exists(GUARDIAN_STATE_FILE):
        return {}
    try:
        with open(GUARDIAN_STATE_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except (OSError, json.JSONDecodeError):
        return {}


def save_guardian_state(state: dict) -> None:
    tmp = GUARDIAN_STATE_FILE + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(state, f, ensure_ascii=False, indent=2)
    os.replace(tmp, GUARDIAN_STATE_FILE)


def save_sys_state(state: dict) -> None:
    tmp = STATE_FILE + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(state, f, ensure_ascii=False, indent=2)
    os.replace(tmp, STATE_FILE)


def log_audit_event(msg: str) -> None:
    line = f"[{fmt_time(now_ts())}] {msg}\n"
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(line)


def is_node_alive(pid: int) -> bool:
    if pid <= 0:
        return False
    try:
        os.kill(pid, 0)
        return True
    except OSError:
        return False


def clear_terminal() -> None:
    os.system("cls" if os.name == "nt" else "clear")


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
            avail_bytes = page_size * (free_pages + inactive_pages + cache_pages)
            return avail_bytes / 1024 / 1024
        except (OSError, ValueError, subprocess.SubprocessError):
            return None

    return None


def parse_ports(ports_raw: str) -> list[int]:
    ports = []
    for chunk in ports_raw.split(","):
        part = chunk.strip()
        if not part:
            continue
        if "-" in part:
            start_s, end_s = part.split("-", 1)
            start, end = int(start_s), int(end_s)
            if start > end:
                start, end = end, start
            for p in range(start, end + 1):
                if 1 <= p <= 65535:
                    ports.append(p)
        else:
            p = int(part)
            if 1 <= p <= 65535:
                ports.append(p)
    return sorted(set(ports))


def iter_nodes_from_entry(entry: str):
    value = entry.strip()
    if not value or value.startswith("#"):
        return

    if "/" in value:
        network = ipaddress.ip_network(value, strict=False)
        for host in network.hosts():
            yield str(host)
        return

    if "-" in value:
        start_raw, end_raw = value.split("-", 1)
        start_ip = ipaddress.ip_address(start_raw.strip())
        end_ip = ipaddress.ip_address(end_raw.strip())
        if start_ip.version != end_ip.version:
            raise ValueError(f"IP 段版本不一致: {value}")
        start_int = int(start_ip)
        end_int = int(end_ip)
        if start_int > end_int:
            start_int, end_int = end_int, start_int
        for ip_int in range(start_int, end_int + 1):
            yield str(ipaddress.ip_address(ip_int))
        return

    try:
        yield str(ipaddress.ip_address(value))
    except ValueError:
        # 允许主机名目标
        yield value


def prompt_int(
    msg: str, default: int, min_value: int = None, max_value: int = None
) -> int:
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


def prompt_float(msg: str, default: float, min_value: float = None) -> float:
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


def read_last_lines(file_path: str, lines: int = 50) -> str:
    if not os.path.exists(file_path):
        return ""
    with open(file_path, "r", encoding="utf-8", errors="replace") as f:
        data = f.readlines()
    return "".join(data[-lines:])


def build_audit_cmd(mode, threads, ports_str, feed_interval):
    return [
        sys.executable,
        os.path.abspath(__file__),
        "run_audit",
        str(mode),
        str(threads),
        ports_str,
        str(feed_interval),
    ]


def spawn_audit_process(mode, threads, ports_str, feed_interval):
    cmd = build_audit_cmd(mode, threads, ports_str, feed_interval)
    return subprocess.Popen(
        cmd,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        stdin=subprocess.DEVNULL,
        start_new_session=True,
    )


def run_guardian_process(
    mode, threads, ports_str, feed_interval, min_free_mb, check_interval
):
    state = {
        "status": "running",
        "pid": os.getpid(),
        "mode": mode,
        "threads": threads,
        "ports": ports_str,
        "feed_interval": feed_interval,
        "min_free_mb": min_free_mb,
        "check_interval": check_interval,
        "started_at": now_ts(),
        "updated_at": now_ts(),
        "last_action": "guardian started",
    }
    save_guardian_state(state)
    log_audit_event("Guardian started.")

    last_start_ts = 0.0
    min_restart_gap = 15.0

    try:
        while True:
            sys_state = load_sys_state()
            active = (
                is_node_alive(sys_state.get("pid", 0))
                and sys_state.get("status") == "running"
            )
            mem_mb = get_available_memory_mb()
            now = now_ts()
            action = "watching"

            if not active:
                if mem_mb is not None and mem_mb < min_free_mb:
                    action = f"low memory ({mem_mb:.0f}MB), waiting"
                elif now - last_start_ts < min_restart_gap:
                    action = "restart cooldown"
                else:
                    proc = spawn_audit_process(mode, threads, ports_str, feed_interval)
                    last_start_ts = now
                    action = f"audit restarted (pid={proc.pid})"
                    log_audit_event(
                        f"Guardian auto-started audit pid={proc.pid}, free_mem={mem_mb:.0f}MB"
                        if mem_mb is not None
                        else f"Guardian auto-started audit pid={proc.pid}"
                    )

            state["updated_at"] = now
            state["last_action"] = action
            state["last_free_mb"] = round(mem_mb, 2) if mem_mb is not None else None
            save_guardian_state(state)
            time.sleep(check_interval)
    finally:
        state["status"] = "stopped"
        state["updated_at"] = now_ts()
        state["last_action"] = "guardian stopped"
        save_guardian_state(state)
        log_audit_event("Guardian stopped.")


# ==================== 审计核心逻辑 (逻辑不变，描述更名) ====================


async def accepts_random_credentials(ip, port):
    """是否错误地接受随机账号密码。"""
    writer = None
    try:
        r, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port), timeout=2.0
        )
        writer.write(b"\x05\x01\x02")
        await writer.drain()
        await r.read(2)
        u, p = (
            "".join(random.choices(string.ascii_letters, k=8)),
            "".join(random.choices(string.digits, k=8)),
        )
        writer.write(
            b"\x01" + bytes([len(u)]) + u.encode() + bytes([len(p)]) + p.encode()
        )
        await writer.drain()
        res = await asyncio.wait_for(r.read(2), timeout=2.0)
        return res and res[1] == 0x00
    except (asyncio.TimeoutError, OSError, ValueError):
        return False
    finally:
        await close_writer(writer)


async def measure_response_time(reader, writer):
    """测量端到端连通性延迟"""
    try:
        start = time.perf_counter()
        writer.write(b"\x05\x01\x00\x01\x01\x01\x01\x01\x00\x50")
        await writer.drain()
        res = await asyncio.wait_for(reader.read(10), timeout=2.5)
        if res and res[1] == 0x00:
            return int((time.perf_counter() - start) * 1000)
    except (asyncio.TimeoutError, OSError):
        pass
    return None


async def audit_node_integrity(ip, port, tokens, mode, state):
    state["current"] = f"Auditing Node -> {ip}:{port}"
    writer = None
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port), timeout=3.0
        )
        writer.write(b"\x05\x02\x00\x02")
        await writer.drain()
        res = await asyncio.wait_for(reader.read(2), timeout=2.0)
        if not res or res[0] != 5:
            return None

        method = res[1]
        if method == 0x00:  # 公共接入节点
            if mode == 3:
                return None
            if await accepts_random_credentials(ip, port):
                return None
            r2, w2 = await asyncio.wait_for(
                asyncio.open_connection(ip, port), timeout=2.5
            )
            w2.write(b"\x05\x01\x00")
            await w2.drain()
            await r2.read(2)
            lat = await measure_response_time(r2, w2)
            await close_writer(w2)
            if lat is not None:
                state["verified"] += 1
                return f"Node[Public]: {ip}:{port} | RTT: {lat}ms"

        if method == 0x02 and tokens:  # 受控接入节点
            for u, p in tokens:
                w3 = None
                try:
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
                        lat = await measure_response_time(r3, w3)
                        await close_writer(w3)
                        if lat is not None:
                            state["verified"] += 1
                            return f"Node[Secure]: {u}@{ip}:{port} | RTT: {lat}ms"
                    await close_writer(w3)
                except (asyncio.TimeoutError, OSError, ValueError):
                    await close_writer(w3)
                    continue
    except (asyncio.TimeoutError, OSError, ValueError):
        pass
    finally:
        await close_writer(writer)
    return None


# ==================== 调度器后端 (去敏感化) ====================


async def internal_audit_process(
    node_source_file, ports, tokens, mode, threads, queue_size=200, feed_interval=0.005
):
    state = {
        "status": "running",
        "pid": os.getpid(),
        "total": 0,
        "done": 0,
        "reachable": 0,
        "verified": 0,
        "current": "Loading targets...",
        "started_at": now_ts(),
        "updated_at": now_ts(),
        "recent": [],
        "mode": mode,
    }
    save_sys_state(state)
    log_audit_event("Audit session started.")

    node_queue = asyncio.Queue(maxsize=queue_size)
    state_lock = asyncio.Lock()

    async def producer_worker():
        emitted = 0
        with open(node_source_file, "r", encoding="utf-8", errors="replace") as f:
            for line_no, raw in enumerate(f, start=1):
                line = raw.strip()
                if not line or line.startswith("#"):
                    continue
                try:
                    for node in iter_nodes_from_entry(line):
                        await node_queue.put(node)
                        emitted += 1
                        async with state_lock:
                            state["total"] += 1
                            state["current"] = f"Feeding target -> {node}"
                            state["updated_at"] = now_ts()
                            if state["total"] % 50 == 0:
                                save_sys_state(state)
                        if feed_interval > 0:
                            await asyncio.sleep(feed_interval)
                except ValueError as exc:
                    log_audit_event(f"Skip line {line_no}: {exc}")
                    continue

        for _ in range(threads):
            await node_queue.put(None)
        log_audit_event(f"Target feeding completed. Total targets: {emitted}")

    async def auditor_worker():
        while True:
            node = await node_queue.get()
            if node is None:
                node_queue.task_done()
                break
            try:
                for port in ports:
                    res = await audit_node_integrity(node, port, tokens, mode, state)
                    if res:
                        async with state_lock:
                            state["reachable"] += 1
                            state["recent"].append(res)
                            if len(state["recent"]) > 6:
                                state["recent"].pop(0)
                        with open(REPORT_FILE, "a", encoding="utf-8") as f:
                            f.write(res + "\n")
                        break
                async with state_lock:
                    state["done"] += 1
                    state["updated_at"] = now_ts()
                    if state["done"] % 5 == 0:
                        save_sys_state(state)
            finally:
                node_queue.task_done()

    workers = [asyncio.create_task(auditor_worker()) for _ in range(threads)]
    producer = asyncio.create_task(producer_worker())
    await producer
    await node_queue.join()
    await asyncio.gather(*workers)

    state["status"] = "completed"
    state["finished_at"] = now_ts()
    save_sys_state(state)
    log_audit_event("Audit session completed.")


# ==================== UI 仪表盘 (企业化风格) ====================


def show_audit_dashboard(state):
    sys.stdout.write("\033[H")
    total = state.get("total", 0)
    done = state.get("done", 0)
    if done > total:
        total = done
    reachable = state.get("reachable", 0)
    verified = state.get("verified", 0)
    status = state.get("status", "unknown")
    pid = state.get("pid", 0)

    elapsed = now_ts() - state.get("started_at", now_ts())
    rate = done / elapsed if elapsed > 0 else 0
    percent = (done / total * 100) if total > 0 else 0
    bar = f"{C_PROC}{'━' * int(25 * percent // 100)}{C_DIM}{'━' * (25 - int(25 * percent // 100))}{C_W}"

    print(
        f"{C_BLUE}┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓{C_W}"
    )
    print(
        f"{C_BLUE}┃ {C_W}{C_BOLD}SAIA ASSET INTEGRITY DASHBOARD{C_W} | {C_DIM}State: {status}{C_BLUE}      ┃{C_W}"
    )
    print(f"{C_BLUE}┣━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━┫{C_W}")
    print(
        f"{C_BLUE}┃{C_W} 可达: {C_FIND}{reachable:<7}{C_W}┃{C_W} 验证: {C_SUCC}{verified:<7}{C_W}┃{C_W} PID: {C_Y}{pid:<8}{C_W}┃{C_W} 频率: {C_CYAN}{rate:>3.0f} n/s{C_W} ┃{C_W}"
    )
    print(f"{C_BLUE}┣━━━━━━━━━━━━━━┻━━━━━━━━━━━━━━┻━━━━━━━━━━━━━━┻━━━━━━━━━━━━━━┫{C_W}")
    print(f"{C_BLUE}┃{C_W} 进度: {bar} {percent:5.1f}% [{done}/{total}] {C_BLUE}┃{C_W}")
    print(
        f"{C_BLUE}┣━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┫{C_W}"
    )
    print(
        f"{C_BLUE}┃{C_W} {C_PROC}[ACTION]{C_W} {str(state.get('current', ''))[:49]:<49} {C_BLUE}┃{C_W}"
    )
    print(
        f"{C_BLUE}┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛{C_W}"
    )

    print(f"\n{C_CYAN}LATEST AUDIT LOGS:{C_W}")
    for res in state.get("recent", []):
        print(f" {C_DIM}•{C_W} {res}")
    print(f"\n{C_Y}Press Ctrl+C to return to Management Console.{C_W}")


def saia_management_console():
    while True:
        clear_terminal()
        print(f"{C_BLUE}┌────────────────────────────────────────────────────────────┐")
        print(
            f"│  {C_BOLD}SAIA MANAGEMENT CONSOLE v15.0{C_W} | {C_CYAN}Asset Auditor System{C_BLUE}    │"
        )
        print(f"└────────────────────────────────────────────────────────────┘{C_W}")
        state = load_sys_state()
        guardian = load_guardian_state()
        active = is_node_alive(state.get("pid", 0)) and state.get("status") == "running"
        guardian_active = (
            is_node_alive(guardian.get("pid", 0))
            and guardian.get("status") == "running"
        )

        print(f"\n系统审计状态: {'活动中' if active else '待机中'}")
        print(f"自启动守护状态: {'活动中' if guardian_active else '待机中'}")
        print("1) 发起后台资产审计任务")
        print("2) 进入实时监控仪表盘")
        print("3) 查看已审计结果")
        print("4) 查看系统日志")
        print("5) 终止当前活动审计进程")
        print("6) 启动自启动守护")
        print("7) 查看自启动守护状态")
        print("8) 停止自启动守护")
        print("9) 退出管理控制台")

        choice = input(f"\n{C_CYAN}请选择指令: {C_W}").strip()
        if choice == "1":
            if active:
                print("审计任务已在执行队列中!")
                time.sleep(1)
                continue
            mode = prompt_int(
                "审计深度 (1基础/2标准/3深度): ", default=2, min_value=1, max_value=3
            )
            threads = prompt_int(
                "审计线程并发 (默认50): ", default=50, min_value=1, max_value=500
            )
            feed_interval = prompt_float(
                "IP投喂间隔秒 (默认0.005): ", default=0.005, min_value=0.0
            )
            ports_str = input("资产端口范围 (回车使用标准预设): ") or DEFAULT_PORTS
            try:
                _ = parse_ports(ports_str)
            except ValueError:
                print("端口范围格式错误，示例: 1080-1090,1111,2222")
                time.sleep(1.5)
                continue

            spawn_audit_process(mode, threads, ports_str, feed_interval)
            print(f"{C_PROC}资产审计进程已挂载至后台。{C_W}")
            time.sleep(1)
        elif choice == "2":
            try:
                while True:
                    show_audit_dashboard(load_sys_state())
                    time.sleep(0.5)
            except KeyboardInterrupt:
                pass
        elif choice == "3":
            output = read_last_lines(REPORT_FILE, lines=50)
            if output:
                print(output)
            else:
                print("暂无已审计结果。")
            input("\n按回车返回...")
        elif choice == "4":
            output = read_last_lines(LOG_FILE, lines=50)
            if output:
                print(output)
            else:
                print("暂无系统日志。")
            input("\n按回车返回...")
        elif choice == "5":
            pid = state.get("pid", 0)
            if is_node_alive(pid):
                os.kill(pid, signal.SIGTERM)
                print("审计进程已释放。")
            else:
                print("当前没有活动的审计任务。")
            time.sleep(1)
        elif choice == "6":
            if guardian_active:
                print("自启动守护已在运行。")
                time.sleep(1)
                continue

            mode = prompt_int(
                "守护目标审计深度 (1基础/2标准/3深度): ",
                default=2,
                min_value=1,
                max_value=3,
            )
            threads = prompt_int(
                "守护目标并发线程 (默认10): ", default=10, min_value=1, max_value=500
            )
            feed_interval = prompt_float(
                "守护IP投喂间隔秒 (默认0.01): ", default=0.01, min_value=0.0
            )
            ports_str = (
                input("守护端口范围 (回车使用标准预设): ").strip() or DEFAULT_PORTS
            )
            try:
                _ = parse_ports(ports_str)
            except ValueError:
                print("端口范围格式错误，示例: 1080-1090,1111,2222")
                time.sleep(1.5)
                continue

            min_free_mb = prompt_float(
                "最低可用内存MB阈值 (默认256): ", default=256.0, min_value=32.0
            )
            check_interval = prompt_float(
                "守护检查间隔秒 (默认5): ", default=5.0, min_value=1.0
            )

            cmd = [
                sys.executable,
                os.path.abspath(__file__),
                "run_guardian",
                str(mode),
                str(threads),
                ports_str,
                str(feed_interval),
                str(min_free_mb),
                str(check_interval),
            ]
            subprocess.Popen(
                cmd,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                stdin=subprocess.DEVNULL,
                start_new_session=True,
            )
            print("自启动守护已在后台启动。")
            time.sleep(1)
        elif choice == "7":
            g = load_guardian_state()
            gpid = g.get("pid", 0)
            print(f"\nPID: {gpid}")
            print(f"状态: {g.get('status', 'unknown')}")
            print(f"最后动作: {g.get('last_action', '-')}")
            print(f"最近可用内存MB: {g.get('last_free_mb', '-')}")
            print(f"更新时间: {fmt_time(g.get('updated_at'))}")
            input("\n按回车返回...")
        elif choice == "8":
            gpid = guardian.get("pid", 0)
            if is_node_alive(gpid):
                os.kill(gpid, signal.SIGTERM)
                print("自启动守护已停止。")
            else:
                print("当前没有活动的自启动守护。")
            time.sleep(1)
        elif choice == "9":
            break


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "run_audit":
        if len(sys.argv) < 5:
            raise SystemExit(
                "参数不足: run_audit <mode> <threads> <ports> [feed_interval]"
            )
        try:
            mode = int(sys.argv[2])
            threads = int(sys.argv[3])
            ports_raw = sys.argv[4]
            ports = parse_ports(ports_raw)
            feed_interval = float(sys.argv[5]) if len(sys.argv) > 5 else 0.005
        except ValueError as exc:
            raise SystemExit(f"参数错误: {exc}")

        if mode not in (1, 2, 3):
            raise SystemExit("mode 仅支持 1/2/3")
        if threads < 1:
            raise SystemExit("threads 必须大于 0")
        if not ports:
            raise SystemExit("未解析到可用端口")
        if feed_interval < 0:
            raise SystemExit("feed_interval 不能小于 0")

        target_file = NODE_FILE
        token_file = TOKEN_FILE

        if not os.path.exists(target_file):
            raise SystemExit(f"节点文件不存在: {target_file}")

        tokens = []
        if os.path.exists(token_file):
            with open(token_file, "r", encoding="utf-8", errors="replace") as f:
                for l in f:
                    item = l.strip()
                    if not item:
                        continue
                    if ":" in item:
                        u, p = item.split(":", 1)
                        if u and p:
                            tokens.append([u, p])
                    else:
                        tokens.append(["admin", item])

        asyncio.run(
            internal_audit_process(
                target_file,
                ports,
                tokens,
                mode,
                threads,
                queue_size=max(100, threads * 4),
                feed_interval=feed_interval,
            )
        )
    elif len(sys.argv) > 1 and sys.argv[1] == "run_guardian":
        if len(sys.argv) < 8:
            raise SystemExit(
                "参数不足: run_guardian <mode> <threads> <ports> <feed_interval> <min_free_mb> <check_interval>"
            )
        try:
            mode = int(sys.argv[2])
            threads = int(sys.argv[3])
            ports_str = sys.argv[4]
            parse_ports(ports_str)
            feed_interval = float(sys.argv[5])
            min_free_mb = float(sys.argv[6])
            check_interval = float(sys.argv[7])
        except ValueError as exc:
            raise SystemExit(f"参数错误: {exc}")

        if mode not in (1, 2, 3):
            raise SystemExit("mode 仅支持 1/2/3")
        if threads < 1:
            raise SystemExit("threads 必须大于 0")
        if feed_interval < 0:
            raise SystemExit("feed_interval 不能小于 0")
        if min_free_mb < 32:
            raise SystemExit("min_free_mb 不应低于 32MB")
        if check_interval < 1:
            raise SystemExit("check_interval 不能小于 1 秒")

        run_guardian_process(
            mode,
            threads,
            ports_str,
            feed_interval,
            min_free_mb,
            check_interval,
        )
    else:
        saia_management_console()
