#!/usr/bin/env python3
"""
cysic-node-monitor
轻量级节点资源与进程监控脚本

用途：
- 周期性采样 CPU / mem / disk / net
- 检查指定进程（名称或 PID）是否存在，抓取进程资源
- 输出到滚动日志（按运行时追加）
- 支持 JSON 输出文件以便上报或后端解析

运行示例：
python monitor.py --process-name cysicd --interval 30
"""

import argparse
import datetime
import json
import logging
import os
import sys
import time

import psutil
import tomli

DEFAULT_CONFIG = {
    "interval": 30,
    "log_path": "monitor.log",
    "json_output": False,
    "process_name": "",
    "process_pid": 0,
}


def load_config(path: str):
    cfg = DEFAULT_CONFIG.copy()
    if not path:
        return cfg
    try:
        with open(path, "rb") as f:
            data = tomli.load(f)
            cfg.update(data)
    except FileNotFoundError:
        print(f"config file {path} not found — using defaults")
    except Exception as e:
        print(f"failed to read config {path}: {e} — using defaults")
    return cfg


def setup_logging(log_path: str):
    logger = logging.getLogger("cysic-monitor")
    logger.setLevel(logging.INFO)
    formatter = logging.Formatter("%(asctime)s %(levelname)s %(message)s")

    fh = logging.FileHandler(log_path)
    fh.setFormatter(formatter)
    logger.addHandler(fh)

    sh = logging.StreamHandler(sys.stdout)
    sh.setFormatter(formatter)
    logger.addHandler(sh)
    return logger


def find_process_by_name(name: str):
    procs = []
    for p in psutil.process_iter(["pid", "name", "exe", "cmdline"]):
        try:
            pname = (p.info.get("name") or "").lower()
            if name.lower() in pname or name.lower() in " ".join((p.info.get("cmdline") or [])).lower():
                procs.append(p)
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    return procs


def collect_system_metrics():
    cpu = psutil.cpu_percent(interval=None)
    cpu_per_cpu = psutil.cpu_percent(interval=None, percpu=True)
    vm = psutil.virtual_memory()
    disk = psutil.disk_usage("/")
    net = psutil.net_io_counters(pernic=False)
    return {
        "timestamp": datetime.datetime.utcnow().isoformat() + "Z",
        "cpu_percent": cpu,
        "cpu_per_cpu": cpu_per_cpu,
        "mem_total": vm.total,
        "mem_used": vm.used,
        "mem_percent": vm.percent,
        "disk_total": disk.total,
        "disk_used": disk.used,
        "disk_percent": disk.percent,
        "net_bytes_sent": net.bytes_sent,
        "net_bytes_recv": net.bytes_recv,
    }


def collect_process_metrics(proc: psutil.Process):
    try:
        with proc.oneshot():
            cpu = proc.cpu_percent(interval=None)
            mem = proc.memory_info()
            io = proc.io_counters() if hasattr(proc, "io_counters") else None
            status = proc.status()
            create_time = datetime.datetime.utcfromtimestamp(proc.create_time()).isoformat() + "Z"
            cmdline = proc.cmdline()
        return {
            "pid": proc.pid,
            "name": proc.name(),
            "cpu_percent": cpu,
            "mem_rss": mem.rss,
            "mem_vms": mem.vms if hasattr(mem, "vms") else None,
            "status": status,
            "create_time": create_time,
            "cmdline": cmdline,
            "io_read_bytes": io.read_bytes if io else None,
            "io_write_bytes": io.write_bytes if io else None,
        }
    except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
        return {"error": str(e), "pid": getattr(proc, "pid", None)}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", help="path to toml config", default="config.toml")
    parser.add_argument("--interval", type=int, help="sampling interval (seconds)", default=None)
    parser.add_argument("--process-name", type=str, help="process name to monitor", default=None)
    parser.add_argument("--process-pid", type=int, help="process pid to monitor", default=None)
    args = parser.parse_args()

    cfg = load_config(args.config)
    # override with CLI args
    if args.interval:
        cfg["interval"] = args.interval
    if args.process_name:
        cfg["process_name"] = args.process_name
    if args.process_pid:
        cfg["process_pid"] = args.process_pid

    logger = setup_logging(cfg["log_path"])
    logger.info("Starting cysic-node-monitor with config: %s", {k: v for k, v in cfg.items() if k != "log_path"})

    json_fp = None
    if cfg.get("json_output"):
        date_str = datetime.datetime.utcnow().strftime("%Y%m%d")
        json_name = f"monitor-{date_str}.json"
        json_fp = open(json_name, "a", encoding="utf-8")
        logger.info("JSON output enabled: %s", json_name)

    try:
        while True:
            sys_metrics = collect_system_metrics()
            entry = {"system": sys_metrics}

            # find process
            target_proc = None
            if cfg.get("process_pid"):
                try:
                    p = psutil.Process(cfg["process_pid"])
                    target_proc = p
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    target_proc = None
            elif cfg.get("process_name"):
                procs = find_process_by_name(cfg["process_name"])
                if procs:
                    # choose the first match
                    target_proc = procs[0]

            if target_proc:
                proc_metrics = collect_process_metrics(target_proc)
                entry["process"] = proc_metrics
                logger.info("Process %s metrics: cpu=%.2f mem=%.2f%% pid=%s",
                            proc_metrics.get("name", "<unknown>"),
                            proc_metrics.get("cpu_percent", 0.0),
                            (proc_metrics.get("mem_rss", 0) / max(1, sys_metrics["mem_total"])) * 100.0 if proc_metrics.get("mem_rss") else 0.0,
                            proc_metrics.get("pid"))
            else:
                entry["process"] = {"found": False}
                logger.warning("Target process not found (name=%s pid=%s)", cfg.get("process_name"), cfg.get("process_pid"))

            # log JSON line if enabled
            if json_fp:
                json_fp.write(json.dumps(entry, ensure_ascii=False) + "\n")
                json_fp.flush()

            time.sleep(cfg["interval"])
    except KeyboardInterrupt:
        logger.info("Shutting down monitor (KeyboardInterrupt)")
    finally:
        if json_fp:
            json_fp.close()


if __name__ == "__main__":
    main()
