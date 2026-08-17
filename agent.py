import os
import json
import time
import socket
import platform
import requests
import psutil
import uuid
import getpass
import traceback
import subprocess
from collections import deque
import sys

# =========================================================
# WMI OPTIONAL SAFE INIT
# =========================================================

WMI_OK = False
c = None

def init_wmi():
    global WMI_OK, c

    try:
        import wmi

        # ตัด pythoncom.CoInitialize() ออกก่อน
        c = wmi.WMI()

        print("[WMI] SUCCESS")

        WMI_OK = True

    except Exception as e:
        print("[WMI] FAILED")
        print(repr(e))

        WMI_OK = False
        c = None

init_wmi()


# =========================================================
# BASE DIR (for exe / py)
# =========================================================

def get_base_dir():
    if getattr(sys, "frozen", False):
        return os.path.dirname(sys.executable)
    return os.path.dirname(os.path.abspath(__file__))

BASE_DIR = get_base_dir()

# =========================================================
# CONFIG
# =========================================================

SERVER_URL = "http://192.168.0.158:5000/api/agent/report"
INTERVAL = 60
TIMEOUT = 10

LOG_FILE = os.path.join(BASE_DIR, "agent.log")
QUEUE_FILE = os.path.join(BASE_DIR, "agent_queue.json")

queue = deque(maxlen=1000)

# =========================================================
# LOG
# =========================================================

def log(msg):
    text = f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] {msg}"
    print(text)

    try:
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(text + "\n")
    except:
        pass

# =========================================================
# SAFE
# =========================================================

def safe(v):
    try:
        if v is None:
            return "-"
        v = str(v).strip()
        return v if v else "-"
    except:
        return "-"

# =========================================================
# CMD SAFE
# =========================================================

def run_cmd(cmd):
    try:
        result = subprocess.check_output(
            cmd,
            shell=True,
            text=True,
            encoding="utf-8",
            errors="ignore"
        )
        return result.strip()
    except:
        return ""
# =========================================================
# WMI SAFE WRAPPER
# =========================================================

def wmi_call(func, default="-"):
    try:
        if not WMI_OK or c is None:
            return default

        return func()

    except Exception as e:

        print("[WMI CALL ERROR]", repr(e))

        return default

# =========================================================
# BASIC INFO
# =========================================================

def get_hostname():
    return safe(socket.gethostname())

def get_username():
    return safe(getpass.getuser())

def get_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return safe(ip)
    except:
        return "-"

def get_mac():
    try:
        mac = uuid.getnode()
        return ':'.join(('%012X' % mac)[i:i+2] for i in range(0, 12, 2))
    except:
        return "-"

# =========================================================
# WINDOWS
# =========================================================

def get_windows():
    return safe(platform.platform())

def get_windows_build():
    try:
        return safe(platform.version())
    except:
        return "-"

# =========================================================
# SYSTEM (WMI)
# =========================================================

def get_system():
    try:
        result = run_cmd(
            "wmic computersystem get manufacturer,model /value"
        )

        manufacturer = "-"
        model = "-"

        for line in result.splitlines():

            if line.startswith("Manufacturer="):
                manufacturer = line.split("=", 1)[1].strip()

            elif line.startswith("Model="):
                model = line.split("=", 1)[1].strip()

        return {
            "manufacturer": manufacturer,
            "model": model
        }

    except:
        return {
            "manufacturer": "-",
            "model": "-"
        }

# =========================================================
# SERIAL
# =========================================================

def get_serial():
    try:
        result = run_cmd(
            "wmic bios get serialnumber"
        )

        lines = [
            x.strip()
            for x in result.splitlines()
            if x.strip()
        ]

        if len(lines) >= 2:
            return lines[-1]

        return "-"

    except:
        return "-"

# =========================================================
# CPU
# =========================================================

def get_cpu():
    try:
        result = run_cmd(
            "wmic cpu get name"
        )

        lines = [
            x.strip()
            for x in result.splitlines()
            if x.strip()
        ]

        if len(lines) >= 2:
            return lines[-1]

        return platform.processor()

    except:
        return platform.processor()

# =========================================================
# GPU
# =========================================================

def get_gpu():
    try:
        result = run_cmd(
            "wmic path win32_VideoController get name"
        )

        lines = [
            x.strip()
            for x in result.splitlines()
            if x.strip()
            and x.strip().lower() != "name"
        ]

        return ", ".join(lines) if lines else "-"

    except:
        return "-"

# =========================================================
# RAM
# =========================================================

def get_ram():
    try:
        return round(psutil.virtual_memory().total / (1024**3), 2)
    except:
        return 0

def get_ram_usage():
    try:
        return round(psutil.virtual_memory().percent, 2)
    except:
        return 0

# =========================================================
# STORAGE
# =========================================================

def get_storage():
    try:
        total = 0
        for d in psutil.disk_partitions():
            try:
                total += psutil.disk_usage(d.mountpoint).total
            except:
                pass
        return round(total / (1024**3), 2)
    except:
        return 0

def get_storage_detail():
    disks = []
    try:
        for d in psutil.disk_partitions():
            try:
                usage = psutil.disk_usage(d.mountpoint)

                disks.append({
                    "drive": d.device,
                    "mountpoint": d.mountpoint,
                    "filesystem": d.fstype,
                    "total_gb": round(usage.total / (1024**3), 2),
                    "used_gb": round(usage.used / (1024**3), 2),
                    "free_gb": round(usage.free / (1024**3), 2),
                    "percent": usage.percent
                })
            except:
                pass
    except:
        pass

    return disks

# =========================================================
# MAINBOARD / BIOS
# =========================================================

def get_mainboard():
    try:
        result = run_cmd(
            "wmic baseboard get manufacturer,product /value"
        )

        manufacturer = ""
        product = ""

        for line in result.splitlines():

            if line.startswith("Manufacturer="):
                manufacturer = line.split("=", 1)[1].strip()

            elif line.startswith("Product="):
                product = line.split("=", 1)[1].strip()

        value = f"{manufacturer} {product}".strip()

        return value if value else "-"

    except:
        return "-"

def get_bios_version():
    try:
        result = run_cmd(
            "wmic bios get SMBIOSBIOSVersion"
        )

        lines = [
            x.strip()
            for x in result.splitlines()
            if x.strip()
        ]

        if len(lines) >= 2:
            return lines[-1]

        return "-"

    except:
        return "-"

# =========================================================
# UPTIME
# =========================================================

def get_uptime():
    try:
        return int((time.time() - psutil.boot_time()) // 3600)
    except:
        return 0

# =========================================================
# ANTIVIRUS
# =========================================================

def get_antivirus():
    try:
        import wmi

        av = wmi.WMI(namespace="root\\SecurityCenter2")

        names = [x.displayName for x in av.AntiVirusProduct()
                 if x.displayName]

        return ", ".join(names) if names else "Windows Defender"

    except Exception as e:
        log(f"AV ERROR: {e}")
        return "Windows Defender"

# =========================================================
# WIFI
# =========================================================

def get_wifi_ssid():
    try:
        result = subprocess.check_output(
            "netsh wlan show interfaces",
            shell=True,
            text=True,
            encoding="utf-8",
            errors="ignore"
        )

        for line in result.splitlines():
            if "SSID" in line and "BSSID" not in line:
                parts = line.split(":")
                if len(parts) > 1:
                    return parts[1].strip()
        return "-"
    except:
        return "-"

# =========================================================
# NETWORK
# =========================================================

def get_network():
    try:
        net = psutil.net_io_counters()
        return {
            "bytes_sent_mb": round(net.bytes_sent / 1024**2, 2),
            "bytes_recv_mb": round(net.bytes_recv / 1024**2, 2)
        }
    except:
        return {}

# =========================================================
# PAYLOAD
# =========================================================

def build_payload():
    system = get_system()

    return {
        "hostname": get_hostname(),
        "ip_address": get_ip(),
        "mac_address": get_mac(),
        "username": get_username(),

        "manufacturer": system.get("manufacturer"),
        "model": system.get("model"),

        "serial_number": get_serial(),

        "cpu": get_cpu(),

        "gpu": get_gpu(),

        "ram_gb": get_ram(),
        "ram_usage": get_ram_usage(),

        "storage": get_storage(),
        "storage_detail": get_storage_detail(),

        "windows_version": get_windows(),
        "windows_build": get_windows_build(),

        "bios_version": get_bios_version(),
        "mainboard": get_mainboard(),

        "uptime_hours": get_uptime(),

        "antivirus": get_antivirus(),

        "wifi_ssid": get_wifi_ssid(),

        "network_stats": get_network(),

        "status": "online",
        "timestamp": int(time.time())
    }

# =========================================================
# SEND
# =========================================================

def send(data):
    try:
        print("=" * 60)
        print("AGENT REPORT")
        print(json.dumps(data, indent=2, ensure_ascii=False))
        print("=" * 60)

        r = requests.post(SERVER_URL, json=data, timeout=TIMEOUT)

        print("STATUS:", r.status_code)
        return r.status_code == 200

    except Exception as e:
        log(f"SEND ERROR: {e}")
        return False

# =========================================================
# MAIN LOOP
# =========================================================

def main():
    log("AGENT STARTED")

    while True:
        try:
            payload = build_payload()
            send(payload)

        except Exception as e:
            log(f"LOOP ERROR: {e}")
            traceback.print_exc()

        time.sleep(INTERVAL)

# =========================================================
# START
# =========================================================

if __name__ == "__main__":
    main()