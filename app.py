from flask import Flask, render_template, request, redirect, send_file
from apscheduler.schedulers.background import BackgroundScheduler
from datetime import datetime, timedelta
import os
from ldap3 import Server, Connection, ALL
import requests
import pandas as pd
import psycopg2
import nmap
import socket
try:
    import wmi
except ImportError:
    wmi = None

try:
    import pythoncom
except ImportError:
    pythoncom = None

import traceback
from psycopg2.extras import RealDictCursor
import time
import json
from flask import request, jsonify

from flask_login import (
    LoginManager,
    UserMixin,
    login_user,
    login_required,
    logout_user
)

from werkzeug.security import (
    generate_password_hash,
    check_password_hash
)

# =========================================================
# APP CONFIG
# =========================================================

app = Flask(__name__)

# =========================================================
# ENVIRONMENT / DEMO CONFIG
# =========================================================
# Render automatically sets RENDER=true. You can also force demo mode
# anywhere by setting DEMO_MODE=true.
IS_RENDER = os.getenv("RENDER", "").lower() == "true"
DEMO_MODE = os.getenv("DEMO_MODE", "").lower() in ("1", "true", "yes") or IS_RENDER

app.secret_key = os.getenv("FLASK_SECRET_KEY", "dev-only-change-me")

# =========================================================
# DOMAIN CONFIG
# =========================================================

DOMAIN_SERVER = os.getenv("DOMAIN_SERVER", "")
DOMAIN_USER = os.getenv("DOMAIN_USER", "")
DOMAIN_PASSWORD = os.getenv("DOMAIN_PASSWORD", "")
DOMAIN_BASE = os.getenv("DOMAIN_BASE", "")

# =========================================================
# HEALTH CHECK
# =========================================================
@app.route("/health")
def health():
    return {
        "status": "ok",
        "demo_mode": DEMO_MODE,
        "platform_features": {
            "wmi": (wmi is not None and not DEMO_MODE),
            "ldap": (not DEMO_MODE and bool(DOMAIN_SERVER)),
            "network_scan": (not DEMO_MODE)
        }
    }, 200

# =========================================================
# LOGIN CONFIG
# =========================================================

login_manager = LoginManager()

login_manager.init_app(app)

login_manager.login_view = "login"

# =========================================================
# DATABASE
# =========================================================

def get_db():
    """
    PostgreSQL connection.

    On Render:
      Set DATABASE_URL to the Internal Database URL from Render PostgreSQL.

    Local development:
      DB_HOST, DB_NAME, DB_USER, DB_PASSWORD and DB_PORT can be used.
    """
    database_url = os.getenv("DATABASE_URL")

    if database_url:
        # Some providers still expose postgres://. psycopg2 accepts
        # postgresql:// more consistently.
        if database_url.startswith("postgres://"):
            database_url = database_url.replace("postgres://", "postgresql://", 1)

        return psycopg2.connect(
            database_url,
            cursor_factory=RealDictCursor
        )

    return psycopg2.connect(
        host=os.getenv("DB_HOST", "localhost"),
        database=os.getenv("DB_NAME", "license_system"),
        user=os.getenv("DB_USER", "postgres"),
        password=os.getenv("DB_PASSWORD", ""),
        port=os.getenv("DB_PORT", "5432"),
        cursor_factory=RealDictCursor
    )

# =========================================================
# USER MODEL
# =========================================================

class User(UserMixin):

    def __init__(self, id, username, password):

        self.id = id
        self.username = username
        self.password = password

@login_manager.user_loader
def load_user(user_id):

    conn = get_db()

    cursor = conn.cursor()

    cursor.execute("""
    SELECT *
    FROM users
    WHERE id=%s
    """, (user_id,))

    row = cursor.fetchone()

    conn.close()

    if row:

        return User(
            row["id"],
            row["username"],
            row["password"]
        )

    return None

from flask import request, jsonify
import json
import traceback

@app.route("/api/agent/report", methods=["POST"])
def agent_report():

    conn = None

    try:

        data = request.get_json(force=True)

        print("=" * 80)
        print("AGENT REPORT")
        print(json.dumps(data, indent=2, ensure_ascii=False))
        print("=" * 80)

        conn = get_db()
        cursor = conn.cursor()

        query = """
        INSERT INTO domain_computers
        (
            hostname,
            ip_address,
            mac_address,
            manufacturer,
            model,
            serial_number,
            cpu,
            gpu,
            ram_gb,
            storage,
            storage_detail,
            windows_version,
            windows_build,
            username,
            bios_version,
            mainboard,
            uptime_hours,
            antivirus,
            wifi_ssid,
            cpu_usage,
            ram_usage,
            status,
            last_seen
        )

        VALUES
        (
            %s,%s,%s,%s,%s,
            %s,%s,%s,%s,%s,
            %s,%s,%s,%s,%s,
            %s,%s,%s,%s,%s,
            %s,%s,
            NOW()
        )

        ON CONFLICT (hostname)

        DO UPDATE SET

            ip_address      = EXCLUDED.ip_address,
            mac_address     = EXCLUDED.mac_address,
            manufacturer    = EXCLUDED.manufacturer,
            model           = EXCLUDED.model,
            serial_number   = EXCLUDED.serial_number,
            cpu             = EXCLUDED.cpu,
            gpu             = EXCLUDED.gpu,
            ram_gb          = EXCLUDED.ram_gb,
            storage         = EXCLUDED.storage,
            storage_detail  = EXCLUDED.storage_detail,
            windows_version = EXCLUDED.windows_version,
            windows_build   = EXCLUDED.windows_build,
            username        = EXCLUDED.username,
            bios_version    = EXCLUDED.bios_version,
            mainboard       = EXCLUDED.mainboard,
            uptime_hours    = EXCLUDED.uptime_hours,
            antivirus       = EXCLUDED.antivirus,
            wifi_ssid       = EXCLUDED.wifi_ssid,
            cpu_usage       = EXCLUDED.cpu_usage,
            ram_usage       = EXCLUDED.ram_usage,
            status          = EXCLUDED.status,
            last_seen       = NOW()
        """

        values = (

            data.get("hostname", "-"),
            data.get("ip_address", "-"),
            data.get("mac_address", "-"),
            data.get("manufacturer", "-"),
            data.get("model", "-"),

            data.get("serial_number", "-"),
            data.get("cpu", "-"),
            data.get("gpu", "-"),
            data.get("ram_gb", 0),
            data.get("storage", 0),

            json.dumps(
                data.get("storage_detail", []),
                ensure_ascii=False
            ),

            data.get("windows_version", "-"),
            data.get("windows_build", "-"),
            data.get("username", "-"),
            data.get("bios_version", "-"),

            data.get("mainboard", "-"),
            data.get("uptime_hours", 0),
            data.get("antivirus", "-"),
            data.get("wifi_ssid", "-"),
            data.get("cpu_usage", 0),

            data.get("ram_usage", 0),
            data.get("status", "online")
        )

        print("TOTAL VALUES =", len(values))

        cursor.execute(query, values)

        conn.commit()

        cursor.close()
        conn.close()

        return jsonify({
            "status": "ok"
        })

    except Exception as e:

        traceback.print_exc()

        if conn:
            conn.rollback()
            conn.close()

        return jsonify({
            "status": "error",
            "message": str(e)
        }), 500
# =========================================================
# LOGIN
# =========================================================

@app.route("/login", methods=["GET", "POST"])
def login():

    if request.method == "POST":

        username = request.form["username"]
        password = request.form["password"]

        conn = get_db()

        cursor = conn.cursor()

        cursor.execute("""
        SELECT *
        FROM users
        WHERE username=%s
        """, (username,))

        row = cursor.fetchone()

        conn.close()

        if row and check_password_hash(
            row["password"],
            password
        ):

            user = User(
                row["id"],
                row["username"],
                row["password"]
            )

            login_user(user)

            return redirect("/menu")

    return render_template("login.html")

# =========================================================
# LOGOUT
# =========================================================

@app.route("/logout")
@login_required
def logout():

    logout_user()

    return redirect("/login")

# =========================================================
# MENU
# =========================================================

@app.route("/menu")
@login_required
def menu():

    return render_template("menu.html")

# =========================================================
# SCAN NETWORK + PORTS
# =========================================================

# =========================================================
# MANUAL SCAN
# =========================================================

@app.route("/scan-network")
@login_required
def scan_network():

    scan_network_background()

    return redirect("/network-devices")

# =========================================================
# NETWORK DEVICES
# =========================================================

@app.route("/network-devices")
@login_required
def network_devices():

    conn = get_db()

    cursor = conn.cursor()

    cursor.execute("""
    SELECT *
    FROM network_devices
    ORDER BY
        CASE
            WHEN status='online' THEN 0
            ELSE 1
        END,
        ip_address ASC
    """)

    devices = cursor.fetchall()

    conn.close()

    return render_template(
        "network-devices.html",
        devices=devices
    )

# =========================================================
# GET DOMAIN COMPUTERS
# =========================================================

def get_domain_computers():

    if DEMO_MODE:
        print("LDAP disabled in demo/cloud environment")
        return []

    if not all([DOMAIN_SERVER, DOMAIN_USER, DOMAIN_PASSWORD, DOMAIN_BASE]):
        print("LDAP configuration is incomplete")
        return []

    print("CONNECT LDAP...")

    server = Server(
        DOMAIN_SERVER,
        get_info=ALL
    )

    conn = Connection(
        server,
        user=DOMAIN_USER,
        password=DOMAIN_PASSWORD,
        auto_bind=True,
        auto_referrals=False
    )

    print("LDAP CONNECTED")

    conn.search(
        search_base=DOMAIN_BASE,
        search_filter='(objectClass=computer)',
        attributes=['cn']
    )

    print("LDAP ENTRIES =", len(conn.entries))

    computers = []

    for entry in conn.entries:

        print("FOUND:", entry.cn)

        computers.append(str(entry.cn))

    return computers


# =========================================================
# GET FULL PC INFO FROM DOMAIN COMPUTER (WINRM VERSION)
# =========================================================

import traceback
import winrm

# =========================================================
# CONFIG (ใช้ของคุณเดิม)
# =========================================================

# DOMAIN_USER is loaded from environment
# DOMAIN_PASSWORD is loaded from environment


# =========================================================
# CONNECT WINRM
# =========================================================

def connect_winrm(host):
    if DEMO_MODE:
        print("WinRM disabled in demo/cloud environment")
        return None

    if not DOMAIN_USER or not DOMAIN_PASSWORD:
        print("WinRM credentials are not configured")
        return None

    username = DOMAIN_USER.split("\\")[-1]

    return winrm.Session(
        host,
        auth=(username, DOMAIN_PASSWORD),
        transport="ntlm",
        server_cert_validation="ignore"
    )


# =========================================================
# RUN COMMAND SAFE
# =========================================================

def run(session, cmd):
    if session is None:
        return ""

    try:
        r = session.run_cmd(cmd)
        return r.std_out.decode(errors="ignore").strip()
    except:
        return ""


# =========================================================
# BACKGROUND SCAN
# =========================================================

def scan_network_background():

    if DEMO_MODE:
        print("Network scan disabled in demo/cloud environment")
        return

    print("START AUTO SCAN")

    try:
        # Let python-nmap discover nmap from PATH.
        # On the Windows production machine, ensure Nmap is installed
        # and its directory is added to PATH.
        scanner = nmap.PortScanner()
    except Exception as e:
        print("Nmap is unavailable:", e)
        return

    network = os.getenv("SCAN_NETWORK", "192.168.0.0/24")

    scanner.scan(

        hosts=network,

        arguments="-T5 -sn -R"

    )

    conn = get_db()

    cursor = conn.cursor()

    # RESET OFFLINE
    cursor.execute("""
    UPDATE network_devices
    SET status='offline'
    """)

    # LOOP HOST
    for host in scanner.all_hosts():

        ip = host

        # =========================
        # HOSTNAME
        # =========================

        hostname = ""

        # วิธี 1
        try:

            hostname = socket.gethostbyaddr(ip)[0]

        except:

            pass

        # วิธี 2
        if not hostname:

            try:

                hostname = scanner[host].hostname()

            except:

                pass

        # ถ้ายังไม่มี
        if not hostname:

            hostname = "Unknown"

        # =========================
        # MAC ADDRESS
        # =========================

        mac = ""

        try:

            mac = scanner[host]["addresses"].get(
                "mac",
                ""
            )

        except:
            pass

        # =========================
        # VENDOR
        # =========================

        vendor = ""

        try:

            vendor_data = scanner[host]["vendor"]

            if vendor_data:

                vendor = list(
                    vendor_data.values()
                )[0]

        except:
            pass

        # =========================
        # CHECK EXIST
        # =========================

        cursor.execute("""
        SELECT id
        FROM network_devices
        WHERE ip_address=%s
        """, (ip,))

        exists = cursor.fetchone()

        # =========================
        # UPDATE
        # =========================

        if exists:

            cursor.execute("""
            UPDATE network_devices
            SET
                hostname=%s,
                mac_address=%s,
                vendor=%s,
                status='online',
                last_seen=NOW()
            WHERE ip_address=%s
            """, (
                hostname,
                mac,
                vendor,
                ip
            ))

        # =========================
        # INSERT
        # =========================

        else:

            cursor.execute("""
            INSERT INTO network_devices
            (
                ip_address,
                hostname,
                mac_address,
                vendor,
                status,
                last_seen
            )
            VALUES
            (
                %s,%s,%s,%s,
                'online',
                NOW()
            )
            """, (
                ip,
                hostname,
                mac,
                vendor
            ))

    conn.commit()

    conn.close()

    print("AUTO SCAN COMPLETE")
# =========================================================
# EMPLOYEE LIST
# =========================================================

@app.route("/employee-list")
@login_required
def employee_list():

    conn = get_db()

    cursor = conn.cursor()

    cursor.execute("""
    SELECT
        e.id,
        e.employee_code,
        e.name,
        e.start_date,
        e.department,
        e.position,

        c.pc_name,
        c.ip_address,
        c.serial_number,

        l.software,
        l.start_date AS license_start,
        l.expiry_date

    FROM employees e

    LEFT JOIN computers c
        ON e.id = c.employee_id

    LEFT JOIN licenses l
        ON e.id = l.employee_id

    ORDER BY e.id ASC
    """)

    rows = cursor.fetchall()

    conn.close()

    employees = {}

    for row in rows:

        emp_id = row["id"]

        if emp_id not in employees:

            employees[emp_id] = {

                "id": row["id"],
                "employee_code": row["employee_code"],
                "name": row["name"],
                "start_date": row["start_date"],
                "department": row["department"],
                "position": row["position"],

                "computer": {
                    "pc_name": row["pc_name"],
                    "ip_address": row["ip_address"],
                    "serial_number": row["serial_number"]
                },

                "licenses": []
            }

        if row["software"]:

            employees[emp_id]["licenses"].append({

                "software": row["software"],
                "start_date": row["license_start"],
                "expiry_date": row["expiry_date"]

            })

    return render_template(
        "employee-list.html",
        employees=list(employees.values())
    )

# =========================================================
# ADD EMPLOYEE
# =========================================================

@app.route("/employee-add", methods=["GET", "POST"])
@login_required
def employee_add():

    conn = get_db()

    cursor = conn.cursor()

    # โหลดแผนกทั้งหมด
    cursor.execute("""
    SELECT *
    FROM departments
    ORDER BY name ASC
    """)

    departments = cursor.fetchall()

    if request.method == "POST":

        employee_code = request.form["employee_code"]

        name = request.form["full_name"]

        start_date = request.form["start_date"]

        department = request.form["department"]

        position = request.form["position"]

        cursor.execute("""
        INSERT INTO employees
        (
            employee_code,
            name,
            start_date,
            department,
            position
        )
        VALUES (%s,%s,%s,%s,%s)
        """, (
            employee_code,
            name,
            start_date,
            department,
            position
        ))

        conn.commit()

        conn.close()

        return redirect("/employee-list")

    conn.close()

    return render_template(
        "employee-add.html",
        departments=departments
    )

# =========================================================
# DELETE EMPLOYEE
# =========================================================

@app.route("/employee-delete/<int:id>")
@login_required
def employee_delete(id):

    conn = get_db()
    cursor = conn.cursor()

    cursor.execute("""
    DELETE FROM employees
    WHERE id=%s
    """, (id,))

    conn.commit()
    conn.close()

    return redirect("/employee-list")

# =========================================================
# STATUS CHECK
# =========================================================

def get_status(expiry):

    if not expiry:

        return "none"

    today = datetime.today().date()

    if isinstance(expiry, str):

        exp = datetime.strptime(
            expiry,
            "%Y-%m-%d"
        ).date()

    else:

        exp = expiry

    if exp < today:

        return "expired"

    elif exp <= today + timedelta(days=7):

        return "warning"

    else:

        return "ok"

# =========================================================
# HOME
# =========================================================

@app.route("/")
@login_required
def home():

    status_filter = request.args.get("status")

    q = request.args.get("q")

    conn = get_db()

    cursor = conn.cursor()

    cursor.execute("""
SELECT
    e.id,
    e.name,
    e.position,

    l.software,
    l.start_date,
    l.expiry_date,

    c.pc_name,
    c.ip_address,
    c.serial_number

FROM employees e

LEFT JOIN licenses l
    ON e.id = l.employee_id

LEFT JOIN computers c
    ON e.id = c.employee_id

ORDER BY e.name ASC
""")

    rows = cursor.fetchall()

    conn.close()

    employees = {}

    for row in rows:

        emp_id = row["id"]

        if emp_id not in employees:

            employees[emp_id] = {

    "id": emp_id,

    "name": row["name"],

    "position": row["position"],

    "computer": {

        "machine": row["pc_name"],

        "ip": row["ip_address"],

        "serial_number": row["serial_number"]

    },

    "licenses": {}

}
        if row["software"]:

            employees[emp_id]["licenses"][row["software"]] = {

                "start": row["start_date"],

                "expiry": row["expiry_date"],

                "status": get_status(
                    row["expiry_date"]
                ),

                "machine": row["pc_name"],

                "serial_number": row["serial_number"],

                "ip": row["ip_address"]

            }

    data = list(employees.values())

    # SEARCH

    if q:

        data = [

            emp for emp in data

            if q.lower() in emp["name"].lower()

        ]

    # FILTER

    if status_filter:

        filtered = []

        for emp in data:

            for lic in emp["licenses"].values():

                if lic["status"] == status_filter:

                    filtered.append(emp)

                    break

        data = filtered

    # DASHBOARD

    total_employees = len(data)

    total_licenses = 0

    expired_count = 0

    warning_count = 0

    for emp in data:

        for lic in emp["licenses"].values():

            total_licenses += 1

            if lic["status"] == "expired":

                expired_count += 1

            elif lic["status"] == "warning":

                warning_count += 1

    return render_template(

        "index.html",

        data=data,

        total_employees=total_employees,

        total_licenses=total_licenses,

        expired_count=expired_count,

        warning_count=warning_count,

        today=datetime.today().strftime("%d/%m/%Y")

    )

# =========================================================
# ADD LICENSE
# =========================================================

@app.route("/add", methods=["GET", "POST"])
@login_required
def add():

    if request.method == "POST":

        name = request.form["name"]

        position = request.form["position"]

        selected = request.form.getlist("software")

        conn = get_db()

        cursor = conn.cursor()

        cursor.execute("""
        INSERT INTO employees
        (
            name,
            position
        )
        VALUES (%s, %s)
        RETURNING id
        """, (
            name,
            position
        ))

        emp_id = cursor.fetchone()["id"]

        for sw in selected:

            start = request.form.get(
                f"start_{sw}"
            ) or None

            expiry = request.form.get(
                f"expiry_{sw}"
            ) or None

            serial_number = request.form.get(
                "serial_number"
            ) or None

            machine_name = request.form.get(
                "machine_name"
            ) or None

            ip_address = request.form.get(
                "ip_address"
            ) or None

            cursor.execute("""
            INSERT INTO licenses
            (
                employee_id,
                software,
                start_date,
                expiry_date,
                machine_name,
                ip_address,
                serial_number
            )
            VALUES (%s,%s,%s,%s,%s,%s,%s)
            """, (
                emp_id,
                sw,
                start,
                expiry,
                machine_name,
                ip_address,
                serial_number
            ))

        conn.commit()

        conn.close()

        return redirect("/")

    return render_template("add.html")

# =========================================================
# EDIT LICENSE
# =========================================================

@app.route("/edit/<int:id>", methods=["GET", "POST"])
@login_required
def edit(id):

    conn = get_db()
    cursor = conn.cursor()

    if request.method == "POST":

        name = request.form["name"]
        position = request.form["position"]

        machine_name = request.form.get("machine_name")
        ip_address = request.form.get("ip_address")
        serial_number = request.form.get("serial_number")

        # UPDATE EMPLOYEE
        cursor.execute("""
        UPDATE employees
        SET name=%s,
            position=%s
        WHERE id=%s
        """, (
            name,
            position,
            id
        ))

        # ลบ licenses เดิม
        cursor.execute("""
        DELETE FROM licenses
        WHERE employee_id=%s
        """, (id,))

        # ลบ computer เดิม
        cursor.execute("""
        DELETE FROM computers
        WHERE employee_id=%s
        """, (id,))

        # เพิ่ม computer ใหม่
        cursor.execute("""
        INSERT INTO computers
        (
            employee_id,
            pc_name,
            ip_address,
            serial_number
        )
        VALUES (%s,%s,%s,%s)
        """, (
            id,
            machine_name,
            ip_address,
            serial_number
        ))

        # SOFTWARE
        selected = request.form.getlist("software")

        for sw in selected:

            start = request.form.get(f"start_{sw}") or None
            expiry = request.form.get(f"expiry_{sw}") or None

            cursor.execute("""
            INSERT INTO licenses
            (
                employee_id,
                software,
                start_date,
                expiry_date
            )
            VALUES (%s,%s,%s,%s)
            """, (
                id,
                sw,
                start,
                expiry
            ))

        conn.commit()
        conn.close()

        return redirect("/")

    # LOAD EMPLOYEE
    cursor.execute("""
    SELECT *
    FROM employees
    WHERE id=%s
    """, (id,))

    employee = cursor.fetchone()

    # LOAD LICENSES
    cursor.execute("""
    SELECT *
    FROM licenses
    WHERE employee_id=%s
    """, (id,))

    licenses = cursor.fetchall()

    # LOAD COMPUTER
    cursor.execute("""
    SELECT *
    FROM computers
    WHERE employee_id=%s
    """, (id,))

    computer = cursor.fetchone()

    conn.close()

    return render_template(
        "edit.html",
        employee=employee,
        licenses=licenses,
        computer=computer
    )

@app.route("/employee-edit/<int:id>", methods=["GET", "POST"])
@login_required
def employee_edit(id):

    conn = get_db()

    cursor = conn.cursor(
        cursor_factory=RealDictCursor
    )

    # ====================================
    # SAVE EDIT
    # ====================================

    if request.method == "POST":

        name = request.form.get("full_name")
        position = request.form.get("position")
        department = request.form.get("department")
        employee_code = request.form.get("employee_code")
        start_date = request.form.get("start_date")

        # UPDATE EMPLOYEE

        cursor.execute("""
            UPDATE employees
            SET
                name=%s,
                position=%s,
                department=%s,
                employee_code=%s,
                start_date=%s
            WHERE id=%s
        """, (
            name,
            position,
            department,
            employee_code,
            start_date,
            id
        ))

        conn.commit()

        conn.close()

        return redirect("/employee-list")

    # ====================================
    # GET EMPLOYEE
    # ====================================

    cursor.execute("""
        SELECT *
        FROM employees
        WHERE id=%s
    """, (id,))

    employee = cursor.fetchone()

    # ====================================
    # GET COMPUTER
    # ====================================

    cursor.execute("""
        SELECT *
        FROM computers
        WHERE employee_id=%s
        LIMIT 1
    """, (id,))

    computer = cursor.fetchone()

    # ====================================
    # GET LICENSES
    # ====================================

    cursor.execute("""
        SELECT *
        FROM licenses
        WHERE employee_id=%s
        ORDER BY software ASC
    """, (id,))

    licenses = cursor.fetchall()

    # ====================================
    # GET DEPARTMENTS
    # ====================================

    cursor.execute("""
        SELECT *
        FROM departments
        ORDER BY name ASC
    """)

    departments = cursor.fetchall()

    conn.close()

    return render_template(
        "employee-edit.html",
        employee=employee,
        computer=computer,
        licenses=licenses,
        departments=departments
    )

# =========================================================
# DELETE LICENSE
# =========================================================

@app.route("/delete/<int:id>")
@login_required
def delete_employee(id):

    conn = get_db()

    cursor = conn.cursor()

    cursor.execute("""
    DELETE FROM licenses
    WHERE employee_id=%s
    """, (id,))

    cursor.execute("""
    DELETE FROM employees
    WHERE id=%s
    """, (id,))

    conn.commit()

    conn.close()

    return redirect("/")

def connect_wmi_safe(target):
    if DEMO_MODE or wmi is None:
        print("WMI disabled/unavailable in this environment")
        return None

    for i in range(2):
        try:
            return wmi.WMI(
                computer=target,
                user=DOMAIN_USER,
                password=DOMAIN_PASSWORD
            )
        except Exception as e:
            print(f"WMI retry {i+1} failed:", e)
            time.sleep(1)

    return None

# =========================================================
# IMPORT EXCEL
# =========================================================

@app.route("/import-excel", methods=["GET", "POST"])
@login_required
def import_excel():

    if request.method == "POST":

        file = request.files["excel_file"]

        if not file:

            return "No file"

        # READ EXCEL
        df = pd.read_excel(file)

        # DB
        conn = get_db()
        cursor = conn.cursor()

        imported = 0
        skipped = 0

        for _, row in df.iterrows():

            name = str(row.get("Name", "")).strip()
            employee_code = str(row.get("Employee Code", "")).strip()
            department = str(row.get("Department", "")).strip()
            position = str(row.get("Position", "")).strip()
            start_date = row.get("Start Date")

            # SKIP EMPTY
            if not name:
                continue

            # CHECK DUPLICATE
            cursor.execute("""
                SELECT id
                FROM employees
                WHERE employee_code=%s
            """, (employee_code,))

            exists = cursor.fetchone()

            if exists:

                skipped += 1

            else:

                cursor.execute("""
                    INSERT INTO employees
                    (
                        name,
                        employee_code,
                        department,
                        position,
                        start_date
                    )
                    VALUES (%s,%s,%s,%s,%s)
                """, (
                    name,
                    employee_code,
                    department,
                    position,
                    start_date
                ))

                imported += 1

        conn.commit()
        conn.close()

        return f"""
        IMPORT COMPLETE <br><br>

        Imported : {imported} <br>
        Skipped Duplicate : {skipped}
        """

    return render_template("import-excel.html")

# =========================================================
# EXPORT EXCEL
# =========================================================

@app.route("/export-excel")
@login_required
def export_excel():

    conn = get_db()

    cursor = conn.cursor()

    cursor.execute("""
    SELECT
        e.name,
        e.position,
        l.software,
        l.expiry_date

    FROM employees e

    LEFT JOIN licenses l
        ON e.id = l.employee_id

    ORDER BY e.name ASC
    """)

    rows = cursor.fetchall()

    conn.close()

    employees = {}

    softwares = [

        "Antivirus",
        "Winspeed",
        "AutoCAD",
        "Visio",
        "PDF Pro",
        "DR-Site(UTH)",
        "Business Std",
        "Business Basic"

    ]

    for row in rows:

        name = row["name"]

        if name not in employees:

            employees[name] = {

                "Name": row["name"],

                "Position": row["position"]

            }

            for sw in softwares:

                employees[name][sw] = "ไม่ใช้"

                employees[name][
                    f"{sw} Expiry"
                ] = ""

        if row["software"]:

            employees[name][
                row["software"]
            ] = "ใช้"

            employees[name][
                f"{row['software']} Expiry"
            ] = row["expiry_date"]

    df = pd.DataFrame(
        employees.values()
    )

    filename = "license_report.xlsx"

    with pd.ExcelWriter(
        filename,
        engine="openpyxl"
    ) as writer:

        df.to_excel(
            writer,
            index=False,
            sheet_name="License Report"
        )

        ws = writer.sheets[
            "License Report"
        ]

        for column in ws.columns:

            max_length = 0

            column_letter = (
                column[0].column_letter
            )

            for cell in column:

                try:

                    if len(
                        str(cell.value)
                    ) > max_length:

                        max_length = len(
                            str(cell.value)
                        )

                except:
                    pass

            ws.column_dimensions[
                column_letter
            ].width = max_length + 5

    return send_file(
        filename,
        as_attachment=True
    )

# =========================================================
# DASHBOARD API
# =========================================================

@app.route("/api/dashboard")
@login_required
def dashboard_api():

    conn = get_db()

    cursor = conn.cursor()

    cursor.execute("""
    SELECT COUNT(*)
    FROM employees
    """)

    total_employees = cursor.fetchone()["count"]

    cursor.execute("""
    SELECT COUNT(*)
    FROM licenses
    """)

    total_licenses = cursor.fetchone()["count"]

    conn.close()

    return {

        "employees": total_employees,

        "licenses": total_licenses

    }

# =========================================================
# LINE CONFIG
# =========================================================

LINE_TOKEN = os.getenv("LINE_TOKEN", "")

def send_line(message):

    if not LINE_TOKEN:
        print("LINE_TOKEN is not configured; notification skipped")
        return False

    headers = {

        "Content-Type": "application/json",

        "Authorization": f"Bearer {LINE_TOKEN}"

    }

    data = {

        "messages": [

            {
                "type": "text",
                "text": message
            }

        ]

    }

    url = "https://api.line.me/v2/bot/message/broadcast"

    response = requests.post(
        url,
        headers=headers,
        json=data
    )

    print(response.text)
    return response.ok

# =========================================================
# LINE TEST
# =========================================================

@app.route("/line-test")
def line_test():

    send_line(
        "🔥 Flask LINE Bot Test"
    )

    return "Send Success"

# =========================================================
# AUTO CHECK EXPIRY
# =========================================================

def auto_check_expiry():

    conn = get_db()

    cursor = conn.cursor()

    cursor.execute("""
    SELECT
        e.name,
        l.software,
        l.expiry_date

    FROM employees e

    JOIN licenses l
        ON e.id = l.employee_id
    """)

    rows = cursor.fetchall()

    conn.close()

    msg = "📢 AUTO LICENSE ALERT\n\n"

    found = False

    for row in rows:

        status = get_status(
            row["expiry_date"]
        )

        if status == "warning":

            found = True

            msg += (
                f"⚠ ใกล้หมดอายุ\n"
                f"👤 {row['name']}\n"
                f"💻 {row['software']}\n"
                f"📅 {row['expiry_date']}\n\n"
            )

        elif status == "expired":

            found = True

            msg += (
                f"❌ หมดอายุแล้ว\n"
                f"👤 {row['name']}\n"
                f"💻 {row['software']}\n"
                f"📅 {row['expiry_date']}\n\n"
            )

    if found:

        send_line(msg)

        print("LINE ALERT SENT")

    else:

        print("NO WARNING LICENSE")

# =========================================================
# SEND ALERT
# =========================================================

@app.route("/send-alert")
@login_required
def send_alert():

    auto_check_expiry()

    return "Alert Sent"

@app.route("/notebooks")
@login_required
def notebooks():

    conn = get_db()
    cursor = conn.cursor()

    cursor.execute("""
    SELECT
        n.*,
        e.name AS employee_name

    FROM notebooks n

    LEFT JOIN notebook_history h
        ON n.id = h.notebook_id
        AND h.status='using'

    LEFT JOIN employees e
        ON h.employee_id = e.id

    ORDER BY n.asset_code ASC
    """)

    notebooks = cursor.fetchall()

    conn.close()

    return render_template(
        "notebooks.html",
        notebooks=notebooks
    )

# =========================================================
# ADD NOTEBOOK
# =========================================================

@app.route("/notebook-add", methods=["GET", "POST"])
@login_required
def notebook_add():

    conn = get_db()
    cursor = conn.cursor()

    if request.method == "POST":

        device_type = request.form.get("device_type")

        asset_code = request.form.get("asset_code")

        brand = request.form.get("brand")

        model = request.form.get("model")

        cpu = request.form.get("cpu") or None

        ram = request.form.get("ram") or None

        storage = request.form.get("storage") or None

        os = request.form.get("os") or None

        serial_number = request.form.get("serial_number") or None

        purchase_date = request.form.get("purchase_date") or None

        warranty_expire = request.form.get("warranty_expire") or None

        price = request.form.get("price") or None

        note = request.form.get("note") or None

        status = request.form.get("status")

        cursor.execute("""
        INSERT INTO notebooks
        (
            device_type,
            asset_code,
            brand,
            model,
            cpu,
            ram,
            storage,
            os,
            serial_number,
            purchase_date,
            warranty_expire,
            price,
            note,
            status
        )
        VALUES
        (
            %s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s
        )
        """, (
            device_type,
            asset_code,
            brand,
            model,
            cpu,
            ram,
            storage,
            os,
            serial_number,
            purchase_date,
            warranty_expire,
            price,
            note,
            status
        ))

        conn.commit()
        conn.close()

        return redirect("/notebooks")

    conn.close()

    return render_template("notebook-add.html")

@app.route("/device/<int:id>")
@login_required
def device_detail(id):

    conn = get_db()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT *
        FROM notebooks
        WHERE id = %s
    """, (id,))

    device = cursor.fetchone()

    # repair history
    cursor.execute("""
        SELECT *
        FROM repairs
        WHERE notebook_id = %s
        ORDER BY repair_date DESC
    """, (id,))

    repairs = cursor.fetchall()

    conn.close()

    return render_template(
        "device-detail.html",
        device=device,
        repairs=repairs
    )

# =========================================================
# NOTEBOOK HISTORY
# =========================================================

@app.route("/notebook-history")
@login_required
def notebook_history():

    conn = get_db()

    cursor = conn.cursor()

    cursor.execute("""
    SELECT

        h.id,

        n.asset_code,

        n.brand,

        n.model,

        e.name AS employee_name,

        h.assign_date,

        h.return_date,

        h.status

    FROM notebook_history h

    LEFT JOIN notebooks n
        ON h.notebook_id = n.id

    LEFT JOIN employees e
        ON h.employee_id = e.id

    ORDER BY h.id DESC
    """)

    histories = cursor.fetchall()

    conn.close()

    return render_template(
        "notebook-history.html",
        histories=histories
    )

# =========================================================
# RETURN NOTEBOOK
# =========================================================

@app.route("/return-notebook/<int:id>")
@login_required
def return_notebook(id):

    conn = get_db()

    cursor = conn.cursor()

    # update history
    cursor.execute("""
    UPDATE notebook_history
    SET
        status='returned',
        return_date=CURRENT_DATE
    WHERE notebook_id=%s
    AND status='using'
    """, (id,))

    # update notebook status
    cursor.execute("""
    UPDATE notebooks
    SET status='available'
    WHERE id=%s
    """, (id,))

    conn.commit()

    conn.close()

    return redirect("/notebooks")

# =========================================================
# DELETE NOTEBOOK
# =========================================================

@app.route("/delete-notebook/<int:id>")
@login_required
def delete_notebook(id):

    conn = get_db()

    cursor = conn.cursor()

    # ลบ history ก่อน (ถ้ามี foreign key)
    cursor.execute("""
    DELETE FROM notebook_history
    WHERE notebook_id=%s
    """, (id,))

    # ลบ notebook
    cursor.execute("""
    DELETE FROM notebooks
    WHERE id=%s
    """, (id,))

    conn.commit()

    conn.close()

    return redirect("/notebooks")

@app.route("/notebook-repairs/<int:id>")
@login_required
def notebook_repairs(id):

    conn = get_db()
    cursor = conn.cursor(cursor_factory=RealDictCursor)

    # notebook
    cursor.execute("""
        SELECT *
        FROM notebooks
        WHERE id=%s
    """, (id,))

    notebook = cursor.fetchone()

    # repair history
    cursor.execute("""
        SELECT *
        FROM notebook_repairs
        WHERE notebook_id=%s
        ORDER BY repair_date DESC
    """, (id,))

    repairs = cursor.fetchall()

    conn.close()

    return render_template(
        "notebook-repairs.html",
        notebook=notebook,
        repairs=repairs
    )

@app.route("/add-repair/<int:id>", methods=["POST"])
@login_required
def add_repair(id):

    repair_date = request.form["repair_date"]
    repair_type = request.form["repair_type"]
    detail = request.form["detail"]
    repaired_by = request.form["repaired_by"]

    # FIX NUMERIC
    cost = request.form["cost"]

    if cost == "":
        cost = None

    conn = get_db()
    cursor = conn.cursor()

    cursor.execute("""
        INSERT INTO notebook_repairs
        (
            notebook_id,
            repair_date,
            repair_type,
            detail,
            cost,
            repaired_by
        )
        VALUES (%s,%s,%s,%s,%s,%s)
    """, (
        id,
        repair_date,
        repair_type,
        detail,
        cost,
        repaired_by
    ))

    conn.commit()
    conn.close()

    return redirect(f"/notebook-repairs/{id}")
# =========================================================
# ASSIGN NOTEBOOK
# =========================================================

@app.route("/assign-notebook", methods=["GET", "POST"])
@login_required
def assign_notebook():

    conn = get_db()
    cursor = conn.cursor()

    # =========================
    # SAVE
    # =========================

    if request.method == "POST":

        employee_id = request.form["employee_id"]
        notebook_id = request.form["notebook_id"]
        assign_date = request.form["assign_date"]

        # SAVE HISTORY
        cursor.execute("""
        INSERT INTO notebook_history
        (
            notebook_id,
            employee_id,
            assign_date,
            status
        )
        VALUES (%s,%s,%s,'using')
        """, (
            notebook_id,
            employee_id,
            assign_date
        ))

        # UPDATE NOTEBOOK STATUS
        # UPDATE NOTEBOOK STATUS
        cursor.execute("""
        UPDATE notebooks
        SET status='in_use'
        WHERE id=%s
        """, (notebook_id,))

        conn.commit()
        conn.close()

        return redirect("/notebooks")

    # =========================
    # LOAD EMPLOYEE
    # =========================

    cursor.execute("""
    SELECT *
    FROM employees
    ORDER BY name ASC
    """)

    employees = cursor.fetchall()

    # =========================
    # LOAD NOTEBOOK AVAILABLE
    # =========================

    cursor.execute("""
    SELECT *
    FROM notebooks
    WHERE status='available'
    ORDER BY asset_code ASC
    """)

    notebooks = cursor.fetchall()

    conn.close()

    return render_template(
        "assign-notebook.html",
        employees=employees,
        notebooks=notebooks
    )


# =========================================================
# RUN APP
# =========================================================

@app.route("/departments")
@login_required
def departments():

    conn = get_db()

    cursor = conn.cursor()

    cursor.execute("""
    SELECT *
    FROM departments
    ORDER BY name ASC
    """)

    departments = cursor.fetchall()

    conn.close()

    return render_template(
        "departments.html",
        departments=departments
    )

@app.route("/department-add", methods=["POST"])
@login_required
def department_add():

    name = request.form["name"]

    conn = get_db()

    cursor = conn.cursor()

    cursor.execute("""
    INSERT INTO departments (name)
    VALUES (%s)
    """, (name,))

    conn.commit()

    conn.close()

    return redirect("/departments")

# =========================================================
# DOMAIN COMPUTERS
# =========================================================

@app.route("/domain-computers")
@login_required
def domain_computers():

    conn = get_db()

    cursor = conn.cursor()

    cursor.execute("""
    SELECT *
    FROM domain_computers
    ORDER BY hostname ASC
    """)

    devices = cursor.fetchall()

    conn.close()

    return render_template(
        "domain-computers.html",
        devices=devices
    )

if __name__ == "__main__":

    # Scheduler is intended for the internal/local installation only.
    # Gunicorn on Render imports app:app, so this block is not executed there.
    if not DEMO_MODE:
        scheduler = BackgroundScheduler(timezone="Asia/Bangkok")
        scheduler.add_job(auto_check_expiry, trigger="cron", hour=8, minute=0)
        scheduler.add_job(scan_network_background, trigger="interval", minutes=30)
        scheduler.start()
        print("Scheduler Started")
    else:
        print("Demo mode: scheduler disabled")

    port = int(os.getenv("PORT", "5000"))
    app.run(
        host="0.0.0.0",
        port=port,
        debug=os.getenv("FLASK_DEBUG", "").lower() == "true"
    )