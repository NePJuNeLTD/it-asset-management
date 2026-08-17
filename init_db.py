import sqlite3

conn = sqlite3.connect('database.db')
cursor = conn.cursor()


# ตารางพนักงาน
cursor.execute("""
CREATE TABLE employees (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT,
    position TEXT
)
""")

# ตาราง license
cursor.execute("""
CREATE TABLE licenses (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    employee_id INTEGER,
    software TEXT,
    start_date TEXT,
    expiry_date TEXT,
    FOREIGN KEY (employee_id) REFERENCES employees(id)
)
""")

# ตาราง users
cursor.execute("""
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE,
    password TEXT
)
""")

conn.commit()
conn.close()

print("สร้าง DB สำเร็จ")