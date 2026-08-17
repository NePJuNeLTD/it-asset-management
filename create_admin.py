import psycopg2
from werkzeug.security import generate_password_hash

conn = psycopg2.connect(
    host="localhost",
    database="license_system",
    user="postgres",
    password="Nepjune@230745",
    port="5432"
)

cursor = conn.cursor()

password = generate_password_hash("@Royaltec350")

cursor.execute("""
INSERT INTO users (username, password)
VALUES (%s, %s)
""", ("admin", password))

conn.commit()
conn.close()

print("ADMIN CREATED")