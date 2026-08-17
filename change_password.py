from werkzeug.security import generate_password_hash

password = generate_password_hash("@Royaltec350")

print(password)