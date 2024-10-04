import csv
import bcrypt
import re
import sys
import requests
import ipaddress
from datetime import datetime

def append_log(user_email, action_msg):
    log_file = f"{user_email}_activity.log"
    try:
        with open(log_file, "a") as log:
            timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            log.write(f"{timestamp} - {action_msg}\n")
    except IOError as log_err:
        print(f"Could not write to log: {log_err}")

def load_csv_data(filename='regno.csv'):
    user_data = []
    try:
        with open(filename, mode='r', newline='') as csvfile:
            reader = csv.DictReader(csvfile)
            for row in reader:
                user_data.append(row)
    except FileNotFoundError:
        print(f"File {filename} not found.")
    return user_data

def update_csv(users, filename='regno.csv'):
    try:
        with open(filename, mode='w', newline='') as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=['email', 'hashed_password', 'security_question', 'security_answer'])
            writer.writeheader()
            writer.writerows(users)
    except IOError as write_err:
        print(f"Error writing CSV: {write_err}")

def log_activity(email, action, ip):
    try:
        with open('activity_log.csv', mode='a', newline='') as logfile:
            writer = csv.writer(logfile)
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            writer.writerow([email, action, ip, timestamp])
    except IOError:
        print("Failed to write activity log.")

def email_is_valid(email):
    email_regex = r'^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$'
    return re.match(email_regex, email) is not None

def password_is_strong(password):
    return (
        len(password) >= 8 and
        re.search(r'[A-Z]', password) and
        re.search(r'[a-z]', password) and
        re.search(r'[0-9]', password) and
        re.search(r'[\W_]', password)
    )

def encrypt_password(password):
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(password.encode('utf-8'), salt)

def verify_password(password, hashed):
    return bcrypt.checkpw(password.encode('utf-8'), hashed.encode('utf-8'))

def authenticate(email, password):
    append_log(email, "Attempting to authenticate")
    for user in users:
        if user['email'] == email and verify_password(password, user['hashed_password']):
            append_log(email, "Authentication successful")
            print(f"Login successful! Welcome, {email}.")
            return user
    append_log(email, "Authentication failed")
    print("Login failed. Invalid email or password.")
    return None

def create_user(email, password, question, answer):
    if email_is_valid(email) and password_is_strong(password):
        encrypted_password = encrypt_password(password).decode('utf-8')
        encrypted_answer = encrypt_password(answer).decode('utf-8')
        users.append({
            'email': email,
            'hashed_password': encrypted_password,
            'security_question': question,
            'security_answer': encrypted_answer
        })
        update_csv(users)
        append_log(email, "User registered successfully")
        print("Registration successful!")
    else:
        print("Invalid email or weak password. Please try again.")

def reset_password(email):
    append_log(email, "Password reset initiated")
    for user in users:
        if user['email'] == email:
            print(f"Security Question: {user['security_question']}")
            answer = input("Security Answer: ")
            if verify_password(answer, user['security_answer']):
                new_password = input("Enter new password: ")
                if password_is_strong(new_password):
                    user['hashed_password'] = encrypt_password(new_password).decode('utf-8')
                    update_csv(users)
                    append_log(email, "Password reset successful")
                    print("Password reset successful!")
                else:
                    print("Weak password.")
            else:
                print("Incorrect answer.")
            return
    print("User not found.")

def lookup_geolocation(ip, email):
    try:
        response = requests.get(f'http://ip-api.com/json/{ip}')
        if response.ok:
            data = response.json()
            if data['status'] == 'success':
                print(f"\nCountry: {data['country']}\nCity: {data['city']}\nRegion: {data['regionName']}")
                print(f"Latitude: {data['lat']}\nLongitude: {data['lon']}\nTimezone: {data['timezone']}\nISP: {data['isp']}")
                append_log(email, f"Geolocation lookup for {ip}")
            else:
                print(f"Error: {data['message']}")
        else:
            print("Geolocation API request failed.")
    except requests.RequestException as req_err:
        print(f"Network error: {req_err}")

def valid_ip(ip):
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False

users = load_csv_data()

login_attempts = 0
MAX_LOGIN_ATTEMPTS = 5

while login_attempts < MAX_LOGIN_ATTEMPTS:
    action = input("\n1. Register\n2. Login\n3. Forgot Password\n4. Exit\nChoose an option: ")
    if action == '1':
        email = input("Enter email: ")
        password = input("Enter password: ")
        question = input("Enter security question: ")
        answer = input("Enter security answer: ")
        create_user(email, password, question, answer)
    elif action == '2':
        email = input("Enter email: ")
        password = input("Enter password: ")
        user = authenticate(email, password)
        if user:
            while True:
                post_login_action = input("\n1. Fetch Geolocation\n2. Logout\nChoose an option: ")
                if post_login_action == '1':
                    ip_input = input("Enter IP or leave blank for current IP: ").strip()
                    if not ip_input:
                        ip_input = requests.get('https://api.ipify.org').text
                    if valid_ip(ip_input):
                        lookup_geolocation(ip_input, user['email'])
                        log_activity(user['email'], "Geolocation fetched", ip_input)
                elif post_login_action == '2':
                    append_log(user['email'], "User logged out")
                    print("Logged out successfully.")
                    break
        else:
            login_attempts += 1
            remaining_attempts = MAX_LOGIN_ATTEMPTS - login_attempts
            print(f"Failed login attempt. You have {remaining_attempts} attempts left.")
            if login_attempts >= MAX_LOGIN_ATTEMPTS:
                print("Maximum login attempts exceeded. Exiting.")
                sys.exit()
    elif action == '3':
        reset_password(input("Enter your email: "))
    elif action == '4':
        sys.exit()
    else:
        print("Invalid choice.")
