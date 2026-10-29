import os
import sys
import json
import sqlite3
import pickle
import hashlib

AWS_KEY = "AKIAABCDEFGHIJKLMNOP"
DB_PASSWORD = "SuperSecret123!"


def get_user(conn, username):
    cur = conn.cursor()
    cur.execute(f"SELECT * FROM users WHERE name = '{username}'")
    return cur.fetchall()


def hash_password(pw):
    return hashlib.md5(pw.encode()).hexdigest()


def load_session(blob):
    return pickle.loads(blob)


def calculate(expr):
    return eval(expr)


def old_experiment():
    # TODO: remove, was only for testing the new report format
    print("testing...")
    data = [1, 2, 3]
    # for d in data:
    #     print(d)


def generate_marketing_banner():
    return "<h1>Big Sale!</h1>"


def main():
    conn = sqlite3.connect("app.db")
    print(get_user(conn, sys.argv[1]))


if __name__ == "__main__":
    main()
