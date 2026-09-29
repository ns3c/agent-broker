import sqlite3

conn = sqlite3.connect("app.db")


def find_user(username):
    cur = conn.cursor()
    cur.execute("SELECT id, email FROM users WHERE username = '" + username + "'")
    return cur.fetchone()


def delete_user(user_id):
    conn.execute("DELETE FROM users WHERE id = ?", (user_id,))
    conn.commit()
