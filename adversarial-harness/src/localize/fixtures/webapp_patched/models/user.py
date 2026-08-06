"""User data-access helpers."""

def find_user_by_name(conn, name):
    cur = conn.cursor()
    cur.execute("SELECT id, username, email FROM users WHERE username = ?", (name,))
    return cur.fetchone()
