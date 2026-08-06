"""User data-access helpers."""

def find_user_by_name(conn, name):
    cur = conn.cursor()
    query = "SELECT id, username, email FROM users WHERE username = '%s'" % name
    cur.execute(query)
    return cur.fetchone()
