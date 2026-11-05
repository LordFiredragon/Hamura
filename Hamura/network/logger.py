from database.database import Database

db = Database()

def log_connection(conn):

    db.save_connection(
        conn["process"],
        conn["pid"],
        conn["local_ip"],
        conn["local_port"],
        conn["remote_ip"],
        conn["remote_port"],
        conn["protocol"],
        conn["status"]
    )
