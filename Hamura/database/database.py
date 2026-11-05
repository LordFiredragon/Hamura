import sqlite3
from pathlib import Path

DB_FILE = Path("hamura.db")


class Database:

    def __init__(self):
        self.conn = sqlite3.connect(DB_FILE)
        self.conn.row_factory = sqlite3.Row
        self.cursor = self.conn.cursor()

    def create_tables(self):
        self.cursor.execute("""
        CREATE TABLE IF NOT EXISTS connections (
            id INTEGER PRIMARY KEY AUTOINCREMENT,

            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,

            process_name TEXT,
            pid INTEGER,

            local_ip TEXT,
            local_port INTEGER,

            remote_ip TEXT,
            remote_port INTEGER,

            protocol TEXT,
            status TEXT,

            country TEXT,
            isp TEXT,

            risk_score INTEGER DEFAULT 0,
            
            first_seen DATETIME,
            last_seen DATETIME,
        
            seen_count INTEGER DEFAULT 1,
        
            UNIQUE(process_name, remote_ip, remote_port)
        )
        """)

        self.cursor.execute("""
        CREATE TABLE IF NOT EXISTS ip_reputation (
            id INTEGER PRIMARY KEY AUTOINCREMENT,

            ip TEXT UNIQUE,

            country TEXT,
            isp TEXT,
            asn TEXT,

            risk_score INTEGER DEFAULT 0,
            risk_level TEXT DEFAULT 'SAFE',

            malicious INTEGER DEFAULT 0,
            last_checked DATETIME DEFAULT CURRENT_TIMESTAMP
        )
        """)

        self.cursor.execute("""
        CREATE TABLE IF NOT EXISTS rules (
            id INTEGER PRIMARY KEY AUTOINCREMENT,

            target_type TEXT,
            target_value TEXT,

            action TEXT,

            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
        """)

        self.cursor.execute("""
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,

            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,

            severity TEXT,
            title TEXT,
            description TEXT,

            ip TEXT,
            process_name TEXT
        )
        """)

        self.cursor.execute("""
        CREATE TABLE IF NOT EXISTS connection_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
        
            event_type TEXT,
        
            process_name TEXT,
            pid INTEGER,
        
            remote_ip TEXT,
            remote_port INTEGER,
            
            details TEXT
        )
        """)

        self.cursor.execute("""
        CREATE TABLE IF NOT EXISTS bandwidth_usage (

            id INTEGER PRIMARY KEY AUTOINCREMENT,
        
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
        
            process_name TEXT,
        
            pid INTEGER,
        
            upload_bytes INTEGER,
        
            download_bytes INTEGER
        
        )
        """)

        self.cursor.execute("""
        CREATE TABLE IF NOT EXISTS active_sessions (

            id INTEGER PRIMARY KEY AUTOINCREMENT,

            pid INTEGER,

            process_name TEXT,

            remote_ip TEXT,

            remote_port INTEGER,

            protocol TEXT,

            first_seen DATETIME DEFAULT CURRENT_TIMESTAMP,

            last_seen DATETIME DEFAULT CURRENT_TIMESTAMP,

            duration_seconds INTEGER DEFAULT 0,

            UNIQUE(
                pid,
                remote_ip,
                remote_port
            )
        )
        """)

        self.cursor.execute("""
        CREATE TABLE IF NOT EXISTS application_rules (

            id INTEGER PRIMARY KEY AUTOINCREMENT,

            process_name TEXT UNIQUE,

            action TEXT,

            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
        """)

        self.conn.commit()

    def save_connection(
            self,
            process_name,
            pid,
            local_ip,
            local_port,
            remote_ip,
            remote_port,
            protocol,
            status
    ):
        self.cursor.execute("""
        INSERT INTO connections (
            process_name,
            pid,
            local_ip,
            local_port,
            remote_ip,
            remote_port,
            protocol,
            status,
            first_seen,
            last_seen,
            seen_count
        )
        VALUES (
            ?, ?, ?, ?, ?, ?, ?, ?,
            CURRENT_TIMESTAMP,
            CURRENT_TIMESTAMP,
            1
        )
        ON CONFLICT(process_name, remote_ip, remote_port)
        DO UPDATE SET
            last_seen = CURRENT_TIMESTAMP,
            status = excluded.status,
            pid = excluded.pid,
            seen_count = seen_count + 1
        """, (
            process_name,
            pid,
            local_ip,
            local_port,
            remote_ip,
            remote_port,
            protocol,
            status
        ))


    def save_connections(self, connections):
        for c in connections:
            self.save_connection(
                c["process"],
                c["pid"],
                c["local_ip"],
                c["local_port"],
                c["remote_ip"],
                c["remote_port"],
                c["protocol"],
                c["status"]
            )

        self.conn.commit()

    def get_recent_connections(self, limit=100):
        self.cursor.execute("""
        SELECT *
        FROM connections
        ORDER BY timestamp DESC
        LIMIT ?
        """, (limit,))

        return self.cursor.fetchall()

    def save_ip_reputation(
            self,
            ip,
            country,
            isp,
            asn,
            risk_score=0,
            malicious=0):
        self.cursor.execute("""
        INSERT OR REPLACE INTO ip_reputation
        (
            ip,
            country,
            isp,
            asn,
            risk_score,
            malicious
        )
        VALUES (?, ?, ?, ?, ?, ?)
        """, (
            ip,
            country,
            isp,
            asn,
            risk_score,
            malicious
        ))

        self.conn.commit()

    def get_ip_info(self, ip):
        self.cursor.execute("""
        SELECT *
        FROM ip_reputation
        WHERE ip = ?
        """, (ip,))

        return self.cursor.fetchone()

    def get_known_ips(self):
        self.cursor.execute("""
        SELECT
            ip,
            country,
            isp,
            risk_score
        FROM ip_reputation
        """)

        return self.cursor.fetchall()

    def save_ip_info(
            self,
            ip,
            country,
            isp,
            asn):
        self.cursor.execute("""
        INSERT OR REPLACE INTO ip_reputation
        (
            ip,
            country,
            isp,
            asn
        )
        VALUES (?, ?, ?, ?)
        """, (
            ip,
            country,
            isp,
            asn
        ))

        self.conn.commit()

    def get_ip_record(self, ip):
        self.cursor.execute("""
        SELECT *
        FROM ip_reputation
        WHERE ip = ?
        """, (ip,))

        return self.cursor.fetchone()

    def update_ip_info(
            self,
            remote_ip,
            country,
            isp
    ):
        self.cursor.execute("""
        UPDATE connections
        SET
            country = ?,
            isp = ?
        WHERE remote_ip = ?
        """, (
            country,
            isp,
            remote_ip
        ))

        self.conn.commit()

    def get_connections_with_intel(
            self,
            limit=500
    ):
        self.cursor.execute("""
        SELECT
            c.*,
            r.country AS geo_country,
            r.isp AS geo_isp,
            r.risk_score AS geo_risk_score
        FROM connections c
        LEFT JOIN ip_reputation r
            ON c.remote_ip = r.ip
        ORDER BY c.last_seen DESC
        LIMIT ?
        """, (limit,))

        return self.cursor.fetchall()

    def update_session(
            self,
            pid,
            process_name,
            remote_ip,
            remote_port,
            protocol):
        self.cursor.execute("""
        INSERT INTO active_sessions (

            pid,
            process_name,
            remote_ip,
            remote_port,
            protocol,

            first_seen,
            last_seen

        )
        VALUES (

            ?, ?, ?, ?, ?,

            CURRENT_TIMESTAMP,
            CURRENT_TIMESTAMP
        )

        ON CONFLICT(pid, remote_ip, remote_port)

        DO UPDATE SET

            last_seen=CURRENT_TIMESTAMP
        """,
                            (
                                pid,
                                process_name,
                                remote_ip,
                                remote_port,
                                protocol
                            ))

        self.conn.commit()

    def update_threat_score(
            self,
            ip,
            score,
            level):
        self.cursor.execute("""
        UPDATE ip_reputation
        SET
            risk_score = ?,
            risk_level = ?
        WHERE ip = ?
        """, (
            score,
            level,
            ip
        ))

        self.conn.commit()

    def get_high_risk_ips(
            self,
            minimum_score=10
    ):
        self.cursor.execute("""
        SELECT *
        FROM ip_reputation
        WHERE risk_score >= ?
        ORDER BY risk_score DESC
        """, (minimum_score,))

        return self.cursor.fetchall()

    def create_alert(
            self,
            severity,
            title,
            description,
            ip,
            process_name):
        self.cursor.execute("""
        INSERT INTO alerts (
            severity,
            title,
            description,
            ip,
            process_name
        )
        VALUES (?, ?, ?, ?, ?)
        """, (
            severity,
            title,
            description,
            ip,
            process_name
        ))

        self.conn.commit()

    def get_alerts(self):
        self.cursor.execute("""
        SELECT *
        FROM alerts
        ORDER BY timestamp DESC
        """)

        return self.cursor.fetchall()

    def get_alert_count(self):
        self.cursor.execute(
            """
            SELECT COUNT(*)
            FROM alerts
            """
        )

        return self.cursor.fetchone()[0]

    def add_rule(
            self,
            target_type,
            target_value,
            action):
        self.cursor.execute("""
        INSERT INTO rules(
            target_type,
            target_value,
            action
        )
        VALUES (?, ?, ?)
        """, (
            target_type,
            target_value,
            action
        ))

        self.conn.commit()

    def get_rule_count(self):
        self.cursor.execute(
            """
            SELECT COUNT(*)
            FROM rules
            """
        )

        return self.cursor.fetchone()[0]

    def get_rules(self):
        self.cursor.execute("""
        SELECT *
        FROM rules
        ORDER BY created_at DESC
        """)

        return self.cursor.fetchall()

    def top_processes(self):
        self.cursor.execute("""
        SELECT
            process_name,
            COUNT(*) AS connection_count
        FROM active_sessions
        GROUP BY process_name
        ORDER BY connection_count DESC
        """)

        return self.cursor.fetchall()

    def get_active_sessions(self):
        self.cursor.execute("""
        SELECT *
        FROM active_sessions
        WHERE
            datetime(last_seen)
            >= datetime(
                'now',
                '-5 minutes'
            )
        ORDER BY last_seen DESC
        """)
        return self.cursor.fetchall()

    def get_all_sessions(self):
        self.cursor.execute("""
        SELECT *
        FROM active_sessions
        ORDER BY last_seen DESC
        """)

        return self.cursor.fetchall()

    def get_session_count(self):
        self.cursor.execute("""
        SELECT COUNT(*)
        FROM active_sessions
        """)

        return self.cursor.fetchone()[0]

    def get_active_connections(self):
        self.cursor.execute("""
        SELECT *
        FROM connections
        WHERE
            datetime(last_seen)
            >= datetime(
                'now',
                '-5 minutes'
            )
        ORDER BY last_seen DESC
        """)

        return self.cursor.fetchall()

    def get_active_connections_with_intel(self):
        self.cursor.execute("""
        SELECT
            c.*,
            r.country AS geo_country,
            r.isp AS geo_isp,
            r.risk_score AS geo_risk_score
        FROM connections c
        LEFT JOIN ip_reputation r
            ON c.remote_ip = r.ip
        WHERE
            datetime(c.last_seen)
            >= datetime('now', '-5 minutes')
        ORDER BY c.last_seen DESC
        """)

        return self.cursor.fetchall()

    def get_high_risk_count(self):
        self.cursor.execute("""
        SELECT COUNT(*)
        FROM ip_reputation
        WHERE risk_score >= 50
        """)

        return self.cursor.fetchone()[0]

    def get_process_count(self):
        self.cursor.execute("""
        SELECT COUNT(DISTINCT process_name)
        FROM active_sessions
        """)

        return self.cursor.fetchone()[0]

    def get_top_process(self):
        self.cursor.execute("""
        SELECT
            process_name,
            COUNT(*) AS total
        FROM active_sessions
        GROUP BY process_name
        ORDER BY total DESC
        LIMIT 1
        """)

        return self.cursor.fetchone()

    def add_application_rule(
            self,
            process_name,
            action):
        self.cursor.execute("""
        INSERT OR REPLACE INTO application_rules
        (
            process_name,
            action
        )
        VALUES (?, ?)
        """, (
            process_name,
            action
        ))

        self.conn.commit()

    def get_application_rule(
            self,
            process_name):
        self.cursor.execute("""
        SELECT *
        FROM application_rules
        WHERE process_name = ?
        """, (
            process_name,
        ))

        return self.cursor.fetchone()

    def get_application_rules(self):
        self.cursor.execute("""
        SELECT *
        FROM application_rules
        ORDER BY process_name
        """)

        return self.cursor.fetchall()

    def get_blocked_ips(self):
        self.cursor.execute("""
        SELECT *
        FROM rules
        WHERE action = 'BLOCK'
        ORDER BY created_at DESC
        """)

        return self.cursor.fetchall()

    def close(self):
        self.conn.close()


if __name__ == "__main__":

    db = Database()

    db.create_tables()
    ips = db.get_known_ips()

    print("\nKnown IPs:")

    for ip in ips:
        print(ip)

    print("Database initialized")

    connections = db.get_recent_connections()

    if not connections:
        print("No connections logged yet.")

    for conn in connections:
        print(conn)

    db.close()
    print("Hamura database created.")
