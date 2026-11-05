import psutil
import socket
from database.database import Database

db = Database()
db.create_tables()

class ConnectionMonitor:

    def __init__(self):
        self.previous_connections = set()

    def get_connections(self):

        results = []

        for conn in psutil.net_connections(kind="inet"):

            try:

                pid = conn.pid or 0

                process_name = f"PID-{pid}"

                if pid:
                    try:
                        process_name = psutil.Process(pid).name()
                    except:
                        pass

                protocol = "TCP"

                if conn.type == socket.SOCK_DGRAM:
                    protocol = "UDP"

                local_ip = ""
                local_port = 0

                if conn.laddr:
                    local_ip = conn.laddr.ip
                    local_port = conn.laddr.port

                remote_ip = ""
                remote_port = 0

                if conn.raddr:
                    remote_ip = conn.raddr.ip
                    remote_port = conn.raddr.port

                results.append({
                    "process": process_name,
                    "pid": pid,
                    "protocol": protocol,
                    "local_ip": local_ip,
                    "local_port": local_port,
                    "remote_ip": remote_ip,
                    "remote_port": remote_port,
                    "status": conn.status
                })

            except Exception as e:
                print(f"Error: {e}")

        return results

    def detect_changes(self, current):

        current_set = set()

        for c in current:
            conn_id = (
                c["pid"],
                c["local_ip"],
                c["local_port"],
                c["remote_ip"],
                c["remote_port"],
                c["protocol"]
            )

            current_set.add(conn_id)

        new_connections = current_set - self.previous_connections
        closed_connections = self.previous_connections - current_set

        self.previous_connections = current_set

        return new_connections, closed_connections
