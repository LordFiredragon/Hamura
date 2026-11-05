import psutil
import time

class BandwidthMonitor:

    def __init__(self):

        self.previous = psutil.net_io_counters()

    def get_speed(self):

        current = psutil.net_io_counters()

        upload = (
            current.bytes_sent -
            self.previous.bytes_sent
        )

        download = (
            current.bytes_recv -
            self.previous.bytes_recv
        )

        self.previous = current

        return {
            "upload": upload,
            "download": download
        }


if __name__ == "__main__":

    monitor = BandwidthMonitor()

    while True:

        time.sleep(1)

        s = monitor.get_speed()

        print(
            f"UP {s['upload']/1024:.2f} KB/s | "
            f"DOWN {s['download']/1024:.2f} KB/s"
        )