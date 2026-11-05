import psutil


class TrafficMonitor:

    def __init__(self):

        self.old = psutil.net_io_counters()

    def get_speed(self):

        new = psutil.net_io_counters()

        upload = (
            new.bytes_sent
            - self.old.bytes_sent
        )

        download = (
            new.bytes_recv
            - self.old.bytes_recv
        )

        self.old = new

        return {
            "upload": upload,
            "download": download
        }