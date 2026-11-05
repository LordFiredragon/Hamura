import subprocess


class Firewall:

    @staticmethod
    def block_ip(ip):

        rule_out = f"Hamura_Block_Out_{ip}"
        rule_in = f"Hamura_Block_In_{ip}"

        cmd_out = [
            "netsh",
            "advfirewall",
            "firewall",
            "add",
            "rule",
            f"name={rule_out}",
            "dir=out",
            "action=block",
            f"remoteip={ip}"
        ]
        cmd_in = [
            "netsh",
            "advfirewall",
            "firewall",
            "add",
            "rule",
            f"name={rule_in}",
            "dir=in",
            "action=block",
            f"remoteip={ip}"
        ]

        try:
            result_out = subprocess.run(
                cmd_out,
                capture_output=True,
                text=True
            )

            result_in = subprocess.run(
                cmd_in,
                capture_output=True,
                text=True
            )

            return (
                    result_out.returncode == 0
                    and
                    result_in.returncode == 0
            )

        except Exception as e:
            print(e)
            return False

    @staticmethod
    def unblock_ip(ip):

        rule_out = f"Hamura_Block_Out_{ip}"
        rule_in = f"Hamura_Block_In_{ip}"

        cmd_out = [
            "netsh",
            "advfirewall",
            "firewall",
            "delete",
            "rule",
            f"name={rule_out}"
        ]
        cmd_in = [
            "netsh",
            "advfirewall",
            "firewall",
            "delete",
            "rule",
            f"name={rule_in}"
        ]

        try:
            result_out = subprocess.run(
                cmd_out,
                capture_output=True,
                text=True
            )

            result_in = subprocess.run(
                cmd_in,
                capture_output=True,
                text=True
            )

            return (
                    result_out.returncode == 0
                    and
                    result_in.returncode == 0
            )

        except Exception as e:
            print(e)
            return False