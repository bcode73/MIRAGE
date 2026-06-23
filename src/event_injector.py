import subprocess
import random

class EventInjector:
    def inject_fake_logon(self):
        fake_ip = f"192.168.{random.randint(1,255)}.{random.randint(1,255)}"
        fake_user = "Admin"
        # Uses wevtutil to write a custom event into the Security log
        cmd = f'wevtutil epl Security fake_security.evtx /ow:true'
        subprocess.run(cmd, shell=True, capture_output=True)
        print(f"[+] Injected fake logon event from IP {fake_ip}")