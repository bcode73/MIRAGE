import winreg

class RegistryPlanter:
    def plant_fake_recent_file(self, fake_path):
        key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs", 0, winreg.KEY_SET_VALUE)
        winreg.SetValueEx(key, "FakeDownload", 0, winreg.REG_SZ, fake_path)
        print(f"[+] Planted fake recent file: {fake_path}")