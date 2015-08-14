-----------------------------
Name
--
The Open Tor Botnet (ZIB) Official Release
-----------------------------
Main information body
--
You need to use bitcoind.... I will not explain that.
ZIB is fully undetectable and bypasses all antivirus by running on top of Python27's pyinstaller, which is used for many legitimate programs. The only possibility of detection comes from the script, however, the script contains randomized-looking data through using a randomized AES key and initialization vector.
ZIB.py is the main project file. It has 2 errors so nobody who isn't qualified will compile it and do something hazardous.
intel.py is the chat bot, and it has 2 errors to prevent bad things from happening.
compileZIB.py is used by intel.py, started with chp.exe to run in the background.. 2 errors once again
ZIB_imports.txt contains all the imports for ZIB to use. They're appended to the script when compiling.
btcpurchases.txt includes all the bitcoin payments that are pending. Ones older than 24 hours are deleted.
channels.txt includes all completed BTC payments.
You want to point your webserver to dist\ for hosting the files.
chp.exe is required in the local dir.
For the IRC server, run bircd, set up an oper with the username Zlo and password RUSSIA!@#$RUSSIA!@#$RUSSIA!@#$RUSSIA!@#$. For the max users per ip set to 0 because tor users will look like 127.0.0.1Keep all scripts in Python27/Scripts.
Put nircmd in the local directory for editing file dates.
-----------------------------
Credits/Attribution
--
Zlo/ZIB/The Open Tor Botnet/Vladimir/DevilsAcid/Alexander
WhitePacket
Python
Socksipy
nircmd
chp
Bitcoin
Pyinstaller
That software was used in the making of this tool. No idea about their licensing so I'm crediting them anyways.
-----------------------------
Legal
--
ZIB is for legal, research purposes only. All of my writings that would be considered legal if they were not fantasy are entirely fictional.
I won't be held responsible or liable for any damages caused by running this application.
Use this software at your own liability.
Please don't use this for malicious purposes. This was released out of good will and for the benifit of others.
Don't modify/fork/profit off of this project, without proper attribution.
-----------------------------
Notes
--
Yes, everything still links to the original website and IRC channel. (ewww)
The default server won't accept new channels, you have to buy one to host there.
This is probably filled with terrible information, non-commented code, etc... My apologies for this work of "art".
Yes, I wrote the README in 3 minutes without proof-reading. Just releasing ZIB real quick.
-----------------------------
Contact
--
Email: whitepacket@sigaint.org
Jabber: whitepacket@fuckav.in
Twitter: @WhitePacket
BTC address: 1QASXpprwocj7Y65DghSjjgTXxrUHe6XEN (used to support my whitehat activities and successful completion of my endeavors).
PGP key:

-----BEGIN PGP PUBLIC KEY BLOCK-----
Version: GnuPG v2

mQENBFXNfgwBCACtq4nznr/SVM57LSgeXy+DfmdBIkUTi0mCHrY2nI1ekYHHozeW
FCo1yacPx7TzGQ6wILvHvgt8yKi8ke1FAGGA7O2fCCNNJ3j7jibhWI9LSUGNa5DO
Ek3iv4UsDS+QuZq1s+4cDA6E028a17JXW1Vtq/29Oy4f8B6MiBBFfe33pIBP0/az
FZg821A2IvRo1vNDNHMKM/RkOLmGI+bzl55wFp/5r5c80z7d67hZreY99d4WiIPQ
8/rO9tgaJwq1+zciLuLErxgz13mkKbQgbQ79gbd76vcZ+FhqkKK9WstD3Qr2ZHDE
astA8cTcPYv51DZ0Zue3xsvNUsyLrVGn4PNvABEBAAG0JVdoaXRlUGFja2V0IDx3
aGl0ZXBhY2tldEBzaWdhaW50Lm9yZz6JATkEEwEIACMFAlXNfgwCGwMHCwkIBwMC
AQYVCAIJCgsEFgIDAQIeAQIXgAAKCRCyuaK7+vbuLuB+B/9vplRJNzmGx0MPiYX3
AJZiBaQAAimDDbkpz6xN+KjRJqd+z0D/TfT9CE0REscPV4APpxE8kVMUwSgOya+Q
IDzfKu1eONiBhzIB2N7xkc9TGbkbkH9OaRRZEfHmYEFHuLZvXC6ply8a3y1Nsg7c
uxbXlTCCr19Yq9TowvUFjhYcOOLYijo0ew0TReVDVquH1M6od+ijVhuT9ged0aZe
YUOg1whWFjGSToFEu4S0y4SUNo5q0x2Wn18uPQXqnKrDjiQKNsWvZUXMqh6em3RF
3Ga87IMroQYq5lzob4AwMgYKSPCKG1FTz8460xdWO8xQOIfjeIcnT7qJ3dA58dSq
2ftyuQENBFXNfgwBCADsMzQ7X1ZbibgqHzpWf/C0vBce9Arr9Mcz7yGtZqFylw+Q
mWGNRmd5sHVDXu33vDFNYLMsTJZ/7jTnpg8P/GLQC7m1GzB9dq5k0icbax7I8tRX
3Peedrvi91ST7/U2N1xm2AHRbZzdtHB07eWk1/4rcEoHUwxESqtn6FnWMZPKf2+x
8lYWipMRDrgefYTKDeOjntNsvRWqQQ5jIEHYtFBscblvyGjO4iJP2veuRlUUI2uY
Mit9KINsjwIgoJ4v+sUdZAiVZC+sXBYcO9BpXB46tBOedn9ekGeYPvZUW4B+Ae3D
F9GbkFNixgCNtSzxaygYZZUdaF+q445icm0wsIcJABEBAAGJAR8EGAEIAAkFAlXN
fgwCGwwACgkQsrmiu/r27i50+gf/f2iacXu2b+Tz5nJOjq8JHzSOKOU7IE7sjbSZ
IPnRLffMqM3/qc8viZJ2P+YMYgx9t0qz16VjUbtu/kOB0FIQ0aYVWIOGrVAJjTA1
mWsy1buztRQwd9H+DGfIZiciAYi+TCBAuyWt7ZUoiDb4gmqWDAzapbtCJXBvIO2j
7zaZbKhjBuaI42lWhJwPoXnySWRteIs4ii+oAF6+jDnUmY1M8lCr21Ukj9JUhZrM
HoZDP9YN8jXC+25hF3Z34z6jJ8W4VeI5ViL6XmreA8wB9yyjnAxG5WXv1vkhsogB
vXT/kDEIeMeXl+yI8D+nzi3J1BdSn+4Xk3WsWFcv/G/1qc2ynQ==
=++w/
-----END PGP PUBLIC KEY BLOCK-----

-----------------------------
