# Extract LOGs from TP-Link Router Model WDR4300
# Log Format
#"Timestamp","Event Created","Module","Severity","Message"
#"1596857513","Aug  7 21:31:54","DHCP","INFO","DHCPS:Send ACK to 192.168.0.100"
#"1596857517","Aug  7 21:31:58","DHCP","INFO","DHCPS:Recv REQUEST from E2:E2:E2:E2:2E:E2"
#"1596857517","Aug  7 21:31:58","DHCP","INFO","DHCPS:Send ACK to 192.168.0.101"
#"1596859121","Aug  7 21:58:42","DHCP","INFO","DHCPC Send REQUEST to server ffffffff with request ip eeeeeeee"
#"1596859123","Aug  7 21:58:44","DHCP","INFO","DHCPC Recv ACK from server ffffffff with ip eeeeeeee lease time 3600"
#"1596859123","Aug  7 21:58:44","DHCP","INFO","DHCPC:GET ip:eeeeeeee mask:ffffff00 gateway:ffffffff dns1:cccccccc dns2:dddddddd static route:0"
#"1596859124","Aug  7 21:58:45","DHCP","NOTICE","Dynamic IP(DHCP Client) obtained an IP successfully"
import urllib.request
import base64
import re
import time
from datetime import datetime, timedelta, timezone

epoch = datetime(1970, 1, 1)


ip = "192.168.0.1"
protocol = "http"

username = "admin"
password = ""

url = "{}://{}/userRpm/SystemLog.txt".format(protocol,ip)

base64string = base64.b64encode(('%s:%s' % (username, password)).encode('ascii')).decode('ascii')

req = urllib.request.Request(url)
req.add_header("Authorization", "Basic %s" % base64string)
req.add_header("Referer", "{}://{}/userRpm/SystemLogRpm.htm".format(protocol,ip))
f = urllib.request.urlopen(req)
content = f.read()
decoded_content = content.decode('utf-8', errors="ignore")

time_diff = 0
now_time = datetime.now()
current_year = str(now_time.year)

print('"Timestamp","Event Created","Module","Severity","Message"')
for line in decoded_content.splitlines():
    line = line.strip()
    if len(line) == 0:
        continue
    if line.startswith("#"):
        if "Time = " in line:
            time = line.split("=")
            time = time[1].strip()
            time = time.split(" ")
            dt = datetime.strptime(time[0] + " " + time[2],  "%Y-%m-%d %H:%M:%S")
            current_year = time[0].split("-")[0]
            time_diff = (dt - now_time) // timedelta(seconds=1)
        continue
    columns = list(map(lambda x: x.strip(), line.split("\t")))
    dt = datetime.strptime(columns[0] + " " + current_year,  "%b %d %H:%M:%S %Y")
    dt = dt + timedelta(seconds=time_diff)
    integer_timestamp = (dt - epoch) // timedelta(seconds=1)
    print('"' + str(integer_timestamp) + '","' + columns[0] + '","' + columns[1] + '","' + columns[2] +  '","' + columns[3] + '"')