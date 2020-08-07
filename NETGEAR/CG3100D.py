# Extract LOGs from Netgear Router Model CG3100D
# Log Format
#"Timestamp","Event Created","Severity","Message"
#"1596831677","Fri Aug 07 20:21:17 2020","Aviso (6)","WiFi Interface [wl0] set to Channel 1 (Side-Band Channel:5) - Reason:INTERFERENCE"
#"1596830772","Fri Aug 07 20:06:12 2020","Aviso (6)","WiFi Interface [wl0] set to Channel 6 (Side-Band Channel:2) - Reason:INTERFERENCE"
#"1596826250","Fri Aug 07 18:50:50 2020","Aviso (6)","WiFi Interface [wl0] set to Channel 1 (Side-Band Channel:5) - Reason:INTERFERENCE"
#"1596825353","Fri Aug 07 18:35:53 2020","Critico (3)","No Ranging Response received - T3 time-out;CM-MAC=ff:ff:ff:ff:ff:ff;CMTS-MAC=ee:ee:ee:ee:ee:ee;CM-QOS=1.1;CM-VER=3.0;"
#"1596825339","Fri Aug 07 18:35:39 2020","Error (4)","Missing BP Configuration Setting TLV Type: 17.8;CM-MAC=ff:ff:ff:ff:ff:ff;CMTS-MAC=ee:ee:ee:ee:ee:ee;CM-QOS=1.1;CM-VER=3.0;"
#"1596825339","Fri Aug 07 18:35:39 2020","Error (4)","Missing BP Configuration Setting TLV Type: 17.9;CM-MAC=ff:ff:ff:ff:ff:ff;CMTS-MAC=ee:ee:ee:ee:ee:ee;CM-QOS=1.1;CM-VER=3.0;"
#"1596743059","Thu Aug 06 19:44:19 2020","Critico (3)","SYNC Timing Synchronization failure - Failed to acquire QAM/QPSK symbol timing;;CM-MAC=ff:ff:ff:ff:ff:ff;CMTS-MAC=00:00:00:00:00:00;CM-QOS=1.0;CM-VER=3.0;"

import urllib.request
import base64
from html.parser import HTMLParser
import time
from datetime import datetime, timedelta, timezone

epoch = datetime(1970, 1, 1)


ip = "192.168.1.1"
protocol = "http"

username = "admin"
password = ""

url = "{}://{}/RgEventLogs.asp".format(protocol,ip)

base64string = base64.b64encode(('%s:%s' % (username, password)).encode('ascii')).decode('ascii')

req = urllib.request.Request(url)
req.add_header("Authorization", "Basic %s" % base64string)
try:
    f = urllib.request.urlopen(req)
except:
    f = urllib.request.urlopen(req)
content = f.read()
decoded_content = content.decode('utf-8', errors="ignore")

class MyHTMLParser(HTMLParser):
    def __init__(self):
        HTMLParser.__init__(self)
        self.rows = []
        self.tr = False
        self.tbody = False
        self.td = False
        self.data = []

    def handle_starttag(self, tag, attrs):
        tag = tag.lower()
        if tag == 'table':
            self.tbody = True
        elif tag == 'tr':
            if self.tr:
                # Bad programmers, not closing tags
                if len(self.data) == 3:
                    self.rows.append(self.data)
            self.tr = True
            self.data = []
        elif tag == 'td':
            self.td = True
            

    def handle_endtag(self, tag):
        tag = tag.lower()
        if tag == "table":
            self.tbody = False
        elif tag == "tr":
            self.tr = False
            if len(self.data) == 3:
                if self.data[0] == '':
                    return
                self.rows.append(self.data)
        elif tag == 'td':
            self.td = False
        

    def handle_data(self, data):
        if self.tbody and self.tr and self.td:
            self.data.append(data.strip())

parser = MyHTMLParser()
parser.feed(decoded_content)


for row in parser.rows:
    split_lngth = len(row[0].split(" "))
    if split_lngth == 1:
        print('"Timestamp","Event Created","Severity","Message"')
        continue
    elif split_lngth != 5:
        print('"0","' + row[0] + '","' + row[1] + '","' + row[2] + '"')
        continue
    dt = datetime.strptime(row[0],  "%a %b %d %H:%M:%S %Y")
    timestamp = (dt - epoch) / timedelta(seconds=1)
    integer_timestamp = (dt - epoch) // timedelta(seconds=1)

    print('"' + str(integer_timestamp) + '","' + row[0] + '","' + row[1] + '","' + row[2] + '"')

