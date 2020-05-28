# -*- coding:utf-8 -*-
import time, datetime, os, json
import urllib, urllib2
import hashlib, base64, hmac, random
import logging
import logging.handlers
import sys
reload(sys)
sys.setdefaultencoding('utf-8')
## 腾讯云API接口签名
QCLOUD_SecretId = '你的SecretId'
QCLOUD_SecretKey = '你的SecretKey'

def spider_url(url):
    print url
    request = urllib2.Request(url)
    content = urllib2.urlopen(request).read()
    return content

def getRecordList(req_action='RecordList',  req_extra_params='', retry_NUM=3):

    req_method = 'GET' # GET  POST
    req_api = 'cns.api.qcloud.com/v2/index.php' # DNS的api地址
    req_timestamp = int(time.time()) # 1520422452
    req_nonce = random.randint(1000, 1000000) # 随机正整数
    req_secretid = QCLOUD_SecretId  # 密钥ID，用作参数
    req_secretkey = QCLOUD_SecretKey  # 密钥key，用作加密
    req_signature_method = 'HmacSHA256' # HmacSHA1(默认), HmacSHA256

    # 请求方法 + 请求主机 +请求路径 + ? + 请求字符串
    req_params = "Action=%s&Timestamp=%s&Nonce=%s&SecretId=%s&SignatureMethod=%s&domain=%s" % (req_action, req_timestamp, req_nonce, req_secretid, req_signature_method,req_extra_params)

    req_params_array = req_params.split('&')
    req_params_array = sorted(req_params_array)
    req_params2 = '&'.join(req_params_array)
    req_uri = "%s%s?%s" % (req_method, req_api, req_params2)
    req_signature = urllib.quote(base64.b64encode(hmac.new(req_secretkey, req_uri, digestmod=hashlib.sha256).digest()))
 
    req_url = "https://%s?%s&Signature=%s" % (req_api, req_params2, req_signature)
    res = spider_url(req_url)
    retry_idx = 0
    while not res and retry_idx < retry_NUM:
        retry_idx += 1
        res = spider_url(req_url)
    if res:
        resJson = json.loads(res)
        print resJson
        resJson = resJson['message']

        print resJson
        return resJson
    else:
        return None


def modify_jiexi(ipv6,):
    subDomain = '你的域名前缀'
    req_action = 'RecordModify'
    domain = 'xxxxxx.com'
    recordId = '你要修改的recordId' # id从 getRecordList()函数获取
    recordType = 'AAAA' # AAAA为IPV6 A 为 IPV4
    recordLine = u"\u9ed8\u8ba4" # '默认'俩字的utf-8 Unicode
    value = ipv6 # '你要修改的ipv6

    req_method = 'GET'  # GET  POST
    req_api = 'cns.api.qcloud.com/v2/index.php'
    req_timestamp = int(time.time())  # 1520422452
    req_nonce = random.randint(1000, 1000000)  # 随机正整数
    req_secretid = QCLOUD_SecretId  # 密钥ID，用作参数
    req_secretkey = QCLOUD_SecretKey  # 密钥key，用作加密
    req_signature_method = 'HmacSHA256'  # HmacSHA1(默认), HmacSHA256
    req_signature = ''

    # 请求方法 + 请求主机 +请求路径 + ? + 请求字符串
    req_params = "Action=%s&Timestamp=%s&Nonce=%s&SecretId=%s&SignatureMethod=%s&domain=%s&recordId=%s&subDomain=%s&recordType=%s&recordLine=%s&value=%s" % (
    req_action, req_timestamp, req_nonce, req_secretid, req_signature_method,domain, recordId,subDomain,recordType,recordLine,value)

    req_params_array = req_params.split('&')
    req_params_array = sorted(req_params_array)
    req_params2 = '&'.join(req_params_array)
    req_uri = "%s%s?%s" % (req_method, req_api, req_params2)
    req_signature = urllib.quote(
        base64.b64encode(hmac.new(req_secretkey, req_uri, digestmod=hashlib.sha256).digest()))  # urllib.quote(xxx)

    req_url = "https://%s?%s&Signature=%s" % (req_api, req_params2, req_signature)
    res = spider_url(req_url)
    resJson = json.loads(res)
    print resJson
    resJson = resJson['message']
    print resJson
    return resJson


def get_ipv6():
    import subprocess
    import socket
    import re
    #
    child = subprocess.Popen("ipconfig", shell=True, stdout=subprocess.PIPE)
    out = child.communicate() # 保存ipconfig中的所有信息
    content = out[0]
    content = content.replace(' ','')
    lines = content.split('\n')
    address = None
    for line in lines:
        if u'临时IPv6地址'.encode('gbk') in line: # 如果想用IPV4自行用re匹配
            print line.decode('gbk')
            ipv6_pattern = '(([a-f0-9]{1,4}:){7}[a-f0-9]{1,4})'
            m = re.findall(ipv6_pattern, str(line))
            address = m[0][0]
            print address
    return address
    pass


def ping_ipv6():
    google_ipv6_url = '2001:dc7:1000::1'
    response = os.system("ping -c 1 " + google_ipv6_url)
    if response == 0:
        ok = True
    else:
        ok = False
    print ok
    return ok
    pass



def get_IP2():
    import socket
    # family = socket.AF_INET    # ipv4时改为socket.AF_INET
    family = socket.AF_INET6    # ipv6时改为socket.AF_INET6
    # server = '8.8.8.8'         # ipv4时改为'8.8.8.8'
    server = '2001:4860:4860::8888'         # ipv6时改为'2001:4860:4860::8888'
    s = socket.socket(family, socket.SOCK_DGRAM)
    s.connect((server, 80))
    my_ip = s.getsockname()[0]
    print my_ip
    return my_ip

def main():

    # 0获取RecordList
    req_action_query = 'RecordList'
    req_extra_params = 'xxxx.com'
    getRecordList(req_action_query, req_extra_params)
    # 1 获取ipv6
    ipv6 = get_ipv6()
    # 2 改解析
    while 1:
        if not ipv6 == None:
            break
        ipv6 = get_ipv6()
        print 'no matching ipv6'
        time.sleep(10)

    while 1:
        try:
            modify_jiexi(ipv6)
            success = 1
        except Exception as e:
            success = 0
            print e
        if success == 1:
            break
        time.sleep(60)

    pass


if __name__ == "__main__":

    while 1:
        main()
        time.sleep(10*60)
