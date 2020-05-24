# 腾讯云动态域名 Tencent Cloud Dynamic DNS #

获取本机IPV6地址，上传到腾讯云的域名解析列表，从而达到动态域名的效果

由于家里的路由器每次重启都会重新分配IPV6，导致外部无法通过域名访问家里设备，因此写了此DDNS的脚本。

此脚本只限于Windows版本，linux有现成的脚本，自行百度。

## 0、准备工作 ##
1、首先你得买个域名，腾讯云的域名一年几十块钱

2、申请腾讯云的API 秘钥和ID

## 1、获取本地IPV6地址 ##
通过windows的 ipconfig 命令获取，用re匹配ipv6，我用的是临时IPV6地址，临时IPV6一般是能有效访问的ip，IPV6很安全，一条宽带能分配大概10的20次方个ip，`(16**4)**4=18445618199572250625`个ip，扫到天荒地老也扫不到。

    import subprocess
    import re
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

## 2、获取你的解析列表ID ##
需要定义以下几个参数：

    req_method = 'GET' # GET  POST
    req_api = 'cns.api.qcloud.com/v2/index.php' # DNS的api地址
    req_timestamp = int(time.time()) # 1520422452
    req_nonce = random.randint(1000, 1000000) # 随机正整数
    req_secretid = QCLOUD_SecretId  # 密钥ID，用作参数
    req_secretkey = QCLOUD_SecretKey  # 密钥key，用作加密
    req_signature_method = 'HmacSHA256' # HmacSHA1(默认), HmacSHA256

生成请求字符串：

    req_params = "Action=%s&Timestamp=%s&Nonce=%s&SecretId=%s&SignatureMethod=%s&domain=%s" % (req_action, req_timestamp, req_nonce, req_secretid, req_signature_method,req_extra_params)

需要把参数从A-Z排序，生成新的请求字符串

    req_params_array = req_params.split('&')
    req_params_array = sorted(req_params_array)
    req_params2 = '&'.join(req_params_array)
	req_uri = "%s%s?%s" % (req_method, req_api, req_params2)

生成签名signature

用你的secretKey使用HmacSHA256加密方法生成一串字符

	req_signature = urllib.quote(base64.b64encode(hmac.new(req_secretkey, req_uri, digestmod=hashlib.sha256).digest()))
 
生成最终的带签名的请求URL：

	req_url = "https://%s?%s&Signature=%s" % (req_api, req_params2, req_signature)


然后打开 `req_url` 链接就能看到解析列表的ID了，记下需要修改的ID，后面修改的时候会用到

## 3、修改解析值 ##
修改解析值和获取解析列表是同一个步骤，只是参数不同

1、先生成请求url，2、参数排序，3、生成签名，4、生成带签名的请求url，5、执行请求

## 4、写个死循环，10分钟执行一次 ##
把脚本添加到任务计划程序，设置开机启动，用pythonw运行

    while 1:
        main()
        time.sleep(10*60)
