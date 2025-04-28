# Sensitive_Information_Extractor
通过输入文本提取敏感信息（HaE规则），做这款工具的初衷是在用 yakit 的导入 hae 规则后，mitm 时常会出现一些问题，所以直接不在 yakit 做规则匹配而是将流量转到本地进行处理。
转发流量和流量处理是两个独立的工作，所以不会影响 yakit 正常抓包和引起卡顿。可以对匹配规则进行修改只留下重要的规则。
1、点击开始劫持（会监听本地 9015 端口），并会对 yakit 发送过来的流量进行规则匹配，并进行标色
![image](https://github.com/user-attachments/assets/cceac519-35c1-4ac1-a7bd-5d021f69c0d2)
2、需要在 yakit 中开启流量转发的插件（源码如下）
```go
# 本地开启一个提取敏感信息的服务链接为 https://github.com/Bbdolt/Sensitive_Information_Extractor
packet1=`POST / HTTP/1.1
Content-Type: application/json
Host: 127.0.0.1:9015

{"url": "__url__","body": "__body__"}`

# 添加白名单
whitelist = [
    "google.com",
    "microsoft.com",
    "github.com",
    "gitlab.com",
    "apple.com",
    "amazon.com",
    "cloudflare.com",
    "akamai.com",
    "fastly.net",
    "facebook.com",
    "fbcdn.net",
    "twitter.com",
    "linkedin.com",
    "youtube.com",
    "ytimg.com",
    "gvt1.com",
    "gvt2.com",
    "googleapis.com",
    "gstatic.com",
    "firebaseio.com",
    "slack.com",
    "discord.com",
    "fofa.info",
    "hunter.io",
    "qianxin.com",
    "360.cn",
    "qq.com",
    "weixin.qq.com",
    "baidu.com",
    "bdstatic.com",
    "bilibili.com",
    "hdslb.com",
    "sina.com.cn",
    "weibo.com",
    "alibaba.com",
    "aliyun.com",
    "taobao.com",
    "tmall.com",
    "jd.com",
    "mi.com",
    "xiaomi.com",
    "dingtalk.com",
    "bytedance.com",
    "toutiao.com",
    "douyin.com",
    "pinduoduo.com",
    "bing.com",
    "skype.com",
    "mozilla.org",
    "ubuntu.com",
    "debian.org",
    "wikipedia.org"
]

# mirrorHTTPFlow 会镜像所有的流量到这里，包括 .js / .css / .jpg 这类一般会被劫持程序过滤的请求
mirrorHTTPFlow = func(isHttps /*bool*/, url /*string*/, req /*[]byte*/, rsp /*[]byte*/, body /*[]byte*/) {
    if str.StringContainsAnyOfSubString(url, whitelist) {
        return // 白名单命中，直接跳过，不做后续处理
    }
    url=codec.EncodeBase64(url)
    body=codec.EncodeBase64(body)
    packet2=packet1
    packet2=str.ReplaceAll(string(packet2) /*type: string*/, "__url__" /*type: string*/, string(url) /*type: string*/)
    packet2=str.ReplaceAll(string(packet2) /*type: string*/, "__body__" /*type: string*/, string(body) /*type: string*/)
    rsp1, req1 = poc.HTTP(packet2)~
}
```
![image](https://github.com/user-attachments/assets/b2198aa8-0f3f-4ec7-8c35-70767bf62008)
![image](https://github.com/user-attachments/assets/8c747dac-ff7a-424b-8be0-9ef6034ac889)




