import tkinter as tk
from tkinter import ttk
import threading
import re
import json
from http.server import BaseHTTPRequestHandler, HTTPServer
import socketserver
import base64
from socketserver import ThreadingMixIn

# 当前的下拉框选择项
current_status = None
# 记录所有匹配项
result_list = []
# 新增：HTTP 服务相关
server_running = False
httpd = None
js_data = []
class RequestHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        content_length = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(content_length)
        
        # 先快速响应
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"OK")
        data = json.loads(body)
        url = data.get('url', '')
        url = base64.b64decode(url).decode('utf-8')
        print("url:", url)
        if url in js_data:
            return
        if '.js' in url:
            js_data.append(url)
        # 后台处理
        try:
            data = json.loads(body)
            url = data.get('url', '')
            body_text = data.get('body', '')
            url = base64.b64decode(url).decode('utf-8')
            body_text = base64.b64decode(body_text).decode('utf-8')
            print("url:", url)
            threading.Thread(target=extract_thread, args=(url, body_text)).start()
        except Exception as e:
            pass
    # 覆盖log_message方法，阻止日志输出
    def log_message(self, format, *args):
        pass


class ThreadingHTTPServer(ThreadingMixIn, HTTPServer):
    daemon_threads = True  # 子线程异常时不会影响主线程

def start_http_server():
    global httpd
    server_address = ('127.0.0.1', 9015)
    httpd = ThreadingHTTPServer(server_address, RequestHandler)
    httpd.serve_forever()

def toggle_server():
    global server_running, httpd, server_thread
    if not server_running:
        server_thread = threading.Thread(target=start_http_server, daemon=True)
        server_thread.start()
        server_running = True
        server_button.config(text="关闭劫持", style="Stop.TButton")  # 变红
    else:
        if httpd:
            httpd.shutdown()
            httpd.server_close()
            httpd = None
        server_running = False
        server_button.config(text="开始劫持", style="Start.TButton")  # 变绿

# 规则匹配颜色
# 高危 红色
first_keywords = [
    "Swagger UI",
    "云密钥",
    "密码字段",
    "敏感字段",
    "企业微信密钥",
    "中国身份证号",
    "中国手机号",
    "手机号字段"
]

# 中危 橙色
second_keywords = [
    "Shiro Cookie",
    "JSON Web Token (JWT)",
    "Druid",
    "Windows 文件/目录路径",
    "JDBC连接",
    "URL 作为值",
    "授权头",
    "用户名字段"
]

# 低危 绿色
third_keywords = [
    "Ueditor",
    "PDF.js 查看器",
    "Java 反序列化",
    "URL 字段",
    "内网IP地址",
    "MAC地址",
    "上传表单"
]

# 信息 无色
info_keywords = [
    "电子邮件",
    "调试逻辑参数",
    "DoS 参数"
]


# 规则如下
rules = [
    {
        "Rule": "(=deleteMe|rememberMe=)",
        "VerboseName": "Shiro Cookie"
    },
    {
        "Rule": "(eyJ[A-Za-z0-9_-]{10,}\\.[A-Za-z0-9._-]{10,})",
        "VerboseName": "JSON Web Token (JWT)"
    },
    {
        "Rule": "((swagger-ui.html)|(\\\"swagger\\\":)|(Swagger UI)|(swaggerUi)|(swaggerVersion))",
        "VerboseName": "Swagger UI"
    },
    {
        "Rule": "(ueditor\\.(config|all)\\.js)",
        "VerboseName": "Ueditor"
    },
    {
        "Rule": "(Druid Stat Index)",
        "VerboseName": "Druid"
    },
    {
        "Rule": "(pdf.worker)",
        "VerboseName": "PDF.js 查看器"
    },
    {
        "Rule": "(javax\\.faces\\.ViewState)",
        "VerboseName": "Java 反序列化"
    },
    # {
    #     "Rule": "((access=)|(adm=)|(admin=)|(alter=)|(cfg=)|(clone=)|(config=)|(create=)|(dbg=)|(debug=)|(delete=)|(disable=)|(edit=)|(enable=)|(exec=)|(execute=)|(grant=)|(load=)|(make=)|(modify=)|(rename=)|(reset=)|(root=)|(shell=)|(test=)|(toggl=))",
    #     "VerboseName": "调试逻辑参数"
    # },
    # {
    #     "Rule": "(=(https?)(://|%3a%2f%2f))",
    #     "VerboseName": "URL 作为值"
    # },
    # {
    #     "Rule": "(type\\=\\\"file\\\")",
    #     "VerboseName": "上传表单"
    # },
    # {
    #     "Rule": "((size=)|(page=)|(num=)|(limit=)|(start=)|(end=)|(count=))",
    #     "VerboseName": "DoS 参数"
    # },
    {
        "Rule": "(([a-z0-9]+[_|\\.])*[a-z0-9]+@([a-z0-9]+[-|_|\\.])*[a-z0-9]+\\.((?!js|css|jpg|jpeg|png|ico)[a-z]{2,5}))",
        "VerboseName": "电子邮件"
    },
    {
        "Rule": "[^0-9]((\\d{8}(0\\d|10|11|12)([0-2]\\d|30|31)\\d{3}$)|(\\d{6}(18|19|20)\\d{2}(0[1-9]|10|11|12)([0-2]\\d|30|31)\\d{3}(\\d|X|x)))[^0-9]",
        "VerboseName": "中国身份证号"
    },
    {
        "Rule": "[^\\w]((?:(?:\\+|0{0,2})86)?1(?:(?:3[\\d])|(?:4[5-79])|(?:5[0-35-9])|(?:6[5-7])|(?:7[0-8])|(?:8[\\d])|(?:9[189]))\\d{8})[^\\w]",
        "VerboseName": "中国手机号"
    },
    {
        "Rule": "[^0-9]((127\\.0\\.0\\.1)|(10\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3})|(172\\.((1[6-9])|(2\\d)|(3[01]))\\.\\d{1,3}\\.\\d{1,3})|(192\\.168\\.\\d{1,3}\\.\\d{1,3}))",
        "VerboseName": "内网IP地址"
    },
    {
        "Rule": "(^([a-fA-F0-9]{2}(:[a-fA-F0-9]{2}){5})|[^a-zA-Z0-9]([a-fA-F0-9]{2}(:[a-fA-F0-9]{2}){5}))",
        "VerboseName": "MAC地址"
    },
    {
        "Rule": "(((access)(|-|_)(key)(|-|_)(id|secret))|(LTAI[a-z0-9]{12,20}))",
        "VerboseName": "云密钥"
    },
    {
        "Rule": "[^\\w]([a-zA-Z]:\\\\\\\\?(?:[^\u003c\u003e:/\\\\|?*]+\\\\\\\\?)*)([^\u003c\u003e:/\\\\|?*]+(?:\\.[^\u003c\u003e:/\\\\|?*]+)?)",
        "VerboseName": "Windows 文件/目录路径"
    },
    {
        "Rule": "(((|\\\\)(|'|\")(|[\\.\\w]{1,10})([p](ass|wd|asswd|assword))(|[\\.\\w]{1,10})(|\\\\)(|'|\")( |)(:|[=]{1,3}|![=]{1,2}|[\\)]{0,1}\\.val\\()( |)(|\\\\)('|\")([^'\"]+?)(|\\\\)('|\")(|,|\\)))|((|\\\\)('|\")([^'\"]+?)(|\\\\)('|\")(|\\\\)(|'|\")( |)(:|[=]{1,3}|![=]{1,2})( |)(|[\\.\\w]{1,10})([p](ass|wd|asswd|assword))(|[\\.\\w]{1,10})(|\\\\)(|'|\")))",
        "VerboseName": "密码字段"
    },
    # {
    #     "Rule": "(((|\\\\)(|'|\")(|[\\.\\w]{1,10})(([u](ser|name|sername))|(account)|((((create|update)((d|r)|(by|on|at)))|(creator))))(|[\\.\\w]{1,10})(|\\\\)(|'|\")( |)(:|=|!=|[\\)]{0,1}\\.val\\()( |)(|\\\\)('|\")([^'\"]+?)(|\\\\)('|\")(|,|\\)))|((|\\\\)('|\")([^'\"]+?)(|\\\\)('|\")(|\\\\)(|'|\")( |)(:|[=]{1,3}|![=]{1,2})( |)(|[\\.\\w]{1,10})(([u](ser|name|sername))|(account)|((((create|update)((d|r)|(by|on|at)))|(creator))))(|[\\.\\w]{1,10})(|\\\\)(|'|\")))",
    #     "VerboseName": "用户名字段"
    # },
    {
        "Rule": "((corp)(id|secret))",
        "VerboseName": "企业微信密钥"
    },
    {
        "Rule": "(jdbc:[a-z:]+://[a-z0-9\\.\\-_:;=/@?,\u0026]+)",
        "VerboseName": "JDBC连接"
    },
    {
        "Rule": "((basic [a-z0-9=:_\\+\\/-]{5,100})|(bearer [a-z0-9_.=:_\\+\\/-]{5,100}))",
        "VerboseName": "授权头"
    },
    {
        "Rule": "(((\\[)?('|\")?([\\.\\w]{0,10})(key|secret|token|config|auth|access|admin|ticket)([\\.\\w]{0,10})('|\")?(\\])?( |)(:|=|!=|[\\)]{0,1}\\.val\\()( |)('|\")([^'\"]+?)('|\")(|,|\\)))|((|\\\\)('|\")([^'\"]+?)(|\\\\)('|\")(|\\\\)(|'|\")( |)(:|[=]{1,3}|![=]{1,2})( |)(|[\\.\\w]{1,10})(key|secret|token|config|auth|access|admin|ticket)(|[\\.\\w]{1,10})(|\\\\)(|'|\")))",
        "VerboseName": "敏感字段"
    },
    {
        "Rule": "(((|\\\\)(|'|\")(|[\\w]{1,10})(mobile|phone|sjh|shoujihao|concat)(|[\\.\\w]{1,10})(|\\\\)(|'|\")( |)(:|=|!=|[\\)]{0,1}\\.val\\()( |)(|\\\\)('|\")([^'\"]+?)(|\\\\)('|\")(|,|\\)))|((|\\\\)('|\")([^'\"]+?)(|\\\\)('|\")(|\\\\)(|'|\")( |)(:|[=]{1,3}|![=]{1,2})( |)(|[\\.\\w]{1,10})(mobile|phone|sjh|shoujihao|concat)(|[\\.\\w]{1,10})(|\\\\)(|'|\"))) ",
        "VerboseName": "手机号字段"
    }
    # ,
    # {
    #     "Rule": "(?:\"|')((?:(?:[a-zA-Z]{1,10}://|//)[^\"'/]{1,}\\.[a-zA-Z]{2,}[^\"']{0,}))(?:(?:\"|')|\\s|$)",
    #     "VerboseName": "URL 字段"
    # }
]

def match_rules(text):
    matched_data = []
    errors = []
    for rule in rules:
        rule_name = rule['VerboseName']
        pattern_str = rule['Rule']
        try:
            pattern = re.compile(pattern_str)
            for match in pattern.finditer(text):
                matched_text = match.group()
                matched_data.append((matched_text, rule_name))
        except re.error as e:
            errors.append(f"规则错误: {rule_name} ({e})")
    return matched_data, errors

import queue

result_queue = queue.Queue()

def extract_thread(url="", body=""):
    extract_button.config(state=tk.DISABLED, text="提取中...")
    input_text = input_box.get("1.0", tk.END)
    if url=="" and body=="":
        matched, errors = match_rules(input_text)
    else:
        matched,errors = match_rules(body)
    
    # 整理结果
    results = []
    if url=="" and body=="":
        for text, rule_name in matched:
            results.append(f"{text}  ({rule_name})  无url")
    else:
        for text, rule_name in matched:
            results.append(f"{text}  ({rule_name})  {url}")
    results.extend(errors)

    # 把结果推到队列里
    result_queue.put(results)

    # 触发主线程更新
    root.after(0, update_output)

def get_tag_by_line(line):
    if any(keyword in line for keyword in first_keywords):
        return "red_tag"
    elif any(keyword in line for keyword in second_keywords):
        return "orange_tag"
    elif any(keyword in line for keyword in third_keywords):
        return "green_tag"
    else:
        return None

def update_output():
    global result_list
    output_box.config(state=tk.NORMAL)

    existing_content = output_box.get("1.0", tk.END).strip().splitlines()
    combined_results = existing_content.copy()

    while not result_queue.empty():
        combined_results += result_queue.get()

    # 去重、去空、去除 '无匹配'
    result_list += list(dict.fromkeys(filter(lambda x: x and x != '无匹配', combined_results)))
    result_list = list(set(result_list))

    output_box.delete("1.0", tk.END)
    if result_list and current_status.get() == "ALL":
        for line in result_list:
            tag = get_tag_by_line(line)
            if tag:
                output_box.insert(tk.END, line + "\n\n", tag)
            else:
                output_box.insert(tk.END, line + "\n\n")
    elif result_list and current_status.get() != "ALL":
        for line in result_list:
            if current_status.get() in line:
                tag = get_tag_by_line(line)
                if tag:
                    output_box.insert(tk.END, line + "\n\n", tag)
                else:
                    output_box.insert(tk.END, line + "\n\n")
    else:
        output_box.insert(tk.END, "无匹配\n", "gray_tag")

    refresh_domains()
    output_box.config(state=tk.DISABLED)
    extract_button.config(state=tk.NORMAL, text="提取")

def refresh_domains():
    domains = set()
    for line in result_list:
        parts = line.split("  ")
        domain = parts[2].replace("https://", "").replace("http://", "")
        domain = domain.split("/")[0]
        domains.add(domain)
    domain_list = sorted(list(domains))
    domain_list.insert(0, "ALL")  # 插到最前面
    domain_combobox['values'] = domain_list
    domain_combobox.set(current_status.get())

def on_extract_click():
    threading.Thread(target=extract_thread).start()

# 添加清空结果按钮
def clear_output():
    global js_data
    js_data = []
    global result_list
    result_list = []
    current_status.set("ALL")
    domain_combobox['values'] = "ALL"
    domain_combobox.set(current_status.get())
    output_box.config(state=tk.NORMAL)  # 允许编辑
    output_box.delete("1.0", tk.END)   # 清空内容
    output_box.config(state=tk.DISABLED)  # 禁用编辑

import tkinter as tk
from tkinter import ttk

# GUI 界面
root = tk.Tk()
root.title("敏感信息提取器_ByBbdolt")
root.geometry("1000x600")
root.minsize(1152, 720)
try:
    root.iconbitmap("icon.ico")
except Exception as e:
    print("未找到icon.ico，忽略图标设置。")

current_status = tk.StringVar(value="ALL")

style = ttk.Style()
style.theme_use('default')
style.configure("TButton", font=("Arial", 12), padding=6, 
                background="#4CAF50", foreground="white")
style.map("TButton", foreground=[('disabled', '#aaaaaa')],
          background=[('disabled', '#cccccc')])
style.configure("Start.TButton", font=("Arial", 12), padding=6, 
                background="#4CAF50", foreground="white")
style.map("Start.TButton", foreground=[('disabled', '#aaaaaa')],
          background=[('disabled', '#cccccc')])

style.configure("Stop.TButton", font=("Arial", 12), padding=6, 
                background="#f44336", foreground="white")  # 红色
style.map("Stop.TButton", foreground=[('disabled', '#aaaaaa')],
          background=[('disabled', '#cccccc')])

main_frame = ttk.Frame(root, padding=10)
main_frame.pack(fill=tk.BOTH, expand=True)

main_frame.columnconfigure(0, weight=5)
main_frame.columnconfigure(1, weight=0)
main_frame.columnconfigure(2, weight=2)
main_frame.rowconfigure(0, weight=1)

# 输入框
input_box = tk.Text(main_frame, wrap=tk.WORD, font=("Arial", 12))
input_box.grid(row=0, column=0, sticky="nsew", padx=(0, 10))

# 下拉框
domain_combobox = ttk.Combobox(main_frame, textvariable=current_status, state="readonly", font=("Arial", 12))
domain_combobox.grid(row=0, column=1, padx=5, pady=(0, 5), sticky="n")
domain_combobox['values'] = ["ALL"]
domain_combobox.set("ALL")
domain_combobox.bind("<<ComboboxSelected>>", lambda event: update_output())

# 提取按钮
extract_button = ttk.Button(main_frame, text="提取", 
                           command=on_extract_click, style="TButton")
extract_button.grid(row=0, column=1, padx=5, pady=5)

# 右边加一个Frame，用来放输出框和滚动条
output_frame = ttk.Frame(main_frame)
output_frame.grid(row=0, column=2, sticky="nsew", padx=(10, 0))

output_frame.rowconfigure(0, weight=1)
output_frame.columnconfigure(0, weight=1)

# 输出框
output_box = tk.Text(output_frame, wrap=tk.WORD, font=("Arial", 12), 
                     state=tk.DISABLED)
output_box.grid(row=0, column=0, sticky="nsew")

# 输出框的滚动条
output_scrollbar = ttk.Scrollbar(output_frame, orient=tk.VERTICAL, command=output_box.yview)
output_scrollbar.grid(row=0, column=1, sticky="ns")

output_box.config(yscrollcommand=output_scrollbar.set)
output_box.tag_configure("red_tag", foreground="red")
output_box.tag_configure("orange_tag", foreground="orange")
output_box.tag_configure("green_tag", foreground="green")
output_box.tag_configure("gray_tag", foreground="gray")


# 劫持按钮
server_button = ttk.Button(main_frame, text="开始劫持", 
                           command=toggle_server, style="Start.TButton")
server_button.grid(row=1, column=0, padx=5, pady=5, sticky="w")

# 清空按钮
clear_button = ttk.Button(main_frame, text="清空结果", 
                          command=clear_output, style="TButton")
clear_button.grid(row=1, column=2, padx=5, pady=5, sticky="e")  # 放在第二行，右侧

root.mainloop()