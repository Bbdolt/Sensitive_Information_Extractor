import tkinter as tk
from tkinter import ttk
import threading
import re

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
    {
        "Rule": "((access=)|(adm=)|(admin=)|(alter=)|(cfg=)|(clone=)|(config=)|(create=)|(dbg=)|(debug=)|(delete=)|(disable=)|(edit=)|(enable=)|(exec=)|(execute=)|(grant=)|(load=)|(make=)|(modify=)|(rename=)|(reset=)|(root=)|(shell=)|(test=)|(toggl=))",
        "VerboseName": "调试逻辑参数"
    },
    {
        "Rule": "(=(https?)(://|%3a%2f%2f))",
        "VerboseName": "URL 作为值"
    },
    {
        "Rule": "(type\\=\\\"file\\\")",
        "VerboseName": "上传表单"
    },
    {
        "Rule": "((size=)|(page=)|(num=)|(limit=)|(start=)|(end=)|(count=))",
        "VerboseName": "DoS 参数"
    },
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
    {
        "Rule": "(((|\\\\)(|'|\")(|[\\.\\w]{1,10})(([u](ser|name|sername))|(account)|((((create|update)((d|r)|(by|on|at)))|(creator))))(|[\\.\\w]{1,10})(|\\\\)(|'|\")( |)(:|=|!=|[\\)]{0,1}\\.val\\()( |)(|\\\\)('|\")([^'\"]+?)(|\\\\)('|\")(|,|\\)))|((|\\\\)('|\")([^'\"]+?)(|\\\\)('|\")(|\\\\)(|'|\")( |)(:|[=]{1,3}|![=]{1,2})( |)(|[\\.\\w]{1,10})(([u](ser|name|sername))|(account)|((((create|update)((d|r)|(by|on|at)))|(creator))))(|[\\.\\w]{1,10})(|\\\\)(|'|\")))",
        "VerboseName": "用户名字段"
    },
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
    },
    {
        "Rule": "(?:\"|')((?:(?:[a-zA-Z]{1,10}://|//)[^\"'/]{1,}\\.[a-zA-Z]{2,}[^\"']{0,}))(?:(?:\"|')|\\s|$)",
        "VerboseName": "URL 字段"
    }
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

def extract_thread():
    extract_button.config(state=tk.DISABLED, text="提取中...")
    input_text = input_box.get("1.0", tk.END)
    matched, errors = match_rules(input_text)

    def update_output():
        output_box.config(state=tk.NORMAL)
        output_box.delete("1.0", tk.END)
        
        results = []
        # 添加匹配结果
        for text, rule_name in matched:
            results.append(f"{text}     ( {rule_name})")
        
        # 添加错误信息
        results.extend(errors)
        
        if results:
            output_box.insert(tk.END, "\n".join(results))
        else:
            output_box.insert(tk.END, "无匹配")
        
        output_box.config(state=tk.DISABLED)
        extract_button.config(state=tk.NORMAL, text="提取")

    root.after(0, update_output)

def on_extract_click():
    threading.Thread(target=extract_thread).start()

# GUI 界面
root = tk.Tk()
root.title("敏感信息提取器_ByBbdolt")
root.geometry("1000x600")
root.minsize(800, 500)
root.wm_iconbitmap("icon.ico")

style = ttk.Style()
style.theme_use('default')
style.configure("TButton", font=("Arial", 12), padding=6, 
                background="#4CAF50", foreground="white")
style.map("TButton", foreground=[('disabled', '#aaaaaa')],
          background=[('disabled', '#cccccc')])

main_frame = ttk.Frame(root, padding=10)
main_frame.pack(fill=tk.BOTH, expand=True)

main_frame.columnconfigure(0, weight=3)
main_frame.columnconfigure(1, weight=0)
main_frame.columnconfigure(2, weight=3)
main_frame.rowconfigure(0, weight=1)

input_box = tk.Text(main_frame, wrap=tk.WORD, font=("Arial", 12))
input_box.grid(row=0, column=0, sticky="nsew", padx=(0, 10))

extract_button = ttk.Button(main_frame, text="提取", 
                           command=on_extract_click, style="TButton")
extract_button.grid(row=0, column=1, padx=5, pady=5)

output_box = tk.Text(main_frame, wrap=tk.WORD, font=("Arial", 12), 
                    state=tk.DISABLED)
output_box.grid(row=0, column=2, sticky="nsew", padx=(10, 0))

root.mainloop()