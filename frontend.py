# frontend.py
import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext, filedialog
from backend import (
    php_xor_base64, php_eval_xor_base64, php_xor_raw,
    php_base64_response, java_aes_base64, java_aes_raw,
    java_aes_base64_response, default_aes, aes_with_magic,
    default_xor_base64, default_xor
)

class DecryptToolGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Webshell流量解密工具 v1.0")
        
        # 初始化变量
        self.tool_type = tk.StringVar(value="Godzilla")
        self.encrypt_type = tk.StringVar()
        self.data_type = tk.StringVar(value="请求体")
        self.encode_type = tk.StringVar(value="utf-8")
        self.key = tk.StringVar()
        self.input_hint = tk.StringVar(value="请输入完整的base64形式的请求体或响应体")
        self.file_content = None
        
        # 参数需求配置
        self.param_requirements = {
            "PHP_XOR_Base64": {"请求体": {"key": True, "encode": False}, "响应体": {"key": True, "encode": True}},
            "PHP_Eval_XOR_Base64": {"请求体": {"key": False, "encode": False}, "响应体": {"key": True, "encode": True}},
            "PHP_XOR_Raw": {"请求体": {"key": True, "encode": True}, "响应体": {"key": True, "encode": True}},
            "Java_AES_Base64": {"请求体": {"key": True, "encode": True}, "响应体": {"key": True, "encode": True}},
            "Java_AES_Raw": {"请求体": {"key": True, "encode": True}, "响应体": {"key": True, "encode": True}},
            "Default_AES": {"请求体": {"key": True, "encode": True}, "响应体": {"key": True, "encode": True}},
            "AES_With_Magic": {"请求体": {"key": True, "encode": True}, "响应体": {"key": True, "encode": True}},
            "Default_XOR_Base64": {"请求体": {"key": True, "encode": False}, "响应体": {"key": True, "encode": False}},
            "Default_XOR_Raw": {"请求体": {"key": True, "encode": False}, "响应体": {"key": True, "encode": False}}
        }
        
        self.create_widgets()
        self.update_encrypt_types()
        self.update_ui_state()  # 初始化UI状态

    def create_widgets(self):
        # 工具类型选择
        ttk.Label(self.root, text="工具类型:").grid(row=0, column=0, padx=5, pady=5, sticky="w")
        tool_combobox = ttk.Combobox(self.root, textvariable=self.tool_type, values=["Godzilla", "Behinder"])
        tool_combobox.grid(row=0, column=1, padx=5, pady=5, sticky="ew")
        tool_combobox.bind("<<ComboboxSelected>>", self.update_encrypt_types)

        # 加密方式选择
        ttk.Label(self.root, text="加密方式:").grid(row=1, column=0, padx=5, pady=5, sticky="w")
        self.encrypt_combobox = ttk.Combobox(self.root, textvariable=self.encrypt_type)
        self.encrypt_combobox.grid(row=1, column=1, padx=5, pady=5, sticky="ew")
        self.encrypt_combobox.bind("<<ComboboxSelected>>", self.update_ui_state)

        # 数据类型选择
        ttk.Label(self.root, text="数据类型:").grid(row=2, column=0, padx=5, pady=5, sticky="w")
        self.data_type_combobox = ttk.Combobox(self.root, textvariable=self.data_type, values=["请求体", "响应体"])
        self.data_type_combobox.grid(row=2, column=1, padx=5, pady=5, sticky="ew")
        self.data_type_combobox.bind("<<ComboboxSelected>>", self.update_ui_state)
        
        # 编码类型
        ttk.Label(self.root, text="编码类型:").grid(row=3, column=0, padx=5, pady=5, sticky="w")
        self.encode_combobox = ttk.Combobox(self.root, textvariable=self.encode_type, values=["utf-8", "gbk", "gb2312", "latin-1"])
        self.encode_combobox.grid(row=3, column=1, padx=5, pady=5, sticky="ew")

        # 密钥输入
        ttk.Label(self.root, text="解密密钥:").grid(row=4, column=0, padx=5, pady=5, sticky="w")
        self.key_entry = ttk.Entry(self.root, textvariable=self.key)
        self.key_entry.grid(row=4, column=1, padx=5, pady=5, sticky="ew")

        # 文件选择和输入提示
        file_frame = ttk.Frame(self.root)
        ttk.Button(file_frame, text="选择文件", command=self.load_file).pack(side=tk.LEFT, padx=5)
        ttk.Label(file_frame, textvariable=self.input_hint, foreground="gray").pack(side=tk.LEFT)
        file_frame.grid(row=5, column=0, columnspan=2, pady=5, sticky="w")

        # 输入输出区域
        notebook = ttk.Notebook(self.root)
        input_frame = ttk.Frame(notebook)
        output_frame = ttk.Frame(notebook)
        
        self.input_text = scrolledtext.ScrolledText(input_frame, width=60, height=15)
        self.input_text.pack(padx=5, pady=5, fill=tk.BOTH, expand=True)
        
        self.output_text = scrolledtext.ScrolledText(output_frame, width=60, height=15)
        self.output_text.pack(padx=5, pady=5, fill=tk.BOTH, expand=True)
        
        notebook.add(input_frame, text="加密内容")
        notebook.add(output_frame, text="解密结果")
        notebook.grid(row=6, column=0, columnspan=2, padx=5, pady=5)

        # 操作按钮
        btn_frame = ttk.Frame(self.root)
        ttk.Button(btn_frame, text="执行解密", command=self.decrypt).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="清空", command=self.clear).pack(side=tk.RIGHT, padx=5)
        btn_frame.grid(row=7, column=0, columnspan=2, pady=5)

    def load_file(self):
        """直接加载文件内容到内存，不显示在文本框"""
        file_path = filedialog.askopenfilename()
        if not file_path:
            return
        
        try:
            with open(file_path, "rb") as f:
                self.file_content = f.read().decode('utf-8', errors='ignore')
            messagebox.showinfo("文件加载", f"已成功加载文件: {file_path}")
        except Exception as e:
            messagebox.showerror("文件错误", f"无法读取文件: {str(e)}")
            self.file_content = None

    def update_encrypt_types(self, event=None):
        """更新加密方式选项"""
        tool = self.tool_type.get()
        if tool == "Godzilla":
            encrypt_types = [
                "PHP_XOR_Base64", "PHP_Eval_XOR_Base64",
                "PHP_XOR_Raw", "Java_AES_Base64", "Java_AES_Raw"
            ]
        else:
            encrypt_types = [
                "Default_AES", "AES_With_Magic",
                "Default_XOR_Base64", "Default_XOR_Raw"
            ]
        self.encrypt_combobox["values"] = encrypt_types
        self.encrypt_type.set(encrypt_types[0])
        self.update_ui_state()

    def update_ui_state(self, event=None):
        """更新界面组件状态"""
        encrypt_type = self.encrypt_type.get()
        data_type = self.data_type.get()
        requirements = self.param_requirements.get(encrypt_type, {}).get(data_type, {})

        # 更新密钥输入状态
        key_required = requirements.get("key", False)
        self.key_entry.config(state=tk.NORMAL if key_required else tk.DISABLED)
        
        # 更新编码选择状态
        encode_required = requirements.get("encode", False)
        self.encode_combobox.config(state="readonly" if encode_required else tk.DISABLED)

        # 更新输入提示
        hex_types = {"PHP_XOR_Raw", "Java_AES_Raw", "AES_With_Magic", "Default_XOR_Raw"}
        self.input_hint.set(
            "请输入完整的hex形式的请求体或响应体" if encrypt_type in hex_types 
            else "请输入完整的base64形式的请求体或响应体"
        )

    def get_input_data(self):
        """优先返回文件内容，其次返回文本框内容"""
        return self.file_content if self.file_content else self.input_text.get("1.0", tk.END).strip()

    def process_decryption(self, data):
        encrypt_type = self.encrypt_type.get()
        data_type = self.data_type.get()
        requirements = self.param_requirements.get(encrypt_type, {}).get(data_type, {})
        
        key = self.key.get() if requirements.get("key") else ""
        encode = self.encode_type.get() if requirements.get("encode") else ""

        if requirements.get("key") and not key:
            raise ValueError("需要提供解密密钥")
        if requirements.get("encode") and not encode:
            raise ValueError("需要选择编码类型")

        try:
            if self.tool_type.get() == "Godzilla":
                handlers = {
                    "PHP_XOR_Base64": {
                        "请求体": lambda: php_xor_base64(data, key),
                        "响应体": lambda: php_base64_response(data, key, encode)
                    },
                    "PHP_Eval_XOR_Base64": {
                        "请求体": lambda: (
                            f"Webshell脚本:\n{php_eval_xor_base64(data)[0]}\n\n"
                            f"执行内容:\n{php_eval_xor_base64(data)[1]}"
                        ),
                        "响应体": lambda: php_base64_response(data, key, encode)
                    },
                    "PHP_XOR_Raw": {
                        "请求体": lambda: php_xor_raw(data, key, encode),
                        "响应体": lambda: php_xor_raw(data, key, encode)
                    },
                    "Java_AES_Base64": {
                        "请求体": lambda: java_aes_base64(data, key, encode),
                        "响应体": lambda: java_aes_base64_response(data, key, encode)
                    },
                    "Java_AES_Raw": {
                        "请求体": lambda: java_aes_raw(data, key, encode),
                        "响应体": lambda: java_aes_raw(data, key, encode)
                    }
                }
            else:
                handlers = {
                    "Default_AES": {
                        "请求体": lambda: default_aes(data, key, encode),
                        "响应体": lambda: default_aes(data, key, encode)
                    },
                    "AES_With_Magic": {
                        "请求体": lambda: aes_with_magic(data, key, encode),
                        "响应体": lambda: aes_with_magic(data, key, encode)
                    },
                    "Default_XOR_Base64": {
                        "请求体": lambda: default_xor_base64(data, key),
                        "响应体": lambda: default_xor_base64(data, key)
                    },
                    "Default_XOR_Raw": {
                        "请求体": lambda: default_xor(data, key),
                        "响应体": lambda: default_xor(data, key)
                    }
                }
            return handlers[encrypt_type][data_type]()
        except KeyError:
            raise ValueError("不支持的组合类型")
        except Exception as e:
            raise ValueError(f"解密失败: {str(e)}")

    def decrypt(self):
        try:
            data = self.get_input_data()
            if not data:
                raise ValueError("请输入加密内容或选择文件")
                
            result = self.process_decryption(data)
            self.output_text.delete("1.0", tk.END)
            self.output_text.insert(tk.END, result)
        except Exception as e:
            messagebox.showerror("解密错误", str(e))

    def clear(self):
        self.file_content = None
        self.input_text.delete("1.0", tk.END)
        self.output_text.delete("1.0", tk.END)
        messagebox.showinfo("清空", "已清除所有输入内容")

if __name__ == "__main__":
    root = tk.Tk()
    app = DecryptToolGUI(root)
    root.mainloop()
