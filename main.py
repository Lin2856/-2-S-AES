import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
import numpy as np
import sys


class SAESEncryptor:
    def __init__(self):
        # S-AES 标准S盒
        self.s_box = [
            [0x9, 0x4, 0xA, 0xB],
            [0xD, 0x1, 0x8, 0x5],
            [0x6, 0x2, 0x0, 0x3],
            [0xC, 0xE, 0xF, 0x7]
        ]

        # S-AES 逆S盒
        self.inv_s_box = [
            [0xA, 0x5, 0x9, 0xB],
            [0x1, 0x7, 0x8, 0xF],
            [0x6, 0x0, 0x2, 0x3],
            [0xC, 0x4, 0xD, 0xE]
        ]

        self.round_const = [0x80, 0x30]  # 轮常量
        self.debug_mode = False

    def activate_debug(self):
        self.debug_mode = True

    def deactivate_debug(self):
        self.debug_mode = False

    def str_to_bin(self, text):
        """字符串转二进制"""
        return ''.join(format(ord(c), '08b') for c in text)

    def bin_to_str(self, bin_str):
        """二进制转字符串"""
        chars = []
        for i in range(0, len(bin_str), 8):
            byte = bin_str[i:i + 8]
            if byte != '00000000':
                chars.append(chr(int(byte, 2)))
        return ''.join(chars)

    def bin_to_matrix(self, bin_str):
        """16位二进制转2x2状态矩阵"""
        if len(bin_str) != 16:
            raise ValueError(f"输入必须为16位，当前长度: {len(bin_str)}")

        matrix = np.zeros((2, 2), dtype=int)
        matrix[0, 0] = int(bin_str[0:4], 2)
        matrix[1, 0] = int(bin_str[4:8], 2)
        matrix[0, 1] = int(bin_str[8:12], 2)
        matrix[1, 1] = int(bin_str[12:16], 2)

        if self.debug_mode:
            print(f"二进制转矩阵: {bin_str} ->\n{matrix}")
        return matrix

    def matrix_to_bin(self, matrix):
        """状态矩阵转16位二进制"""
        bin_str = ""
        bin_str += format(matrix[0, 0], '04b')
        bin_str += format(matrix[1, 0], '04b')
        bin_str += format(matrix[0, 1], '04b')
        bin_str += format(matrix[1, 1], '04b')

        if self.debug_mode:
            print(f"矩阵转二进制:\n{matrix} -> {bin_str}")
        return bin_str

    def expand_key(self, key):
        """密钥扩展生成3轮密钥"""
        if len(key) != 16:
            raise ValueError(f"密钥必须为16位，当前长度: {len(key)}")

        w0 = key[0:8]
        w1 = key[8:16]

        if self.debug_mode:
            print(f"\n=== 密钥扩展 ===")
            print(f"w0: {w0}, w1: {w1}")

        # 计算轮密钥1
        temp = self.g_transform(w1, 1)
        w2 = self.bin_xor(w0, temp)
        w3 = self.bin_xor(w2, w1)

        # 计算轮密钥2
        temp = self.g_transform(w3, 2)
        w4 = self.bin_xor(w2, temp)
        w5 = self.bin_xor(w4, w3)

        round_keys = [w0 + w1, w2 + w3, w4 + w5]

        if self.debug_mode:
            print(f"g(w1): {temp}")
            print(f"w2: {w2}, w3: {w3}")
            print(f"w4: {w4}, w5: {w5}")
            print(f"轮密钥0: {round_keys[0]}")
            print(f"轮密钥1: {round_keys[1]}")
            print(f"轮密钥2: {round_keys[2]}")

        return round_keys

    def g_transform(self, word, round_num):
        """密钥扩展的g函数"""
        # 循环左移4位
        rotated = word[4:8] + word[0:4]

        # S盒替换
        sub_result = ""
        sub_result += self.nibble_sub(rotated[0:4], self.s_box)
        sub_result += self.nibble_sub(rotated[4:8], self.s_box)

        # 与轮常量异或
        rcon = format(self.round_const[round_num - 1], '08b')
        result = self.bin_xor(sub_result, rcon)

        if self.debug_mode:
            print(f"g函数(轮{round_num}):")
            print(f"  输入: {word}")
            print(f"  循环移位: {rotated}")
            print(f"  S盒替换: {sub_result}")
            print(f"  RCON: {rcon}")
            print(f"  结果: {result}")

        return result

    def nibble_sub(self, nibble, box):
        """半字节替换"""
        if len(nibble) != 4:
            raise ValueError(f"半字节必须为4位，当前长度: {len(nibble)}")

        row = int(nibble[0:2], 2)
        col = int(nibble[2:4], 2)
        return format(box[row][col], '04b')

    def matrix_sub(self, matrix, box):
        """矩阵半字节替换"""
        new_matrix = matrix.copy()
        for i in range(2):
            for j in range(2):
                nibble = format(matrix[i, j], '04b')
                new_matrix[i, j] = int(self.nibble_sub(nibble, box), 2)
        return new_matrix

    def shift_row(self, matrix):
        """行移位"""
        new_matrix = matrix.copy()
        new_matrix[1, 0], new_matrix[1, 1] = new_matrix[1, 1], new_matrix[1, 0]

        if self.debug_mode:
            print("行移位:")
            print(f"  前: {matrix[1, 0]:04b} {matrix[1, 1]:04b}")
            print(f"  后: {new_matrix[1, 0]:04b} {new_matrix[1, 1]:04b}")

        return new_matrix

    def inv_shift_row(self, matrix):
        """逆行移位"""
        return self.shift_row(matrix)

    def mix_col(self, matrix):
        """列混淆"""
        new_matrix = np.zeros((2, 2), dtype=int)
        new_matrix[0, 0] = self.gf_mul(1, matrix[0, 0]) ^ self.gf_mul(4, matrix[1, 0])
        new_matrix[1, 0] = self.gf_mul(4, matrix[0, 0]) ^ self.gf_mul(1, matrix[1, 0])
        new_matrix[0, 1] = self.gf_mul(1, matrix[0, 1]) ^ self.gf_mul(4, matrix[1, 1])
        new_matrix[1, 1] = self.gf_mul(4, matrix[0, 1]) ^ self.gf_mul(1, matrix[1, 1])

        if self.debug_mode:
            print("列混淆:")
            print(f"  输入: {matrix[0, 0]:04b} {matrix[0, 1]:04b}")
            print(f"        {matrix[1, 0]:04b} {matrix[1, 1]:04b}")
            print(f"  输出: {new_matrix[0, 0]:04b} {new_matrix[0, 1]:04b}")
            print(f"        {new_matrix[1, 0]:04b} {new_matrix[1, 1]:04b}")

        return new_matrix

    def inv_mix_col(self, matrix):
        """逆列混淆"""
        new_matrix = np.zeros((2, 2), dtype=int)
        new_matrix[0, 0] = self.gf_mul(9, matrix[0, 0]) ^ self.gf_mul(2, matrix[1, 0])
        new_matrix[1, 0] = self.gf_mul(2, matrix[0, 0]) ^ self.gf_mul(9, matrix[1, 0])
        new_matrix[0, 1] = self.gf_mul(9, matrix[0, 1]) ^ self.gf_mul(2, matrix[1, 1])
        new_matrix[1, 1] = self.gf_mul(2, matrix[0, 1]) ^ self.gf_mul(9, matrix[1, 1])

        if self.debug_mode:
            print("逆列混淆:")
            print(f"  输入: {matrix[0, 0]:04b} {matrix[0, 1]:04b}")
            print(f"        {matrix[1, 0]:04b} {matrix[1, 1]:04b}")
            print(f"  输出: {new_matrix[0, 0]:04b} {new_matrix[0, 1]:04b}")
            print(f"        {new_matrix[1, 0]:04b} {new_matrix[1, 1]:04b}")

        return new_matrix

    def gf_mul(self, a, b):
        """GF(2^4)域乘法"""
        if a == 0 or b == 0:
            return 0

        product = 0
        a_temp = a

        for _ in range(4):
            if b & 1:
                product ^= a_temp
            high_bit = a_temp & 0x8
            a_temp <<= 1
            if high_bit:
                a_temp ^= 0x13  # 模多项式x^4 + x + 1
            a_temp &= 0xF
            b >>= 1

        return product

    def bin_xor(self, bin1, bin2):
        """二进制异或"""
        if len(bin1) != len(bin2):
            raise ValueError(f"异或长度不匹配: {len(bin1)} vs {len(bin2)}")
        return ''.join('1' if b1 != b2 else '0' for b1, b2 in zip(bin1, bin2))

    def add_round_key(self, matrix, round_key):
        """轮密钥加"""
        key_matrix = self.bin_to_matrix(round_key)
        new_matrix = matrix.copy()

        for i in range(2):
            for j in range(2):
                new_matrix[i, j] ^= key_matrix[i, j]

        if self.debug_mode:
            print(f"轮密钥加:")
            print(f"  状态: {matrix[0, 0]:04b} {matrix[0, 1]:04b}")
            print(f"        {matrix[1, 0]:04b} {matrix[1, 1]:04b}")
            print(f"  密钥: {key_matrix[0, 0]:04b} {key_matrix[0, 1]:04b}")
            print(f"        {key_matrix[1, 0]:04b} {key_matrix[1, 1]:04b}")
            print(f"  结果: {new_matrix[0, 0]:04b} {new_matrix[0, 1]:04b}")
            print(f"        {new_matrix[1, 0]:04b} {new_matrix[1, 1]:04b}")

        return new_matrix

    def encrypt(self, plaintext, key):
        """加密过程"""
        if self.debug_mode:
            print(f"\n{'=' * 50}")
            print(f"开始加密")
            print(f"明文: {plaintext}")
            print(f"密钥: {key}")
            print(f"{'=' * 50}")

        round_keys = self.expand_key(key)
        state = self.bin_to_matrix(plaintext)

        if self.debug_mode:
            print(f"\n--- 第0轮: 初始密钥加 ---")

        state = self.add_round_key(state, round_keys[0])

        if self.debug_mode:
            print(f"第0轮后状态: {self.matrix_to_bin(state)}")

        # 第1轮
        if self.debug_mode:
            print(f"\n--- 第1轮 ---")

        state = self.matrix_sub(state, self.s_box)
        if self.debug_mode:
            print(f"半字节代替后: {self.matrix_to_bin(state)}")

        state = self.shift_row(state)
        if self.debug_mode:
            print(f"行移位后: {self.matrix_to_bin(state)}")

        state = self.mix_col(state)
        if self.debug_mode:
            print(f"列混淆后: {self.matrix_to_bin(state)}")

        state = self.add_round_key(state, round_keys[1])
        if self.debug_mode:
            print(f"轮密钥加后: {self.matrix_to_bin(state)}")

        # 第2轮
        if self.debug_mode:
            print(f"\n--- 第2轮 ---")

        state = self.matrix_sub(state, self.s_box)
        if self.debug_mode:
            print(f"半字节代替后: {self.matrix_to_bin(state)}")

        state = self.shift_row(state)
        if self.debug_mode:
            print(f"行移位后: {self.matrix_to_bin(state)}")

        state = self.add_round_key(state, round_keys[2])
        if self.debug_mode:
            print(f"轮密钥加后: {self.matrix_to_bin(state)}")

        ciphertext = self.matrix_to_bin(state)

        if self.debug_mode:
            print(f"\n加密完成!")
            print(f"密文: {ciphertext}")
            print(f"{'=' * 50}")

        return ciphertext

    def decrypt(self, ciphertext, key):
        """解密过程"""
        if self.debug_mode:
            print(f"\n{'=' * 50}")
            print(f"开始解密")
            print(f"密文: {ciphertext}")
            print(f"密钥: {key}")
            print(f"{'=' * 50}")

        round_keys = self.expand_key(key)
        state = self.bin_to_matrix(ciphertext)

        if self.debug_mode:
            print(f"\n--- 第2轮逆操作 ---")

        state = self.add_round_key(state, round_keys[2])
        if self.debug_mode:
            print(f"轮密钥加后: {self.matrix_to_bin(state)}")

        state = self.inv_shift_row(state)
        if self.debug_mode:
            print(f"逆行移位后: {self.matrix_to_bin(state)}")

        state = self.matrix_sub(state, self.inv_s_box)
        if self.debug_mode:
            print(f"逆半字节代替后: {self.matrix_to_bin(state)}")

        # 第1轮逆操作
        if self.debug_mode:
            print(f"\n--- 第1轮逆操作 ---")

        state = self.add_round_key(state, round_keys[1])
        if self.debug_mode:
            print(f"轮密钥加后: {self.matrix_to_bin(state)}")

        state = self.inv_mix_col(state)
        if self.debug_mode:
            print(f"逆列混淆后: {self.matrix_to_bin(state)}")

        state = self.inv_shift_row(state)
        if self.debug_mode:
            print(f"逆行移位后: {self.matrix_to_bin(state)}")

        state = self.matrix_sub(state, self.inv_s_box)
        if self.debug_mode:
            print(f"逆半字节代替后: {self.matrix_to_bin(state)}")

        # 第0轮逆操作
        if self.debug_mode:
            print(f"\n--- 第0轮逆操作 ---")

        state = self.add_round_key(state, round_keys[0])
        if self.debug_mode:
            print(f"轮密钥加后: {self.matrix_to_bin(state)}")

        plaintext = self.matrix_to_bin(state)

        if self.debug_mode:
            print(f"\n解密完成!")
            print(f"明文: {plaintext}")
            print(f"{'=' * 50}")

        return plaintext


class DoubleEncrypt(SAESEncryptor):
    """双重S-AES加密"""

    def double_encrypt(self, plaintext, key):
        if len(key) != 32:
            raise ValueError("双重加密密钥必须为32位")

        key1 = key[:16]
        key2 = key[16:]

        intermediate = self.encrypt(plaintext, key1)
        return self.encrypt(intermediate, key2)

    def double_decrypt(self, ciphertext, key):
        if len(key) != 32:
            raise ValueError("双重解密密钥必须为32位")

        key1 = key[:16]
        key2 = key[16:]

        intermediate = self.decrypt(ciphertext, key2)
        return self.decrypt(intermediate, key1)


class TripleEncrypt(SAESEncryptor):
    """三重S-AES加密"""

    def triple_encrypt_32(self, plaintext, key):
        if len(key) != 32:
            raise ValueError("32位三重加密密钥必须为32位")

        key1 = key[:16]
        key2 = key[16:]

        step1 = self.encrypt(plaintext, key1)
        step2 = self.decrypt(step1, key2)
        return self.encrypt(step2, key1)

    def triple_decrypt_32(self, ciphertext, key):
        if len(key) != 32:
            raise ValueError("32位三重解密密钥必须为32位")

        key1 = key[:16]
        key2 = key[16:]

        step1 = self.decrypt(ciphertext, key1)
        step2 = self.encrypt(step1, key2)
        return self.decrypt(step2, key1)

    def triple_encrypt_48(self, plaintext, key):
        if len(key) != 48:
            raise ValueError("48位三重加密密钥必须为48位")

        key1 = key[:16]
        key2 = key[16:32]
        key3 = key[32:]

        step1 = self.encrypt(plaintext, key1)
        step2 = self.encrypt(step1, key2)
        return self.encrypt(step2, key3)

    def triple_decrypt_48(self, ciphertext, key):
        if len(key) != 48:
            raise ValueError("48位三重解密密钥必须为48位")

        key1 = key[:16]
        key2 = key[16:32]
        key3 = key[32:]

        step1 = self.decrypt(ciphertext, key3)
        step2 = self.decrypt(step1, key2)
        return self.decrypt(step2, key1)


class MiddleAttack:
    """中间相遇攻击实现"""

    def __init__(self, saes):
        self.saes = saes

    def attack(self, plaintext, ciphertext, max_keys=1000):
        encrypt_map = {}

        # 预计算K1加密结果
        for k1 in range(min(65536, max_keys)):
            key1 = format(k1, '016b')
            intermediate = self.saes.encrypt(plaintext, key1)
            encrypt_map[intermediate] = key1

        # 寻找匹配的K2
        found = []
        for k2 in range(min(65536, max_keys)):
            key2 = format(k2, '016b')
            intermediate = self.saes.decrypt(ciphertext, key2)
            if intermediate in encrypt_map:
                found.append((encrypt_map[intermediate], key2))

        return found, min(65536, max_keys)


class CBCMode:
    """CBC工作模式"""

    def __init__(self, saes):
        self.saes = saes

    def encrypt(self, plain_blocks, key, iv):
        cipher_blocks = []
        prev_block = iv

        for block in plain_blocks:
            xor_block = self.saes.bin_xor(block, prev_block)
            encrypted = self.saes.encrypt(xor_block, key)
            cipher_blocks.append(encrypted)
            prev_block = encrypted

        return cipher_blocks

    def decrypt(self, cipher_blocks, key, iv):
        plain_blocks = []
        prev_block = iv

        for block in cipher_blocks:
            decrypted = self.saes.decrypt(block, key)
            xor_block = self.saes.bin_xor(decrypted, prev_block)
            plain_blocks.append(xor_block)
            prev_block = block

        return plain_blocks


class SAESInterface:
    def __init__(self, root):
        self.root = root
        self.root.title("S-AES加密系统")
        self.root.geometry("900x700")

        # 算法实例
        self.saes = SAESEncryptor()
        self.double = DoubleEncrypt()
        self.triple = TripleEncrypt()
        self.attack = MiddleAttack(self.saes)
        self.cbc = CBCMode(self.saes)

        # 创建界面组件
        self.create_widgets()

    def create_widgets(self):
        # 顶部选项卡区域
        tab_control = ttk.Notebook(self.root)

        # 创建选项卡
        self.tab_basic = ttk.Frame(tab_control)
        self.tab_ascii = ttk.Frame(tab_control)
        self.tab_double = ttk.Frame(tab_control)
        self.tab_triple = ttk.Frame(tab_control)
        self.tab_attack = ttk.Frame(tab_control)
        self.tab_cbc = ttk.Frame(tab_control)
        self.tab_test = ttk.Frame(tab_control)

        # 添加选项卡
        tab_control.add(self.tab_basic, text="基础加密")
        tab_control.add(self.tab_ascii, text="ASCII加密")
        tab_control.add(self.tab_double, text="双重加密")
        tab_control.add(self.tab_triple, text="三重加密")
        tab_control.add(self.tab_attack, text="中间攻击")
        tab_control.add(self.tab_cbc, text="CBC模式")
        tab_control.add(self.tab_test, text="正确性测试")

        tab_control.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)

        # 初始化各选项卡
        self.init_basic_tab()
        self.init_ascii_tab()
        self.init_double_tab()
        self.init_triple_tab()
        self.init_attack_tab()
        self.init_cbc_tab()
        self.init_test_tab()

        # 底部调试区域
        self.debug_frame = ttk.LabelFrame(self.root, text="调试输出")
        self.debug_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)

        self.debug_text = scrolledtext.ScrolledText(self.debug_frame, height=10)
        self.debug_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        # 调试控制按钮
        ctrl_frame = ttk.Frame(self.root)
        ctrl_frame.pack(fill=tk.X, padx=10, pady=5)

        ttk.Button(ctrl_frame, text="开启调试", command=self.start_debug).pack(side=tk.LEFT, padx=5)
        ttk.Button(ctrl_frame, text="关闭调试", command=self.stop_debug).pack(side=tk.LEFT, padx=5)
        ttk.Button(ctrl_frame, text="清空输出", command=self.clear_debug).pack(side=tk.LEFT, padx=5)

        # 重定向输出
        sys.stdout = TextRedirect(self.debug_text)

    # 初始化各选项卡界面
    def init_basic_tab(self):
        # 输入区域
        input_frame = ttk.Frame(self.tab_basic)
        input_frame.pack(padx=10, pady=10, fill=tk.X)

        ttk.Label(input_frame, text="明文 (16位二进制):").grid(row=0, column=0, padx=5, pady=5, sticky=tk.W)
        self.basic_plain = ttk.Entry(input_frame, width=20)
        self.basic_plain.grid(row=0, column=1, padx=5, pady=5)

        ttk.Label(input_frame, text="密钥 (16位二进制):").grid(row=1, column=0, padx=5, pady=5, sticky=tk.W)
        self.basic_key = ttk.Entry(input_frame, width=20)
        self.basic_key.grid(row=1, column=1, padx=5, pady=5)

        # 按钮区域
        btn_frame = ttk.Frame(self.tab_basic)
        btn_frame.pack(pady=10)

        ttk.Button(btn_frame, text="加密", command=self.basic_encrypt).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="解密", command=self.basic_decrypt).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="填充示例", command=self.fill_basic).pack(side=tk.LEFT, padx=5)

        # 结果区域（移至下方）
        result_frame = ttk.LabelFrame(self.tab_basic, text="结果")
        result_frame.pack(fill=tk.X, padx=10, pady=10)

        ttk.Label(result_frame, text="密文:").grid(row=0, column=0, padx=5, pady=5, sticky=tk.W)
        self.basic_cipher = ttk.Label(result_frame, text="", foreground="blue")
        self.basic_cipher.grid(row=0, column=1, padx=5, pady=5, sticky=tk.W)

        ttk.Label(result_frame, text="解密结果:").grid(row=1, column=0, padx=5, pady=5, sticky=tk.W)
        self.basic_decrypt_res = ttk.Label(result_frame, text="", foreground="green")
        self.basic_decrypt_res.grid(row=1, column=1, padx=5, pady=5, sticky=tk.W)

        ttk.Label(result_frame, text="验证:").grid(row=2, column=0, padx=5, pady=5, sticky=tk.W)
        self.basic_verify = ttk.Label(result_frame, text="", foreground="red")
        self.basic_verify.grid(row=2, column=1, padx=5, pady=5, sticky=tk.W)

    def init_ascii_tab(self):
        input_frame = ttk.Frame(self.tab_ascii)
        input_frame.pack(padx=10, pady=10, fill=tk.X)

        ttk.Label(input_frame, text="ASCII文本:").grid(row=0, column=0, padx=5, pady=5, sticky=tk.W)
        self.ascii_text = ttk.Entry(input_frame, width=30)
        self.ascii_text.grid(row=0, column=1, padx=5, pady=5)

        ttk.Label(input_frame, text="密钥 (16位二进制):").grid(row=1, column=0, padx=5, pady=5, sticky=tk.W)
        self.ascii_key = ttk.Entry(input_frame, width=20)
        self.ascii_key.grid(row=1, column=1, padx=5, pady=5)

        btn_frame = ttk.Frame(self.tab_ascii)
        btn_frame.pack(pady=10)

        ttk.Button(btn_frame, text="加密", command=self.ascii_encrypt).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="解密", command=self.ascii_decrypt).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="填充示例", command=self.fill_ascii).pack(side=tk.LEFT, padx=5)

        result_frame = ttk.LabelFrame(self.tab_ascii, text="结果")
        result_frame.pack(fill=tk.X, padx=10, pady=10)

        ttk.Label(result_frame, text="加密结果:").grid(row=0, column=0, padx=5, pady=5, sticky=tk.W)
        self.ascii_cipher = ttk.Label(result_frame, text="", foreground="blue", wraplength=400)
        self.ascii_cipher.grid(row=0, column=1, padx=5, pady=5, sticky=tk.W)

        ttk.Label(result_frame, text="解密结果:").grid(row=1, column=0, padx=5, pady=5, sticky=tk.W)
        self.ascii_decrypt_res = ttk.Label(result_frame, text="", foreground="green")
        self.ascii_decrypt_res.grid(row=1, column=1, padx=5, pady=5, sticky=tk.W)

        ttk.Label(result_frame, text="验证:").grid(row=2, column=0, padx=5, pady=5, sticky=tk.W)
        self.ascii_verify = ttk.Label(result_frame, text="", foreground="red")
        self.ascii_verify.grid(row=2, column=1, padx=5, pady=5, sticky=tk.W)

    def init_double_tab(self):
        input_frame = ttk.Frame(self.tab_double)
        input_frame.pack(padx=10, pady=10, fill=tk.X)

        ttk.Label(input_frame, text="明文 (16位二进制):").grid(row=0, column=0, padx=5, pady=5, sticky=tk.W)
        self.double_plain = ttk.Entry(input_frame, width=20)
        self.double_plain.grid(row=0, column=1, padx=5, pady=5)

        ttk.Label(input_frame, text="密钥 (32位二进制):").grid(row=1, column=0, padx=5, pady=5, sticky=tk.W)
        self.double_key = ttk.Entry(input_frame, width=35)
        self.double_key.grid(row=1, column=1, padx=5, pady=5)

        btn_frame = ttk.Frame(self.tab_double)
        btn_frame.pack(pady=10)

        ttk.Button(btn_frame, text="加密", command=self.double_encrypt).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="解密", command=self.double_decrypt).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="填充示例", command=self.fill_double).pack(side=tk.LEFT, padx=5)

        result_frame = ttk.LabelFrame(self.tab_double, text="结果")
        result_frame.pack(fill=tk.X, padx=10, pady=10)

        ttk.Label(result_frame, text="加密结果:").grid(row=0, column=0, padx=5, pady=5, sticky=tk.W)
        self.double_cipher = ttk.Label(result_frame, text="", foreground="blue")
        self.double_cipher.grid(row=0, column=1, padx=5, pady=5, sticky=tk.W)

        ttk.Label(result_frame, text="解密结果:").grid(row=1, column=0, padx=5, pady=5, sticky=tk.W)
        self.double_decrypt_res = ttk.Label(result_frame, text="", foreground="green")
        self.double_decrypt_res.grid(row=1, column=1, padx=5, pady=5, sticky=tk.W)

        ttk.Label(result_frame, text="验证:").grid(row=2, column=0, padx=5, pady=5, sticky=tk.W)
        self.double_verify = ttk.Label(result_frame, text="", foreground="red")
        self.double_verify.grid(row=2, column=1, padx=5, pady=5, sticky=tk.W)

    def init_triple_tab(self):
        input_frame = ttk.Frame(self.tab_triple)
        input_frame.pack(padx=10, pady=10, fill=tk.X)

        ttk.Label(input_frame, text="加密模式:").grid(row=0, column=0, padx=5, pady=5, sticky=tk.W)
        self.triple_mode = tk.StringVar(value="32")
        ttk.Radiobutton(input_frame, text="32位密钥", variable=self.triple_mode, value="32").grid(row=0, column=1,
                                                                                                  sticky=tk.W)
        ttk.Radiobutton(input_frame, text="48位密钥", variable=self.triple_mode, value="48").grid(row=1, column=1,
                                                                                                  sticky=tk.W)

        ttk.Label(input_frame, text="明文 (16位二进制):").grid(row=2, column=0, padx=5, pady=5, sticky=tk.W)
        self.triple_plain = ttk.Entry(input_frame, width=20)
        self.triple_plain.grid(row=2, column=1, padx=5, pady=5)

        ttk.Label(input_frame, text="密钥:").grid(row=3, column=0, padx=5, pady=5, sticky=tk.W)
        self.triple_key = ttk.Entry(input_frame, width=50)
        self.triple_key.grid(row=3, column=1, padx=5, pady=5)

        btn_frame = ttk.Frame(self.tab_triple)
        btn_frame.pack(pady=10)

        ttk.Button(btn_frame, text="加密", command=self.triple_encrypt).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="解密", command=self.triple_decrypt).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="填充示例", command=self.fill_triple).pack(side=tk.LEFT, padx=5)

        result_frame = ttk.LabelFrame(self.tab_triple, text="结果")
        result_frame.pack(fill=tk.X, padx=10, pady=10)

        ttk.Label(result_frame, text="加密结果:").grid(row=0, column=0, padx=5, pady=5, sticky=tk.W)
        self.triple_cipher = ttk.Label(result_frame, text="", foreground="blue")
        self.triple_cipher.grid(row=0, column=1, padx=5, pady=5, sticky=tk.W)

        ttk.Label(result_frame, text="解密结果:").grid(row=1, column=0, padx=5, pady=5, sticky=tk.W)
        self.triple_decrypt_res = ttk.Label(result_frame, text="", foreground="green")
        self.triple_decrypt_res.grid(row=1, column=1, padx=5, pady=5, sticky=tk.W)

        ttk.Label(result_frame, text="验证:").grid(row=2, column=0, padx=5, pady=5, sticky=tk.W)
        self.triple_verify = ttk.Label(result_frame, text="", foreground="red")
        self.triple_verify.grid(row=2, column=1, padx=5, pady=5, sticky=tk.W)

    def init_attack_tab(self):
        input_frame = ttk.Frame(self.tab_attack)
        input_frame.pack(padx=10, pady=10, fill=tk.X)

        ttk.Label(input_frame, text="已知明文 (16位):").grid(row=0, column=0, padx=5, pady=5, sticky=tk.W)
        self.attack_plain = ttk.Entry(input_frame, width=20)
        self.attack_plain.grid(row=0, column=1, padx=5, pady=5)

        ttk.Label(input_frame, text="已知密文 (16位):").grid(row=1, column=0, padx=5, pady=5, sticky=tk.W)
        self.attack_cipher = ttk.Entry(input_frame, width=20)
        self.attack_cipher.grid(row=1, column=1, padx=5, pady=5)

        ttk.Label(input_frame, text="最大测试密钥数:").grid(row=2, column=0, padx=5, pady=5, sticky=tk.W)
        self.attack_max = tk.StringVar(value="1000")
        ttk.Entry(input_frame, textvariable=self.attack_max, width=10).grid(row=2, column=1, padx=5, pady=5,
                                                                            sticky=tk.W)

        ttk.Button(input_frame, text="执行攻击", command=self.run_attack).grid(row=3, column=0, columnspan=2, pady=10)

        # 结果区域
        result_frame = ttk.LabelFrame(self.tab_attack, text="攻击结果")
        result_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        self.attack_result = scrolledtext.ScrolledText(result_frame, width=60, height=6)
        self.attack_result.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        self.attack_status = ttk.Label(self.tab_attack, text="")
        self.attack_status.pack(pady=5)

        ttk.Button(self.tab_attack, text="填充示例", command=self.fill_attack).pack(pady=5)

    def init_cbc_tab(self):
        input_frame = ttk.Frame(self.tab_cbc)
        input_frame.pack(padx=10, pady=10, fill=tk.X)

        ttk.Label(input_frame, text="明文分组 (空格分隔):").grid(row=0, column=0, padx=5, pady=5, sticky=tk.W)
        self.cbc_plain = ttk.Entry(input_frame, width=50)
        self.cbc_plain.grid(row=0, column=1, padx=5, pady=5)

        ttk.Label(input_frame, text="密钥 (16位):").grid(row=1, column=0, padx=5, pady=5, sticky=tk.W)
        self.cbc_key = ttk.Entry(input_frame, width=20)
        self.cbc_key.grid(row=1, column=1, padx=5, pady=5)

        ttk.Label(input_frame, text="初始向量IV (16位):").grid(row=2, column=0, padx=5, pady=5, sticky=tk.W)
        self.cbc_iv = ttk.Entry(input_frame, width=20)
        self.cbc_iv.grid(row=2, column=1, padx=5, pady=5)

        btn_frame = ttk.Frame(self.tab_cbc)
        btn_frame.pack(pady=10)

        ttk.Button(btn_frame, text="加密", command=self.cbc_encrypt).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="解密", command=self.cbc_decrypt).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="篡改测试", command=self.cbc_tamper).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="填充示例", command=self.fill_cbc).pack(side=tk.LEFT, padx=5)

        result_frame = ttk.LabelFrame(self.tab_cbc, text="结果")
        result_frame.pack(fill=tk.X, padx=10, pady=10)

        ttk.Label(result_frame, text="加密结果:").grid(row=0, column=0, padx=5, pady=5, sticky=tk.W)
        self.cbc_cipher = ttk.Label(result_frame, text="", foreground="blue", wraplength=500)
        self.cbc_cipher.grid(row=0, column=1, padx=5, pady=5, sticky=tk.W)

        ttk.Label(result_frame, text="解密结果:").grid(row=1, column=0, padx=5, pady=5, sticky=tk.W)
        self.cbc_decrypt_res = ttk.Label(result_frame, text="", foreground="green", wraplength=500)
        self.cbc_decrypt_res.grid(row=1, column=1, padx=5, pady=5, sticky=tk.W)

        ttk.Label(result_frame, text="篡改后解密:").grid(row=2, column=0, padx=5, pady=5, sticky=tk.W)
        self.cbc_tamper_res = ttk.Label(result_frame, text="", foreground="red", wraplength=500)
        self.cbc_tamper_res.grid(row=2, column=1, padx=5, pady=5, sticky=tk.W)

    def init_test_tab(self):
        btn_frame = ttk.Frame(self.tab_test)
        btn_frame.pack(pady=10)

        ttk.Button(btn_frame, text="标准测试", command=self.run_std_test).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="验证S盒", command=self.verify_sbox).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="验证列混淆", command=self.verify_mixcol).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="交叉测试", command=self.cross_test).pack(side=tk.LEFT, padx=5)

        self.test_result = scrolledtext.ScrolledText(self.tab_test, height=15)
        self.test_result.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

    # 功能实现
    def basic_encrypt(self):
        try:
            plain = self.basic_plain.get()
            key = self.basic_key.get()

            if len(plain) != 16 or len(key) != 16:
                messagebox.showerror("错误", "明文和密钥必须为16位二进制")
                return

            cipher = self.saes.encrypt(plain, key)
            self.basic_cipher.config(text=cipher)
        except Exception as e:
            messagebox.showerror("错误", f"加密失败: {str(e)}")

    def basic_decrypt(self):
        try:
            cipher = self.basic_cipher.cget("text")
            key = self.basic_key.get()

            if not cipher or len(key) != 16:
                messagebox.showerror("错误", "请先加密或检查密钥")
                return

            plain = self.saes.decrypt(cipher, key)
            self.basic_decrypt_res.config(text=plain)

            original = self.basic_plain.get()
            if plain == original:
                self.basic_verify.config(text="✓ 解密成功", foreground="green")
            else:
                self.basic_verify.config(text="✗ 解密失败", foreground="red")
        except Exception as e:
            messagebox.showerror("错误", f"解密失败: {str(e)}")

    def ascii_encrypt(self):
        try:
            text = self.ascii_text.get()
            key = self.ascii_key.get()

            if not text or len(key) != 16:
                messagebox.showerror("错误", "请输入文本和16位密钥")
                return

            bin_text = self.saes.str_to_bin(text)
            encrypted_bin = ""

            for i in range(0, len(bin_text), 16):
                block = bin_text[i:i + 16].ljust(16, '0')
                encrypted_bin += self.saes.encrypt(block, key)

            self.ascii_cipher.config(text=self.saes.bin_to_str(encrypted_bin))
        except Exception as e:
            messagebox.showerror("错误", f"加密失败: {str(e)}")

    def ascii_decrypt(self):
        try:
            cipher_text = self.ascii_cipher.cget("text")
            key = self.ascii_key.get()

            if not cipher_text or len(key) != 16:
                messagebox.showerror("错误", "请先加密或检查密钥")
                return

            cipher_bin = self.saes.str_to_bin(cipher_text)
            decrypted_bin = ""

            for i in range(0, len(cipher_bin), 16):
                block = cipher_bin[i:i + 16].ljust(16, '0')
                decrypted_bin += self.saes.decrypt(block, key)

            decrypted_text = self.saes.bin_to_str(decrypted_bin)
            self.ascii_decrypt_res.config(text=decrypted_text)

            original = self.ascii_text.get()
            if decrypted_text == original:
                self.ascii_verify.config(text="✓ 解密成功", foreground="green")
            else:
                self.ascii_verify.config(text="✗ 解密失败", foreground="red")
        except Exception as e:
            messagebox.showerror("错误", f"解密失败: {str(e)}")

    def double_encrypt(self):
        try:
            plain = self.double_plain.get()
            key = self.double_key.get()

            if len(plain) != 16 or len(key) != 32:
                messagebox.showerror("错误", "明文16位，密钥32位")
                return

            cipher = self.double.double_encrypt(plain, key)
            self.double_cipher.config(text=cipher)
        except Exception as e:
            messagebox.showerror("错误", f"加密失败: {str(e)}")

    def double_decrypt(self):
        try:
            cipher = self.double_cipher.cget("text")
            key = self.double_key.get()

            if not cipher or len(key) != 32:
                messagebox.showerror("错误", "请先加密或检查密钥")
                return

            plain = self.double.double_decrypt(cipher, key)
            self.double_decrypt_res.config(text=plain)

            original = self.double_plain.get()
            if plain == original:
                self.double_verify.config(text="✓ 解密成功", foreground="green")
            else:
                self.double_verify.config(text="✗ 解密失败", foreground="red")
        except Exception as e:
            messagebox.showerror("错误", f"解密失败: {str(e)}")

    def triple_encrypt(self):
        try:
            plain = self.triple_plain.get()
            key = self.triple_key.get()
            mode = self.triple_mode.get()

            if len(plain) != 16:
                messagebox.showerror("错误", "明文必须为16位")
                return

            if mode == "32":
                if len(key) != 32:
                    messagebox.showerror("错误", "32位模式密钥必须为32位")
                    return
                cipher = self.triple.triple_encrypt_32(plain, key)
            else:
                if len(key) != 48:
                    messagebox.showerror("错误", "48位模式密钥必须为48位")
                    return
                cipher = self.triple.triple_encrypt_48(plain, key)

            self.triple_cipher.config(text=cipher)
        except Exception as e:
            messagebox.showerror("错误", f"加密失败: {str(e)}")

    def triple_decrypt(self):
        try:
            cipher = self.triple_cipher.cget("text")
            key = self.triple_key.get()
            mode = self.triple_mode.get()

            if not cipher:
                messagebox.showerror("错误", "请先加密")
                return

            if mode == "32":
                if len(key) != 32:
                    messagebox.showerror("错误", "32位模式密钥必须为32位")
                    return
                plain = self.triple.triple_decrypt_32(cipher, key)
            else:
                if len(key) != 48:
                    messagebox.showerror("错误", "48位模式密钥必须为48位")
                    return
                plain = self.triple.triple_decrypt_48(cipher, key)

            self.triple_decrypt_res.config(text=plain)

            original = self.triple_plain.get()
            if plain == original:
                self.triple_verify.config(text="✓ 解密成功", foreground="green")
            else:
                self.triple_verify.config(text="✗ 解密失败", foreground="red")
        except Exception as e:
            messagebox.showerror("错误", f"解密失败: {str(e)}")

    def run_attack(self):
        try:
            plain = self.attack_plain.get()
            cipher = self.attack_cipher.get()
            max_keys = int(self.attack_max.get())

            if len(plain) != 16 or len(cipher) != 16:
                messagebox.showerror("错误", "明文和密文必须为16位")
                return

            self.attack_status.config(text="攻击中...")
            self.attack_result.delete(1.0, tk.END)
            self.root.update()

            found, tested = self.attack.attack(plain, cipher, max_keys)

            self.attack_result.insert(tk.END, f"测试了 {tested} 个密钥对\n")
            self.attack_result.insert(tk.END, f"找到 {len(found)} 个可能密钥对:\n\n")

            for i, (k1, k2) in enumerate(found[:10]):
                self.attack_result.insert(tk.END, f"密钥对 {i + 1}:\n")
                self.attack_result.insert(tk.END, f"  K1: {k1}\n")
                self.attack_result.insert(tk.END, f"  K2: {k2}\n")
                self.attack_result.insert(tk.END, f"  完整密钥: {k1 + k2}\n\n")

            self.attack_status.config(text=f"完成！找到 {len(found)} 个密钥对")
        except Exception as e:
            messagebox.showerror("错误", f"攻击失败: {str(e)}")
            self.attack_status.config(text="攻击失败")

    def cbc_encrypt(self):
        try:
            plain_blocks = self.cbc_plain.get().split()
            key = self.cbc_key.get()
            iv = self.cbc_iv.get()

            if not plain_blocks or len(key) != 16 or len(iv) != 16:
                messagebox.showerror("错误", "请输入完整信息")
                return

            for block in plain_blocks:
                if len(block) != 16:
                    messagebox.showerror("错误", f"分组 {block} 不是16位")
                    return

            cipher_blocks = self.cbc.encrypt(plain_blocks, key, iv)
            self.cbc_cipher.config(text=" ".join(cipher_blocks))
        except Exception as e:
            messagebox.showerror("错误", f"加密失败: {str(e)}")

    def cbc_decrypt(self):
        try:
            cipher_blocks = self.cbc_cipher.cget("text").split()
            key = self.cbc_key.get()
            iv = self.cbc_iv.get()

            if not cipher_blocks or len(key) != 16 or len(iv) != 16:
                messagebox.showerror("错误", "请先加密或检查参数")
                return

            plain_blocks = self.cbc.decrypt(cipher_blocks, key, iv)
            self.cbc_decrypt_res.config(text=" ".join(plain_blocks))
            self.cbc_tamper_res.config(text="")
        except Exception as e:
            messagebox.showerror("错误", f"解密失败: {str(e)}")

    def cbc_tamper(self):
        try:
            cipher_blocks = self.cbc_cipher.cget("text").split()
            key = self.cbc_key.get()
            iv = self.cbc_iv.get()

            if not cipher_blocks or len(cipher_blocks) < 2:
                messagebox.showerror("错误", "至少需要2个分组")
                return

            # 篡改中间分组
            tampered = cipher_blocks.copy()
            idx = len(tampered) // 2
            original = tampered[idx]
            tampered[idx] = ''.join('1' if b == '0' else '0' for b in original[:8]) + original[8:]

            plain = self.cbc.decrypt(tampered, key, iv)
            self.cbc_tamper_res.config(text=" ".join(plain))
            messagebox.showinfo("提示", f"已篡改第 {idx + 1} 个分组")
        except Exception as e:
            messagebox.showerror("错误", f"测试失败: {str(e)}")

    # 测试功能
    def run_std_test(self):
        self.test_result.delete(1.0, tk.END)
        tests = [
            {
                "name": "标准测试1",
                "plain": "0110111101101011",
                "key": "1010011100111011",
                "cipher": "0000011100111000"
            },
            {
                "name": "全零测试",
                "plain": "0000000000000000",
                "key": "0000000000000000",
                "cipher": "1100101000000011"
            },
            {
                "name": "全一测试",
                "plain": "1111111111111111",
                "key": "1111111111111111",
                "cipher": "0011000100101110"
            }
        ]

        all_ok = True
        for test in tests:
            self.test_result.insert(tk.END, f"测试: {test['name']}\n")
            self.test_result.insert(tk.END, f"明文: {test['plain']}\n")
            self.test_result.insert(tk.END, f"密钥: {test['key']}\n")

            cipher = self.saes.encrypt(test['plain'], test['key'])
            self.test_result.insert(tk.END, f"加密结果: {cipher}\n")
            self.test_result.insert(tk.END, f"预期结果: {test['cipher']}\n")
            enc_ok = cipher == test['cipher']
            self.test_result.insert(tk.END, f"加密: {'✓' if enc_ok else '✗'}\n")

            plain = self.saes.decrypt(cipher, test['key'])
            self.test_result.insert(tk.END, f"解密结果: {plain}\n")
            dec_ok = plain == test['plain']
            self.test_result.insert(tk.END, f"解密: {'✓' if dec_ok else '✗'}\n\n")

            if not (enc_ok and dec_ok):
                all_ok = False

        self.test_result.insert(tk.END, "🎉 所有测试通过！\n" if all_ok else "❌ 测试失败\n")

    def verify_sbox(self):
        self.test_result.delete(1.0, tk.END)
        all_ok = True

        for i in range(16):
            nibble = format(i, '04b')
            s_res = int(self.saes.nibble_sub(nibble, self.saes.s_box), 2)
            inv_res = int(self.saes.nibble_sub(format(s_res, '04b'), self.saes.inv_s_box), 2)

            if inv_res != i:
                self.test_result.insert(tk.END,
                                        f"✗ 错误: {nibble} -> {format(s_res, '04b')} -> {format(inv_res, '04b')}\n")
                all_ok = False
            else:
                self.test_result.insert(tk.END,
                                        f"✓ {nibble} -> {format(s_res, '04b')} -> {format(inv_res, '04b')}\n")

        self.test_result.insert(tk.END, "\n🎉 S盒验证通过！\n" if all_ok else "\n❌ S盒验证失败！\n")

    def verify_mixcol(self):
        self.test_result.delete(1.0, tk.END)
        matrices = [
            np.array([[1, 2], [3, 4]]),
            np.array([[5, 6], [7, 8]]),
            np.array([[9, 10], [11, 12]]),
            np.array([[13, 14], [15, 0]])
        ]

        all_ok = True
        for i, mat in enumerate(matrices):
            mixed = self.saes.mix_col(mat)
            inv_mixed = self.saes.inv_mix_col(mixed)

            self.test_result.insert(tk.END,
                                    f"测试 {i + 1}: {'通过' if np.array_equal(mat, inv_mixed) else '失败'}\n")
            if not np.array_equal(mat, inv_mixed):
                all_ok = False

        self.test_result.insert(tk.END, "\n🎉 列混淆验证通过！\n" if all_ok else "\n❌ 列混淆验证失败！\n")

    def cross_test(self):
        plain = "0110111101101011"
        key = "1010011100111011"
        expected = "0000011100111000"

        actual = self.saes.encrypt(plain, key)
        self.test_result.delete(1.0, tk.END)
        self.test_result.insert(tk.END, f"明文: {plain}\n密钥: {key}\n")
        self.test_result.insert(tk.END, f"预期密文: {expected}\n实际密文: {actual}\n\n")

        if actual == expected:
            self.test_result.insert(tk.END, "✓ 交叉测试通过！")
        else:
            self.test_result.insert(tk.END, "✗ 交叉测试失败！")

    # 辅助功能
    def start_debug(self):
        self.saes.activate_debug()
        self.double.activate_debug()
        self.triple.activate_debug()
        print("调试模式开启")

    def stop_debug(self):
        self.saes.deactivate_debug()
        self.double.deactivate_debug()
        self.triple.deactivate_debug()
        print("调试模式关闭")

    def clear_debug(self):
        self.debug_text.delete(1.0, tk.END)

    # 填充示例
    def fill_basic(self):
        self.basic_plain.delete(0, tk.END)
        self.basic_plain.insert(0, "0110111101101011")
        self.basic_key.delete(0, tk.END)
        self.basic_key.insert(0, "1010011100111011")

    def fill_ascii(self):
        self.ascii_text.delete(0, tk.END)
        self.ascii_text.insert(0, "Hello AES!")
        self.ascii_key.delete(0, tk.END)
        self.ascii_key.insert(0, "1010011100111011")

    def fill_double(self):
        self.double_plain.delete(0, tk.END)
        self.double_plain.insert(0, "0110111101101011")
        self.double_key.delete(0, tk.END)
        self.double_key.insert(0, "10100111001110111010011100111011")

    def fill_triple(self):
        self.triple_plain.delete(0, tk.END)
        self.triple_plain.insert(0, "0110111101101011")
        self.triple_key.delete(0, tk.END)
        self.triple_key.insert(0, "10100111001110111010011100111011")

    def fill_attack(self):
        self.attack_plain.delete(0, tk.END)
        self.attack_plain.insert(0, "0110111101101011")
        self.attack_cipher.delete(0, tk.END)
        self.attack_cipher.insert(0, "1101001010010111")

    def fill_cbc(self):
        self.cbc_plain.delete(0, tk.END)
        self.cbc_plain.insert(0, "0110111101101011 1100110011001100 1010101010101010")
        self.cbc_key.delete(0, tk.END)
        self.cbc_key.insert(0, "1010011100111011")
        self.cbc_iv.delete(0, tk.END)
        self.cbc_iv.insert(0, "1111000011110000")


class TextRedirect:
    """输出重定向到文本框"""

    def __init__(self, text_widget):
        self.text_widget = text_widget

    def write(self, string):
        self.text_widget.insert(tk.END, string)
        self.text_widget.see(tk.END)
        self.text_widget.update()

    def flush(self):
        pass


def main():
    root = tk.Tk()
    app = SAESInterface(root)
    root.mainloop()


if __name__ == "__main__":
    main()