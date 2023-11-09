import re
import os
import ecdsa
from ecdsa import VerifyingKey
from binascii import hexlify, unhexlify


def extract_private_keys(input_file):
    # 用于匹配私钥的正则表达式
    private_key_pattern = r"(0x[a-fA-F0-9]{64})"

    with open(input_file, "r") as file:
        content = file.read()

    # 使用正则表达式找到所有的私钥
    private_keys = re.findall(private_key_pattern, content)
    private_keys = re.findall(private_key_pattern, content)
    print("提取的私钥总数为：", len(private_keys))

    return private_keys


def perform_operations(private_keys, path):
    # 对私钥0-99的操作
    for i in range(100):
        output_file_path = path + "user account " + str(i) + ".txt"
        processed_keys = []
        processed_keys.append(private_keys[i])
        processed_keys.append(private_keys[i + 100])
        write_private_keys(output_file_path, processed_keys)


def write_private_keys(output_file_path, private_keys, mode="wt"):
    # 保存到文件，默认重写文件
    with open(output_file_path, mode) as file:
        for private_key in private_keys:
            file.write(private_key + "\n")


def get_public_key(private_key_str):
    public_keys = []
    for private_key in private_key_str:
        # 创建验证私钥对象
        sk = ecdsa.SigningKey.from_string(
            unhexlify(private_key[2:]), curve=ecdsa.SECP256k1
        )
        vk = sk.get_verifying_key()
        public_keys.append("0x" + hexlify(vk.to_string()).decode())
    print(len(public_keys))
    return public_keys


if __name__ == "__main__":
    path = r"C:\Users\lsj\Desktop\account\\"
    input_file_path = path + "hardhat-account.txt"
    # 提取私钥
    private_keys = extract_private_keys(input_file_path)

    # 在数组中执行一些操作
    # 0-99(real name account) 100-199(anonymous account)
    perform_operations(private_keys, path)
    # 账户划分：200-299(temp account), 前闭后开
    write_private_keys(path + "user account 0" + ".txt", private_keys[200:300], "at")
    # 账户划分：300（validator的私钥）
    write_private_keys(path + ".validator account" + ".txt", private_keys[300:])
    # 提取公钥到public key文件中
    public_keys = get_public_key(private_keys[0:100])
    write_private_keys(path + "public key" + ".txt", public_keys, "at")
    print("私钥已提取、处理并写入到输出文件中。")
