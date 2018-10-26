import base64
import os
import json


def encode64_file(file_path):
    with open(file_path, "rb") as content_file:
        content = content_file.read()
        # print(content)
        encoded = base64.b64encode(content)
        return encoded.decode()


def read_allfile(file_path):
    with open(file_path, "r") as content_file:
        content = content_file.read()
        return content


def read_file_tojson(file_path):
    data = {}
    with open(file_path, "r") as content_file:
        content = content_file.read()
        data = json.loads(content)
    return data

if __name__ == "__main__":
    a = read_file_tojson("test.json")
