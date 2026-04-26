from flask import Flask, request, jsonify
import json
import os
import requests
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import binascii

app = Flask(__name__)
ACCOUNTS_FILE = 'assec.json'

# مفاتيح التشفير
KEY = bytes([89, 103, 38, 116, 99, 37, 68, 69, 117, 104, 54, 37, 90, 99, 94, 56])
IV = bytes([54, 111, 121, 90, 68, 114, 50, 50, 69, 51, 121, 99, 104, 106, 77, 37])

def load_accounts():
    """تحميل الحسابات من ملف JSON"""
    if os.path.exists(ACCOUNTS_FILE):
        with open(ACCOUNTS_FILE) as f:
            return json.load(f)
    return {}

def encrypt_data(plain_text):
    """تشفير البيانات باستخدام AES-CBC"""
    if isinstance(plain_text, str):
        plain_text = bytes.fromhex(plain_text)
    cipher = AES.new(KEY, AES.MODE_CBC, IV)
    cipher_text = cipher.encrypt(pad(plain_text, AES.block_size))
    return cipher_text.hex()

def encode_id(number):
    """تشفير ID اللاعب"""
    number = int(number)
    encoded_bytes = []
    while True:
        byte = number & 0x7F
        number >>= 7
        if number:
            byte |= 0x80
        encoded_bytes.append(byte)
        if not number:
            break
    return bytes(encoded_bytes).hex()

def get_tokens():
    """الحصول على توكنات الحسابات بشكل متزامن"""
    accounts = load_accounts()
    tokens = []
    for uid, pwd in accounts.items():
        try:
            response = requests.get(
                f"https://jwt-gen-api-v2.onrender.com/token?uid={uid}&password={pwd}",
                timeout=10
            )
            if response.status_code == 200:
                data = response.json()
                token = data[0]["token"] if isinstance(data, list) else data.get("token")
                if token:
                    tokens.append(token)
        except:
            continue
    return tokens

@app.route('/add', methods=['GET'])
def like_handler():
    """معالجة طلبات الإعجاب/الصداقة"""
    uid = request.args.get("uid")
    if not uid:
        return jsonify({"error": "يجب تقديم UID"}), 400

    tokens = get_tokens()
    if not tokens:
        return jsonify({"error": "لا توجد توكنات صالحة"}), 401
    
    enc_id = encode_id(uid)
    payload = f"08a7c4839f1e10{enc_id}1801"
    enc_data = encrypt_data(payload)
    
    results = []
    for token in tokens:
        try:
            response = requests.post(
                "https://clientbp.ggpolarbear.com/RequestAddingFriend",
                headers={
                    "Authorization": f"Bearer {token}",
                    "X-Unity-Version": "2018.4.11f1",
                    "X-GA": "v1 1",
                    "ReleaseVersion": "OB53",
                    "Content-Type": "application/x-www-form-urlencoded",
                    "User-Agent": "Dalvik/2.1.0 (Linux; Android 9)",
                    "Connection": "Keep-Alive",
                    "Accept-Encoding": "gzip"
                },
                data=bytes.fromhex(enc_data),
                timeout=10
            )
            results.append({
                "status": response.status_code,
                "message": response.text
            })
        except Exception as e:
            results.append({
                "status": 500,
                "message": str(e)
            })
    
    success = sum(1 for r in results if r["status"] == 200)
    return jsonify({
        "successful_requests": success,
        "total_tokens": len(tokens),
        "results": results,
        "encrypted_payload": enc_data
    })

@app.route('/')
def home():
    """الصفحة الرئيسية"""
    return jsonify({
        "status": "نشط",
        "endpoints": {
            "/add": "إرسال طلبات صداقة - يحتاج параметر uid"
        }
    })

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)