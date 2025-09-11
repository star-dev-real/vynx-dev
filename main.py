import asyncio
import ujson, json
import os
import subprocess
import winreg
import win32api
import psutil
import shutil
import requests
import ssl
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from mitmproxy import certs, http, options
from mitmproxy.tools.dump import DumpMaster
import sys

def resource_path(relative_path):
    try:
        base_path = sys._MEIPASS
    except AttributeError:
        base_path = os.path.abspath(".")

    return os.path.join(base_path, relative_path)

with open(resource_path("shop.json"), "r", encoding="utf-8") as f:
    CUSTOM_SHOP = json.load(f)

with open(resource_path("common_core.json"), "r", encoding="utf-8") as f:
    COMMON_CORE = json.load(f)

with open(resource_path("athena.json"), "r", encoding="utf-8") as f:
    ATHENA = json.load(f)

with open(resource_path("content.json"), "r", encoding="utf-8") as f:
    CONTENT = json.load(f)

def clear_fortnite_cms():
    local_appdata = os.getenv('LOCALAPPDATA')
    target_path = os.path.join(local_appdata, 'FortniteGame', 'Saved', 'PersistentDownloadDir', 'CMS')
    
    if not os.path.exists(target_path):
        return
    
    try:
        for filename in os.listdir(target_path):
            file_path = os.path.join(target_path, filename)
            try:
                if os.path.isfile(file_path) or os.path.islink(file_path):
                    os.unlink(file_path)
                elif os.path.isdir(file_path):
                    shutil.rmtree(file_path)
            except Exception:
                pass
    except Exception:
        pass

def set_proxy_settings(proxy_server, enable_proxy):
    reg_path = r'Software\Microsoft\Windows\CurrentVersion\Internet Settings'
    try:
        key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, reg_path, 0, winreg.KEY_WRITE)
        winreg.SetValueEx(key, 'ProxyServer', 0, winreg.REG_SZ, proxy_server)
        winreg.SetValueEx(key, 'ProxyEnable', 0, winreg.REG_DWORD, enable_proxy)
        winreg.CloseKey(key)
    except Exception:
        pass

def kill_process_by_name(name):
    for proc in psutil.process_iter(['pid', 'name']):
        if name.lower() in proc.info['name'].lower():
            try:
                proc.kill()
            except psutil.NoSuchProcess:
                pass

def on_exit(signal_type):
    set_proxy_settings("", 0)
    kill_process_by_name("FortniteClient-Win64-Shipping_EAC_EOS.exe")
    kill_process_by_name("FortniteClient-Win64-Shipping.exe")
    kill_process_by_name("FortniteLauncher.exe")
    clear_fortnite_cms()

class Proxy:
    def __init__(self):
        self.config_file = "config.json"
        
    def get_level_value(self):
        try:
            if os.path.exists(self.config_file):
                with open(self.config_file, 'r') as f:
                    config = ujson.load(f)
                    return int(config.get("level", 1))  
            return 1  
        except (ValueError, TypeError, KeyError):
            return 1 

    def update_athena_profile(self, athena_profile_data):
        if "profileChanges" not in athena_profile_data or not athena_profile_data["profileChanges"]:
            return
            
        profile = athena_profile_data["profileChanges"][0].get("profile", {})
        if not profile:
            return

        if "stats" in profile and "attributes" in profile["stats"]:
            past_seasons = []
            for i in range(1, 101):
                past_seasons.append({
                    "seasonNumber": i,
                    "numWins": 10000,
                    "seasonXp": 1000000,
                    "seasonLevel": 500,
                    "bookXp": 1000000,
                    "bookLevel": 500,
                    "purchasedVIP": True
                })
            profile["stats"]["attributes"]["past_seasons"] = past_seasons
            
            level_value = self.get_level_value()
            profile["stats"]["attributes"]["level"] = level_value
            profile["stats"]["attributes"]["xp"] = 0


    def response(self, flow: http.HTTPFlow):
        url = flow.request.pretty_url

        if "/fortnite/api/storefront/v2/catalog" in url:
            flow.response = http.Response.make(
                200,  
                json.dumps(CUSTOM_SHOP),  
                {"Content-Type": "application/json"}
            )
            print("Custom shop response injected")

        elif "fortnite/api/game/v2/profile" in url and "common_core" in url:
            flow.response = http.Response.make(
                200,  
                json.dumps(COMMON_CORE),  
                {"Content-Type": "application/json"}
            )
            print("Common core response injected")

        elif "fortnite/api/game/v2/profile" in url and "athena" in url:
            try:
                if "SetCosmeticLockerSlot" in url and flow.request.method == "POST" and flow.request.text:
                    req_data = json.loads(flow.request.text)
                    
                    if 'lockerItem' in req_data and 'itemToSlot' in req_data:
                        res_data = json.loads(json.dumps(ATHENA))
                        
                        if "profileChanges" not in res_data or not res_data["profileChanges"]:
                            res_data["profileChanges"] = [{"profile": {}}]
                        
                        profile = res_data["profileChanges"][0].get("profile", {})
                        if "items" not in profile:
                            profile["items"] = {}
                        
                        category = req_data.get('category', '')
                        lockerItem = req_data.get('lockerItem', '')
                        itemId = req_data.get('itemToSlot', '')
                        variantUpdates = req_data.get('variantUpdates', [])
                        
                        if lockerItem in profile["items"]:
                            sandbox = profile["items"][lockerItem]
                            if "attributes" in sandbox and "locker_slots_data" in sandbox["attributes"]:
                                locker_slots_data = sandbox["attributes"]["locker_slots_data"]
                                if "slots" in locker_slots_data and category in locker_slots_data["slots"]:
                                    slots = locker_slots_data["slots"]
                                    slots[category]['items'] = [itemId]
                                    
                                    if variantUpdates and isinstance(variantUpdates, list):
                                        active_variants = []
                                        for variant_update in variantUpdates:
                                            if isinstance(variant_update, dict):
                                                channel = variant_update.get('channel', '')
                                                active = variant_update.get('active', '')
                                                if channel and active:
                                                    active_variants.append({
                                                        "channel": channel,
                                                        "active": active
                                                    })
                                        
                                        if active_variants:
                                            slots[category]['activeVariants'] = [{
                                                "variants": active_variants
                                            }]
                        
                        flow.response = http.Response.make(
                            200,
                            json.dumps(res_data),
                            {"Content-Type": "application/json"}
                        )
                        print("Athena response modified with locker changes")
                        return
                
                flow.response = http.Response.make(
                    200,
                    json.dumps(ATHENA),
                    {"Content-Type": "application/json"}
                )
                print("Athena response injected")

            except Exception as e:
                print(f"Error injecting Athena response: {e}")
                import traceback
                traceback.print_exc()
                flow.response = http.Response.make(
                    200,
                    json.dumps(ATHENA),
                    {"Content-Type": "application/json"}
                )

        elif "content/api/pages/fortnite-game" in url:
            flow.response = http.Response.make(
                200,  
                json.dumps(CONTENT),  
                {"Content-Type": "application/json"}
            )
            print("Content response injected")

        elif "account/api/oauth/token" in url:
            try:
                data = json.loads(flow.response.text)
                data['displayName'] = "star\n" * 5
                flow.response = http.Response.make(
                    200,  
                    json.dumps(data),  
                    {"Content-Type": "application/json"}
                )
                print("OAuth token response modified")
            except Exception as e:
                print(f"Error modifying OAuth response: {e}")

        elif "/QueryProfile" in url or "/ClientQuestLogin" in url:
            try:
                if "athena" in url:
                    profile_data = json.loads(flow.response.text)
                    self.update_athena_profile(profile_data)
                    flow.response.set_text(json.dumps(profile_data))
                    print("Athena profile updated with level and past seasons")
            except Exception as e:
                print(f"Error processing profile: {e}")

def is_certificate_installed():
    try:
        cert_dir = os.path.expanduser("~/.mitmproxy")
        if not os.path.exists(cert_dir):
            return False
            
        cert_files = [f for f in os.listdir(cert_dir) if f.endswith('.pem')]
        if not cert_files:
            return False
            
        cert_path = os.path.join(cert_dir, cert_files[0])
        with open(cert_path, "rb") as f:
            mitm_cert = x509.load_pem_x509_certificate(f.read())
            mitm_fingerprint = mitm_cert.fingerprint(hashes.SHA256())
        
        for cert, encoding, trust in ssl.enum_certificates("ROOT"):
            if encoding == "x509_asn":
                try:
                    cert_obj = x509.load_der_x509_certificate(cert)
                    if cert_obj.fingerprint(hashes.SHA256()) == mitm_fingerprint:
                        return True
                except:
                    continue
        return False
    except Exception as e:
        print(f"Certificate check error: {e}")
        return False

async def install_certificate():
    cert_dir = os.path.expanduser("~/.mitmproxy")
    if not os.path.exists(cert_dir):
        os.makedirs(cert_dir)
    
    if not any(f.endswith('.pem') for f in os.listdir(cert_dir) if os.path.isfile(os.path.join(cert_dir, f))):
        print("Generating MITMproxy certificates...")
        try:
            subprocess.run([
                "mitmdump", 
                "--set", f"confdir={cert_dir}",
                "--certsserver"
            ], capture_output=True, timeout=30)
            print("Certificates generated successfully")
        except Exception as e:
            print(f"Error generating certificates: {e}")
            return
    
    pem_path = os.path.join(cert_dir, "mitmproxy-ca.pem")
    cer_path = os.path.join(cert_dir, "mitmproxy-ca.cer")
    
    if os.path.exists(pem_path) and not os.path.exists(cer_path):
        try:
            with open(pem_path, "rb") as pem_file:
                pem_data = pem_file.read()
            with open(cer_path, "wb") as cer_file:
                cer_file.write(pem_data)
            print("Certificate converted to CER format")
        except Exception as e:
            print(f"Error converting certificate: {e}")
    
    if not is_certificate_installed():
        print("Installing MITMproxy certificate...")
        try:
            result = subprocess.run([
                "certutil.exe",
                "-user",
                "-addstore",
                "Root",
                cer_path
            ], capture_output=True, text=True, timeout=30)
            
            if result.returncode == 0:
                print("Certificate installed successfully")
            else:
                print(f"Certificate installation failed: {result.stderr}")
        except Exception as e:
            print(f"Error installing certificate: {e}")
    else:
        print("Certificate already installed")

async def run_proxy():
    try:
        clear_fortnite_cms()

        win32api.SetConsoleCtrlHandler(on_exit, True)
        os.system("start com.epicgames.launcher://apps/Fortnite?action=launch?silent=true")

        opts = options.Options(
            listen_host="0.0.0.0",
            listen_port=1944
        )
        master = DumpMaster(opts)
        master.addons.add(Proxy())

        set_proxy_settings("127.0.0.1:1944", 1)

        await master.run()
    except KeyboardInterrupt:
        pass
    finally:
        if 'master' in locals():
            master.shutdown()

if __name__ == '__main__':
    asyncio.run(run_proxy())