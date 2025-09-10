import asyncio
import json
import os
import subprocess
import winreg
import win32api
import psutil
import ssl
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from mitmproxy import http, options, certs
from mitmproxy.tools.dump import DumpMaster

with open("shop.json", "r", encoding="utf-8") as f:
    CUSTOM_SHOP = json.load(f)

with open("common_core.json", "r", encoding="utf-8") as f:
    COMMON_CORE = json.load(f)

with open("athena.json", "r", encoding="utf-8") as f:
    ATHENA = json.load(f)

with open("content.json", "r", encoding="utf-8") as f:
    CONTENT = json.load(f)

def set_proxy_settings(proxy_server, enable_proxy):
    reg_path = r'Software\Microsoft\Windows\CurrentVersion\Internet Settings'
    try:
        key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, reg_path, 0, winreg.KEY_WRITE)
        winreg.SetValueEx(key, 'ProxyServer', 0, winreg.REG_SZ, proxy_server)
        winreg.SetValueEx(key, 'ProxyEnable', 0, winreg.REG_DWORD, enable_proxy)
        winreg.CloseKey(key)
        print(f"Proxy settings updated: {proxy_server}, Enabled: {enable_proxy}")
    except Exception as e:
        print(f"Error setting proxy: {e}")

def kill_process_by_name(name):
    for proc in psutil.process_iter(['pid', 'name']):
        if name.lower() in proc.info['name'].lower():
            try:
                proc.kill()
                print(f"Killed process: {name}")
            except psutil.NoSuchProcess:
                pass

def on_exit(signal_type):
    set_proxy_settings("", 0)
    kill_process_by_name("FortniteClient-Win64-Shipping_EAC_EOS.exe")
    kill_process_by_name("FortniteClient-Win64-Shipping.exe")
    kill_process_by_name("FortniteLauncher.exe")
    print("Proxy stopped and settings cleaned up")

class CustomProxy:
    def response(self, flow: http.HTTPFlow):
        url = flow.request.pretty_url

        if "/fortnite/api/storefront/v2/catalog" in url:
            flow.response = http.Response.make(
                200,  
                json.dumps(CUSTOM_SHOP, indent=2),  
                {"Content-Type": "application/json"}
            )
            print("Custom shop response injected")

        if "fortnite/api/game/v2/profile" in url and "common_core" in url:
            flow.response = http.Response.make(
                200,  
                json.dumps(COMMON_CORE, indent=2),  
                {"Content-Type": "application/json"}
            )
            print("Common core response injected")

        if "fortnite/api/game/v2/profile" in flow.request.url and "athena" in flow.request.url:
            try:
                req_data = json.loads(flow.request.text)
                res_data = ATHENA

                if req_data:
                    category = req_data.get('category')
                    lockerItem = req_data.get('lockerItem')
                    itemId = req_data.get('itemToSlot')
                    slotIndex = req_data.get('slotIndex')
                    variantUpdates = req_data.get('variantUpdates', {})
                    channel = variantUpdates.get('channel')
                    active = variantUpdates.get('active')

                    profile = res_data['profileChanges'][0]['profile']
                    items = profile['items']

                    sandbox = items[lockerItem]
                    attributes = sandbox['attributes']
                    locker_slots_data = attributes['locker_slots_data']
                    slots = locker_slots_data['slots']

                    slots[category] = {
                        "items": [itemId],
                        "activeVariants": [] if not variantUpdates else [
                            {
                                "variants": [
                                    {
                                        "channel": channel,
                                        "active": active
                                    }
                                ]
                            }
                        ]
                    }

                flow.response = http.Response.make(
                    200,
                    json.dumps(res_data, indent=2),
                    {"Content-Type": "application/json"}
                )
                print("Athena response injected")

            except Exception as e:
                print(f"Error injecting Athena response: {e}")


        if "content/api/pages/fortnite-game" in url:
            flow.response = http.Response.make(
                200,  
                json.dumps(CONTENT, indent=2),  
                {"Content-Type": "application/json"}
            )
            print("Content response injected")

        if "account/api/oauth/token" in url:
            try:
                data = json.loads(flow.response.text)
                data['displayName'] = "star\n" * 5
                flow.response = http.Response.make(
                    200,  
                    json.dumps(data, indent=2),  
                    {"Content-Type": "application/json"}
                )
                print("OAuth token response modified")
            except Exception as e:
                print(f"Error modifying OAuth response: {e}")


def is_certificate_installed():
    try:
        fingerprint = certs.CertStore.from_store(
            path=os.path.expanduser("~/.mitmproxy/"),
            basename="mitmproxy",
            key_size=2048
        ).default_ca.fingerprint()

        return any(
            x509.load_der_x509_certificate(cert).fingerprint(hashes.SHA256()) == fingerprint
            for cert, _, _ in ssl.enum_certificates("ROOT")
        )
    except Exception as e:
        print(f"Certificate check error: {e}")
        return False

async def install_certificate():
    cert_path = os.path.expanduser("~/.mitmproxy/mitmproxy-ca-cert.cer")
    
    if not os.path.exists(cert_path):
        print("MITMproxy certificate not found. Generating certificate...")
        opts = options.Options()
        master = DumpMaster(opts)
        master.shutdown()
    
    if not os.path.exists(cert_path):
        print("Failed to generate certificate. HTTPS interception may not work.")
        return
    
    while not is_certificate_installed():
        try:
            print("Installing MITMproxy certificate...")
            result = subprocess.run([
                "certutil.exe",
                "-user",
                "-addstore",
                "Root",
                cert_path
            ], capture_output=True, text=True, check=True)
            
            if "ERROR" not in result.stdout:
                print("Certificate installed successfully")
                break
            else:
                print("Certificate installation failed, retrying...")
                await asyncio.sleep(1)
                
        except subprocess.CalledProcessError as e:
            print(f"Certificate installation error: {e}")
            await asyncio.sleep(1)
        except Exception as e:
            print(f"Unexpected error during certificate installation: {e}")
            await asyncio.sleep(1)

async def run_proxy():
    try:
        await install_certificate()
        
        win32api.SetConsoleCtrlHandler(on_exit, True)
        
        opts = options.Options(
            listen_host="0.0.0.0",
            listen_port=1944
        )
        
        master = DumpMaster(opts)
        master.addons.add(CustomProxy())
        
        set_proxy_settings("127.0.0.1:1944", 1)
        
        print("Proxy started on 127.0.0.1:1944")
        print("Press Ctrl+C to stop the proxy and restore settings")
        
        await master.run()
        
    except KeyboardInterrupt:
        print("Proxy interrupted by user")
    except Exception as e:
        print(f"Error running proxy: {e}")
    finally:
        on_exit(None)
        if 'master' in locals():
            master.shutdown()

if __name__ == '__main__':
    asyncio.run(run_proxy())