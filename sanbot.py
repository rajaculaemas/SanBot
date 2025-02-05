import os
import time
import requests
from fpdf import FPDF
from telegram import Update, ReplyKeyboardMarkup, KeyboardButton
from telegram.ext import (
    Application, CommandHandler, MessageHandler, filters, CallbackContext
)

# Konfigurasi API Key Hybrid-Analysis dan Token Bot Telegram
HYBRID_ANALYSIS_API_KEY = "<Your Hybrid-Analysis API Key>"  # HA API Key
TELEGRAM_BOT_TOKEN = "<Your Telegram Bot Token>"  # Telegram Bot API

# Pilihan environment yang tersedia di Hybrid-Analysis
ENVIRONMENTS = {
    "Windows 7 32 bit": 100,
    "Windows 7 64 bit": 120,
    "Windows 10 64 bit": 160,
    "Windows 11 64 bit": 140,
    "Android Static Analysis": 200,
    "Linux (Ubuntu 20.04, 64 bit)": 310,
    "Mac Catalina 64 bit (x86)": 400
}

# Fungsi untuk mengunggah file dari telegram ke Hybrid Analysis API
def analyze_with_hybrid_analysis(file_path, environment_id):
    url = "https://www.hybrid-analysis.com/api/v2/submit/file"
    headers = {
        "api-key": HYBRID_ANALYSIS_API_KEY,
        "User-Agent": "Telegram Malware Analysis Bot"
    }
    files = {"file": open(file_path, "rb")}
    data = {
        "environment_id": environment_id,
        "network_settings": "default",
        "allow_community_access": 1,
        "comment": "Submitted via Telegram Bot"
    }

    try:
        # Fungsi untuk mendapatkan report dari file yang telah diunggah
        response = requests.post(url, headers=headers, files=files, data=data)
        if response.status_code == 201:
            submission_id = response.json().get("job_id")
            if submission_id:
                # laporan analisis di GET by submission id
                report_url = f"https://www.hybrid-analysis.com/api/v2/report/{submission_id}/summary"
                # Tambahkan delay untuk menunggu analisis lengkap
                time.sleep(300)  # Menunggu 300 detik sebelum mengecek analisis
                report_response = requests.get(report_url, headers=headers)
                if report_response.status_code == 200:
                    return report_response.json()
                else:
                    return f"Gagal mengambil laporan analisis. Kode status: {report_response.status_code}"
            else:
                return "Gagal mendapatkan ID submission."
        else:
            return f"Gagal mengunggah file. Kode status: {response.status_code}, Pesan: {response.text}"
    except Exception as e:
        return f"Terjadi kesalahan: {str(e)}"

# Fungsi parsing JSON dari laporan analisis ke dalam output yang bisa dibaca di Telegram
def format_report(report):
    if isinstance(report, dict):
        formatted_report = f"""
# Ringkasan Analisis
**File Name**: {report.get("submit_name")}
**Verdict**: {report.get("verdict")}
**Hash md5**: {report.get("md5")}
**Threat Score**: {report.get("threat_score")}
**Malware Family**: {report.get("vx_family")}
**Suspicious Activities**: {report.get("interesting")}
**Environment**: {report.get("environment_description")}
**AV Detection Rate**: {report.get("av_detect")} detections
**Link lengkap Report**: https://www.hybrid-analysis.com/sample/{report.get("sha256")}


# Behaviour file saat di running
"""
        # **Detected MITRE ATT&CK Techniques**
        mitre_attck_techniques = ""
        for technique in report.get("mitre_attcks", []):
            technique_name = technique.get('technique', '')
            attck_id = technique.get('attck_id', '')
            attck_wiki = technique.get('attck_id_wiki', '')
            technique_string = f"- {technique_name} ({attck_id}): {attck_wiki}\n"
            if len(mitre_attck_techniques) + len(technique_string) <= 500:
                mitre_attck_techniques += technique_string
        
        if mitre_attck_techniques:
            formatted_report += f"**Detected MITRE ATT&CK Techniques**:\n{mitre_attck_techniques}"

        # **Extracted Files**
        extracted_files = ""
        for file in report.get("extracted_files", []):
            file_name = file.get('name', '')
            file_path = file.get('file_path', '')
            threat_level = file.get('threat_level_readable', '')
            file_string = f"- {file_name} ({file_path}) - Threat Level: {threat_level}\n"
            if len(extracted_files) + len(file_string) <= 500:
                extracted_files += file_string
        
        if extracted_files:
            formatted_report += f"\n**Extracted Files**:\n{extracted_files}"

        # **Processes Created**
        processes_created = ""
        for process in report.get("processes", []):
            process_name = process.get('name', '')
            pid = str(process.get('uid', ''))
            process_string = f"- {process_name} (PID: {pid})\n"
            if len(processes_created) + len(process_string) <= 500:
                processes_created += process_string
        
        if processes_created:
            formatted_report += f"\n**Processes Created**:\n{processes_created}"

        # **DLLs and Modules Loaded**
        dlls_loaded = ""
        for file in report.get("extracted_files", []):
            if "dll" in file.get("name", "").lower():
                file_name = file.get('name', '')
                file_path = file.get('file_path', '')
                dll_string = f"- {file_name} ({file_path})\n"
                if len(dlls_loaded) + len(dll_string) <= 500:
                    dlls_loaded += dll_string
        
        if dlls_loaded:
            formatted_report += f"\n**DLLs and Modules Loaded**:\n{dlls_loaded}"

        return formatted_report
    else:
        return "Gagal memproses laporan."

# Fungsi untuk membuat laporan PDF
def generate_pdf_report(report_data, file_name="report.pdf"):
    pdf = FPDF()
    pdf.set_auto_page_break(auto=True, margin=15)
    pdf.add_page()
    pdf.set_font("Arial", size=12)

    # Menambahkan data laporan ke PDF
    pdf.multi_cell(0, 10, report_data)
    
    # Menyimpan PDF
    pdf.output(file_name)
    return file_name

# Handler untuk perintah /start
async def start(update: Update, context: CallbackContext):
    keyboard = [
        [KeyboardButton("Sandbox Analysis")],
        [KeyboardButton("Menu lain 1 (TBD)")],
        [KeyboardButton("Menu lain 2 (TBD)")],
        [KeyboardButton("Menu lain 3 (TBD)")]
    ]
    reply_markup = ReplyKeyboardMarkup(keyboard, resize_keyboard=True)
    await update.message.reply_text(
        "Halo! ingin running suatu file dalam sandbox secara mudah? "
        "Silakan pilih menu di bawah ini:",
        reply_markup=reply_markup
    )

# Handler untuk tombol "Sandbox Analysis"
async def sandbox_analysis(update: Update, context: CallbackContext):
    keyboard = [[KeyboardButton(env)] for env in ENVIRONMENTS.keys()]
    reply_markup = ReplyKeyboardMarkup(keyboard, resize_keyboard=True)
    await update.message.reply_text(
        "Pilih environment untuk analisis, sesuaikan dengan tipe file yang anda ingin analisis, jan file .exe anda pilih linux busset ngerepotin:",
        reply_markup=reply_markup
    )

# Fungsi untuk menangani pemilihan environment
async def handle_environment(update: Update, context: CallbackContext):
    environment_name = update.message.text
    if environment_name in ENVIRONMENTS:
        context.user_data["environment"] = environment_name
        await update.message.reply_text(
            f"Anda memilih environment: {environment_name}. "
            "Silakan lampirkan file yang ingin dianalisis."
        )
    else:
        await update.message.reply_text("Environment tidak valid. Silakan pilih dari daftar yang tersedia.")

# Handler untuk menerima file dari pengguna
async def handle_file(update: Update, context: CallbackContext):
    environment_name = context.user_data.get("environment")
    if not environment_name:
        await update.message.reply_text("dibilang pilih environment dulu busset...")
        return

    environment_id = ENVIRONMENTS.get(environment_name)
    if not environment_id:
        await update.message.reply_text("Environment tidak valid.")
        return

    file = await update.message.document.get_file()
    file_path = f"{update.message.document.file_name}"
    await file.download_to_drive(file_path)

    await update.message.reply_text("File diterima. waktu analisis tergantung dari ukuran file, signature dan lain lain pokoknya very flexible.")
    await update.message.reply_text("jika report yang diberikan dirasa kurang lengkap maka anda perlu mengunggah ulang file setelah waktu tertentu, hal ini terjadi karena analisis file belum selesai dilakukan di sandbox")

    # Menganalisis file menggunakan Hybrid Analysis
    report = analyze_with_hybrid_analysis(file_path, environment_id)
    formatted_report = format_report(report)
    
    # Kirim laporan teks di Telegram
    max_length = 4096
    while len(formatted_report) > max_length:
        await update.message.reply_text(formatted_report[:max_length])
        formatted_report = formatted_report[max_length:]
    
    # Kirim sisa pesan
    if formatted_report:
        await update.message.reply_text(formatted_report)

    # Generate PDF dan kirimkan ke Telegram
    pdf_file_path = generate_pdf_report(formatted_report, "analisis_report.pdf")
    with open(pdf_file_path, "rb") as pdf_file:
        await update.message.reply_document(pdf_file, caption="Laporan PDF Analisis")

    # Hapus file sementara
    os.remove(file_path)
    os.remove(pdf_file_path)

# Fungsi utama untuk menjalankan bot
def main():
    application = Application.builder().token(TELEGRAM_BOT_TOKEN).build()

    application.add_handler(CommandHandler("start", start))
    application.add_handler(MessageHandler(filters.Regex("^Sandbox Analysis$"), sandbox_analysis))
    application.add_handler(MessageHandler(filters.Regex("^(" + "|".join(ENVIRONMENTS.keys()) + ")$"), handle_environment))
    application.add_handler(MessageHandler(filters.Document.ALL, handle_file))

    application.run_polling()

if __name__ == "__main__":
    main()
