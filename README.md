# SanBot **(An Easy Sandbox Malware or File Analysis Using Telegram Bot)**

**A. OVERVIEW**

To build this system, we integrated the Hybrid-Analysis API, which enables automatic malware analysis using files sent through the Telegram bot. Here are the technical steps involved in this system:

**1. File Reception from Users**

Users send files through the Telegram Bot, which is then downloaded by the bot and prepared for analysis.

**2. Sending the File to Hybrid-Analysis API**

The received file is sent to the Hybrid-Analysis platform for analysis within a secure sandbox environment. This process involves selecting the appropriate environment based on the file type (e.g., Windows, Linux, or Android).

**3. Analysis Results**

Once the file is sent for analysis, the bot waits for the results. The waiting time varies depending on the size and complexity of the file being analyzed, which may take several minutes. Therefore, the system is also equipped with a delaying mechanism that ensures more complete and accurate results.

**4. Report Delivery to Users**

After the analysis results are obtained, the bot will send the report in two forms: a text report that can be read directly on Telegram and a more detailed PDF report.

**5. Security and Performance**
We also prioritize user data security and system performance, ensuring that file sending and receiving processes are conducted securely, and reports are generated in a reasonable time frame.

**B. REQUIREMENT AND CODE**

**1. Requirement**

To develop this malware analysis bot, the following components or requirements are needed:

- Hybrid-Analysis API key and API Endpoint
- Telegram Bot Token
- Python version 3.13 or higher
- Python Libraries (os, time, requests, fpdf, python-telegram-bot)
- A server with an internet connection (no need for a public IP or DNS) to run the script

**2. Code**

At this stage, source code development is carried out using the Python programming language. The reason for using Python is because it is more flexible and has many libraries that can be imported for backend communication with both the Telegram Bot and the Hybrid-Analysis API. The source code development should also follow the previously created sequence diagram. This approach will facilitate the creation of functions within the source code. Some of the functions in the current source code development are as follows:

- Configuration of the Hybrid-Analysis API Key and Telegram Bot Token
- Creation of environment options for the Bot user based on the available environment options in Hybrid-Analysis
- Function to upload files from Telegram to the Hybrid-Analysis API
- Function to retrieve the report from the uploaded file
- "Delaying" function to wait for the analysis results from the sandbox to be completed. The waiting time for the analysis results can vary depending on the file to be analyzed
- JSON parsing function (Hybrid-Analysis API output) into a format that can be read on Telegram
- Function to generate a report in PDF format
- Handler function to manage commands from the Telegram Bot user (start, menu options, environment options, file upload)
- Main function to run the bot
