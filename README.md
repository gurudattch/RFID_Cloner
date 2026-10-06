A. Flash the ESP8266 firmware (one-time, ~10 min)

    Install Arduino IDE + add ESP8266 board package:
         File → Preferences → "Additional boards manager URLs" → paste https://arduino.esp8266.com/stable/package_esp8266com_index.json
         Tools → Board → Boards Manager → search esp8266 → install
         Tools → Board → NodeMCU 1.0 (ESP-12E Module)

    Install 4 libraries (Tools → Manage Libraries, search each):
         MFRC522 by GithubCommunity
         WebSockets by Markus Sattler
         ArduinoJson by Benoit Blanchon
         WiFiManager by tzapu

    Wire MFRC522 → NodeMCU (7 jumpers):
    MFRC522
    	
    NodeMCU
    	
    GPIO
    3V3	3V3	—
    GND	GND	—
    RST	D2	GPIO4
    SDA/SS	D8	GPIO15
    MOSI	D7	GPIO13
    MISO	D6	GPIO12
    SCK	D5	GPIO14
     
     

    ⚠️ Power the MFRC522 from 3V3, never 5V.

    Open /home/z/my-project/download/esp8266-rfid/RFID_Cloner.ino → select your board + port → Upload.

    Open Serial Monitor at 115200 baud. The ESP8266 boots into AP mode and advertises a WiFi network called RFID-Cloner-Setup. Join it from your phone/laptop, browse to 192.168.4.1, pick your home WiFi, enter its password. The ESP8266 reboots and prints:
    text
     
      
     
     
    WiFi connected. IP: 192.168.1.50
    WebSocket URL: ws://192.168.1.50:81/
     
     

B. Use the web UI (every session, ~30 sec)

    Open the preview link.
    Paste ws://192.168.1.50:81/ (the URL from Serial Monitor) into the URL field.
    Click Connect → the pill goes Online.
    Place a tag on the reader → click Read tag → UID + type + block count appear inline.
    Click Save → tag is now in IndexedDB in this browser. Persists across reloads, survives reboots.
    To clone: place a blank Magic UID Mifare Classic card on the reader → find the saved tag → click Clone. Result message shows below the list.

C. Try without any hardware (Demo Mode, 0 min)

Just toggle Demo → click Connect → click Read tag. The UI simulates a Mifare Classic 1K tag with a random 7-byte UID and 64 blocks. Use this to validate the UI before your hardware arrives.
The 100% works checklist (also in download/esp8266-rfid/README.md)
✅ Required for full read+write
NodeMCU 1.0 / Wemos D1 (or any ESP8266 with this pinout)
Genuine MFRC522 wired correctly, powered at 3V3 (not 5V)
All 4 libraries installed
Tag is a MIFARE Classic 1K or 4K (the default blue clamshell card that ships with every MFRC522 kit satisfies this)
Destination blank is a Magic UID Mifare Classic (≈$1 each — search "CUID Mifare 1K magic UID")
Computer/phone running the UI is on the same WiFi as the ESP8266
 
 

Honest caveat: standard Mifare Classic cards are read-only at block 0 (the UID) at the factory. So you can clone every sector of data, but the destination keeps its own UID unless you use a Magic UID blank. Most door/access systems check the UID, so a Magic UID blank is the realistic path.

Next steps for you: 

    Open the preview, toggle Demo, click Connect, then Read tag → Save → Clone to see the new minimal flow.
    When hardware arrives, follow the 5-step "Flash the firmware" guide above.
    If you want to add custom tag keys (e.g. you know the door reader uses a specific Key A), add them to KNOWN_KEYS[] in RFID_Cloner.ino and re-flash.
