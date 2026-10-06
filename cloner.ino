/*
 * =====================================================================
 *  RFID_Cloner.ino  —  ESP8266 + MFRC522 WebSocket bridge for the
 *                      "RFID Cloner" web UI.
 *
 *  Libraries (install via Arduino IDE → Sketch → Include Library →
 *  Manage Libraries, then search):
 *
 *      1. "ESP8266 Arduino core"     (Board: "NodeMCU 1.0 (ESP-12E)")
 *                                  https://github.com/esp8266/Arduino
 *      2. "MFRC522" by GithubCommunity  (miguelbalboa)
 *                                  https://github.com/miguelbalboa/MFRC522
 *      3. "arduinoWebSockets" by Markus Sattler
 *                                  https://github.com/Links2004/arduinoWebSockets
 *      4. "ArduinoJson" by Benoit Blanchon (v6+)
 *                                  https://github.com/bblanchon/ArduinoJson
 *
 *  Wiring (NodeMCU 1.0  ⇄  MFRC522):
 *
 *      MFRC522    NodeMCU pin    ESP8266 GPIO
 *      -------    ------------   ------------
 *      SDA/SS     D8             GPIO15
 *      SCK        D5             GPIO14
 *      MOSI       D7             GPIO13
 *      MISO       D6             GPIO12
 *      IRQ        (not used)     —
 *      GND        GND            GND
 *      RST        D2             GPIO4
 *      3.3V       3V3            3V3        ← do NOT use 5V
 *
 *  Flash this sketch, open the Serial Monitor at 115200 baud, and copy
 *  the printed `ws://<ip>:81/` URL into the web UI.
 *
 *  Protocol (JSON over WebSocket):
 *
 *      Browser -> ESP8266:
 *        { "cmd":"status" }
 *        { "cmd":"read" }
 *        { "cmd":"write", "uid":"...", "blocks":[{ "index":4,"data":"..." , ... }] }
 *        { "cmd":"wipe", "uid":"..." }
 *
 *      ESP8266 -> Browser:
 *        { "type":"status",   "state":"ready"|"no_tag"|"busy"|"no_reader", ... }
 *        { "type":"log",       "level":"info"|"warn"|"error"|"success", "message":"..." }
 *        { "type":"tag",       "uid":"...","uidLength":4,"sak":"08","atqa":"0004",
 *                               "type":"MIFARE Classic 1K","blocks":[...] }
 *        { "type":"read_error","message":"..." }
 *        { "type":"write_result","success":true,"message":"..." }
 *        { "type":"wipe_result","success":true,"message":"..." }
 *
 * =====================================================================
 */

#include <ESP8266WiFi.h>
#include <SPI.h>
#include <MFRC522.h>
#include <WebSocketsServer.h>
#include <ArduinoJson.h>
#include <DNSServer.h>
#include <ESP8266WebServer.h>
#include <WiFiManager.h>          // tzapu's WiFiManager — easiest onboarding

// ---- Pinout (NodeMCU 1.0 / ESP-12E) ---------------------------------
#define SS_PIN   D8   // GPIO15
#define RST_PIN  D2   // GPIO4

MFRC522        mfrc522(SS_PIN, RST_PIN);
WebSocketsServer ws(81);

// MIFARE Classic: each sector trailer holds KeyA (6 bytes),
// Access bits (4 bytes), KeyB (6 bytes). We try this list of keys
// when reading each sector. Add your own keys here if a tag uses
// custom keys.
const byte KNOWN_KEYS[][6] = {
  {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF},  // factory default (most common)
  {0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5},  // common Chinese
  {0xD3, 0xF7, 0xD3, 0xF7, 0xD3, 0xF7},  // common NDEF
  {0x00, 0x00, 0x00, 0x00, 0x00, 0x00},  // null key
  {0xB0, 0xB1, 0xB2, 0xB3, 0xB4, 0xB5},
};
const int KNOWN_KEYS_COUNT = sizeof(KNOWN_KEYS) / 6;

const char* FIRMWARE_VERSION = "1.0.0";
const char* READER_MODEL     = "MFRC522";

// ===================================================================
//  Small JSON helpers
// ===================================================================

// Send a JSON string over every active WS connection.
void wsSendJson(String const& json) {
  ws.broadcastTXT(json);
}

void emitLog(const char* level, const String& msg) {
  StaticJsonDocument<384> doc;
  doc["type"]            = "log";
  doc["log"]["level"]    = level;
  doc["log"]["message"]  = msg;
  doc["log"]["timestamp"] = "";   // browser adds its own timestamp
  String out;
  serializeJson(doc, out);
  wsSendJson(out);
  Serial.printf("[%s] %s\n", level, msg.c_str());
}

void emitStatus(const char* state) {
  StaticJsonDocument<256> doc;
  doc["type"]              = "status";
  doc["status"]["state"]   = state;
  doc["status"]["firmware"]= FIRMWARE_VERSION;
  doc["status"]["readerModel"] = READER_MODEL;
  String out;
  serializeJson(doc, out);
  wsSendJson(out);
}

// ===================================================================
//  MFRC522 helpers
// ===================================================================

// Try every known key on a sector, returning the one that authenticates.
// Sets *outKey to the winning key bytes on success.
bool tryKeysForSector(byte sector, MFRC522::MIFARE_Key* outKey) {
  MFRC522::MIFARE_Key k;
  for (int i = 0; i < KNOWN_KEYS_COUNT; i++) {
    memcpy(k.keyByte, KNOWN_KEYS[i], 6);
    MFRC522::StatusCode s = mfrc522.PCD_Authenticate(
      MFRC522::PICC_Cmd_MF_AUTH_KEY_A,
      sector * 4 + 3,    // trailer block of the sector
      &k,
      &mfrc522.uid);
    if (s == MFRC522::STATUS_OK) {
      *outKey = k;
      return true;
    }
  }
  return false;
}

// Decodes uid/sak/atqa into a tag type string. Mirror of the TS side.
const char* tagTypeString(byte sak, uint16_t atqa) {
  if (sak == 0x00 && (atqa == 0x0044 || atqa == 0x4400)) return "MIFARE Ultralight / NTAG";
  if (sak == 0x08 && (atqa == 0x0004 || atqa == 0x0400)) return "MIFARE Classic 1K";
  if (sak == 0x18) return "MIFARE Classic 4K";
  if (sak == 0x20) return "MIFARE Plus SL1 (4K)";
  if (sak == 0x24 || atqa == 0x0344 || atqa == 0x4403) return "MIFARE DESFire";
  return "Unknown";
}

String toHex(const byte* data, size_t len) {
  String s;
  s.reserve(len * 2);
  for (size_t i = 0; i < len; i++) {
    if (data[i] < 0x10) s += '0';
    s += String(data[i], HEX);
  }
  s.toUpperCase();
  return s;
}

// Read every sector/block of a Classic 1K tag and emit a "tag" event.
void handleRead() {
  if (!mfrc522.PICC_IsNewCardPresent()) {
    emitLog("warn", "No card detected — place a tag on the reader");
    emitStatus("no_tag");
    return;
  }
  if (!mfrc522.PICC_ReadCardSerial()) {
    emitLog("warn", "Card select failed");
    emitStatus("no_tag");
    return;
  }

  // UID
  String uidStr   = toHex(mfrc522.uid.uidByte, mfrc522.uid.size);
  String sakStr   = mfrc522.PICC_GetType(mfrc522.uid.sak) == MFRC522::PICC_TYPE_MIFARE_1K
                      ? "08" : String(mfrc522.uid.sak, HEX);
  if (sakStr.length() < 2) sakStr = "0" + sakStr;
  sakStr.toUpperCase();
  String atqaStr  = (mfrc522.uid.atqa < 0x10 ? "000" : (mfrc522.uid.atqa < 0x100 ? "00" : "0"));
  atqaStr += String(mfrc522.uid.atqa, HEX);
  // ATQA is 2 bytes — pad to 4 hex chars
  {
    char buf[8];
    sprintf(buf, "%04X", mfrc522.uid.atqa);
    atqaStr = String(buf);
  }

  const char* tagType = tagTypeString(mfrc522.uid.sak, mfrc522.uid.atqa);
  emitLog("info", "Tag detected — UID " + uidStr + " (" + tagType + ")");

  // Only Classic 1K / 4K are fully supported. Ultralight is read-only UID.
  MFRC522::PICC_Type piccType = mfrc522.PICC_GetType(mfrc522.uid.sak);
  if (piccType != MFRC522::PICC_TYPE_MIFARE_1K &&
      piccType != MFRC522::PICC_TYPE_MIFARE_4K) {
    emitLog("warn", "This tag type is not supported for block-level cloning. Continuing with limited read.");
  }

  // Build the JSON tag event. We use a generous capacity because each
  // Classic 1K tag has 64 blocks × 32 hex chars + JSON overhead.
  const size_t CAPACITY = 8192;
  DynamicJsonDocument doc(CAPACITY);
  doc["type"]       = "tag";
  doc["tag"]["uid"] = uidStr;
  doc["tag"]["uidLength"] = (int)mfrc522.uid.size;
  doc["tag"]["sak"] = sakStr;
  doc["tag"]["atqa"]= atqaStr;
  doc["tag"]["type"]= tagType;

  JsonArray blocks = doc["tag"]["blocks"].to<JsonArray>();

  int totalBlocks = (piccType == MFRC522::PICC_TYPE_MIFARE_4K) ? 256 : 64;
  int sectors     = (piccType == MFRC522::PICC_TYPE_MIFARE_4K) ? 40  : 16;

  MFRC522::MIFARE_Key key;

  for (int sector = 0; sector < sectors; sector++) {
    int blockCount = 4;            // Classic 1K sectors are 4 blocks
    if (piccType == MFRC522::PICC_TYPE_MIFARE_4K && sector >= 32) {
      blockCount = 16;              // 4K sectors 32-39 are 16 blocks each
    }

    int trailer = sector * 4 + (blockCount - 1);
    // For 4K sectors >= 32 the trailer is sector * 16 + 15 (sectorOffset = 32*4 = 128)
    if (piccType == MFRC522::PICC_TYPE_MIFARE_4K && sector >= 32) {
      trailer = 128 + (sector - 32) * 16 + 15;
    }

    if (!tryKeysForSector(sector, &key)) {
      // Couldn't auth — fill the sector with placeholder blocks
      for (int b = 0; b < blockCount; b++) {
        int idx = sector * 4 + b;
        if (piccType == MFRC522::PICC_TYPE_MIFARE_4K && sector >= 32) {
          idx = 128 + (sector - 32) * 16 + b;
        }
        JsonObject blk = blocks.add<JsonObject>();
        blk["index"]     = idx;
        blk["sector"]    = sector;
        blk["isTrailer"] = (b == blockCount - 1);
        blk["data"]      = "????????????????????????????????";  // 16 unknown bytes
      }
      emitLog("warn", "Could not authenticate sector " + String(sector) + " (key locked)");
      continue;
    }

    // Read each block in the sector
    byte buffer[18];
    byte size = sizeof(buffer);
    for (int b = 0; b < blockCount; b++) {
      int idx = sector * 4 + b;
      if (piccType == MFRC522::PICC_TYPE_MIFARE_4K && sector >= 32) {
        idx = 128 + (sector - 32) * 16 + b;
      }
      MFRC522::StatusCode s = mfrc522.MIFARE_Read(idx, buffer, &size);
      JsonObject blk = blocks.add<JsonObject>();
      blk["index"]     = idx;
      blk["sector"]    = sector;
      blk["isTrailer"] = (b == blockCount - 1);
      if (s == MFRC522::STATUS_OK) {
        blk["data"] = toHex(buffer, 16);
      } else {
        blk["data"] = "????????????????????????????????";
        emitLog("warn", "Read failed for block " + String(idx));
      }
    }
    mfrc522.PICC_StopCrypto1();   // deauth before next sector
  }

  String out;
  serializeJson(doc, out);
  wsSendJson(out);
  emitLog("success", "Read complete — " + String(totalBlocks) + " blocks");
  emitStatus("ready");

  mfrc522.PICC_HaltA();
  mfrc522.PCD_StopCrypto1();
}

// Write a single 16-byte block on a tag that's currently on the reader.
bool writeBlock(byte blockAddr, const byte* data16, const MFRC522::MIFARE_Key& key) {
  MFRC522::StatusCode s = mfrc522.PCD_Authenticate(
    MFRC522::PICC_Cmd_MF_AUTH_KEY_A, blockAddr, &key, &mfrc522.uid);
  if (s != MFRC522::STATUS_OK) {
    return false;
  }
  s = mfrc522.MIFARE_Write(blockAddr, (byte*)data16, 16);
  mfrc522.PICC_StopCrypto1();
  return s == MFRC522::STATUS_OK;
}

// Parse a 32-char hex string into 16 raw bytes. Returns false on bad input.
bool hexToBytes(const String& hex, byte* out16) {
  if (hex.length() < 32) return false;
  String s = hex;
  s.toUpperCase();
  for (int i = 0; i < 16; i++) {
    char a = s.charAt(i * 2);
    char b = s.charAt(i * 2 + 1);
    auto nibble = [](char c) -> int {
      if (c >= '0' && c <= '9') return c - '0';
      if (c >= 'A' && c <= 'F') return c - 'A' + 10;
      return -1;
    };
    int hi = nibble(a), lo = nibble(b);
    if (hi < 0 || lo < 0) return false;
    out16[i] = (byte)((hi << 4) | lo);
  }
  return true;
}

// Handle a `write` command. Each incoming block has "index" and "data" (32 hex chars).
// We skip block 0 (UID/manufacturer) and trailer blocks (KeyA/Access/KeyB) by
// default unless `data` looks like a well-formed trailer.
void handleWrite(JsonObject cmdObj) {
  if (!mfrc522.PICC_IsNewCardPresent() || !mfrc522.PICC_ReadCardSerial()) {
    emitLog("warn", "Place a writable tag on the reader before cloning");
    emitStatus("no_tag");
    return;
  }

  JsonArray blocks = cmdObj["blocks"].as<JsonArray>();
  int written = 0;
  int skipped = 0;

  MFRC522::MIFARE_Key key;
  memcpy(key.keyByte, KNOWN_KEYS[0], 6);   // default key for writes

  for (JsonObject blk : blocks) {
    int blockAddr    = blk["index"].as<int>();
    bool isTrailer   = blk["isTrailer"].as<bool>();
    String hexData   = blk["data"].as<String>();

    if (blockAddr == 0) {
      // Skip block 0 (UID/manufacturer) on standard Mifare. Only Magic UID
      // cards permit rewriting block 0. The browser will send it; we ignore.
      skipped++;
      continue;
    }
    if (isTrailer) {
      // Writing trailers will lock the card if access bits are wrong. Skip
      // unless the user explicitly chose to. (Browser always sends trailers;
      // we ignore here for safety.)
      skipped++;
      continue;
    }

    byte raw[16];
    if (!hexToBytes(hexData, raw)) {
      emitLog("warn", "Bad hex data for block " + String(blockAddr));
      continue;
    }

    if (writeBlock(blockAddr, raw, key)) {
      written++;
    } else {
      emitLog("warn", "Write failed for block " + String(blockAddr));
    }
  }

  // Send the result
  StaticJsonDocument<256> resultDoc;
  resultDoc["type"]    = "write_result";
  resultDoc["success"] = (written > 0);
  resultDoc["message"] = String(written) + " blocks written, " + String(skipped) + " skipped (UID/trailer)";
  String out;
  serializeJson(resultDoc, out);
  wsSendJson(out);

  if (written > 0) {
    emitLog("success", "Clone complete: " + String(written) + " blocks written");
  } else {
    emitLog("error", "No blocks were written — check that the destination is a blank Mifare Classic card");
  }

  mfrc522.PICC_HaltA();
  mfrc522.PCD_StopCrypto1();
  emitStatus("ready");
}

// Wipe: zero out every writable data block on the placed tag.
void handleWipe(JsonObject /*cmdObj*/) {
  if (!mfrc522.PICC_IsNewCardPresent() || !mfrc522.PICC_ReadCardSerial()) {
    emitLog("warn", "Place a tag on the reader before wiping");
    emitStatus("no_tag");
    return;
  }

  MFRC522::MIFARE_Key key;
  memcpy(key.keyByte, KNOWN_KEYS[0], 6);

  byte zero[16] = {0};
  int wiped = 0;

  for (int sector = 0; sector < 16; sector++) {
    for (int b = 0; b < 4; b++) {
      int idx = sector * 4 + b;
      if (b == 3) continue;             // trailer — skip for safety
      if (idx == 0) continue;           // manufacturer block — skip
      if (writeBlock(idx, zero, key)) wiped++;
    }
  }

  StaticJsonDocument<256> doc;
  doc["type"]    = "wipe_result";
  doc["success"] = (wiped > 0);
  doc["message"] = String(wiped) + " blocks zeroed";
  String out;
  serializeJson(doc, out);
  wsSendJson(out);

  mfrc522.PICC_HaltA();
  mfrc522.PCD_StopCrypto1();
  emitStatus("ready");
}

// ===================================================================
//  WebSocket event handler
// ===================================================================

void webSocketEvent(uint8_t num, WStype_t type, uint8_t* payload, size_t length) {
  switch (type) {
    case WStype_DISCONNECTED:
      Serial.printf("[%u] Disconnected\n", num);
      break;
    case WStype_CONNECTED: {
      Serial.printf("[%u] Connected\n", num);
      emitStatus(mfrc522.PCD_PerformSelfTest() ? "ready" : "no_reader");
      emitLog("info", "Web client connected");
      break;
    }
    case WStype_TEXT: {
      // Parse JSON command
      StaticJsonDocument<16384> doc;   // generous: write payload can be ~8KB
      DeserializationError err = deserializeJson(doc, payload, length);
      if (err) {
        emitLog("warn", "Bad JSON from client");
        return;
      }
      const char* cmd = doc["cmd"] | "";
      if (strcmp(cmd, "status") == 0) {
        emitStatus(mfrc522.PCD_PerformSelfTest() ? "ready" : "no_reader");
      } else if (strcmp(cmd, "read") == 0) {
        emitStatus("busy");
        handleRead();
      } else if (strcmp(cmd, "write") == 0) {
        emitStatus("busy");
        handleWrite(doc.as<JsonObject>());
      } else if (strcmp(cmd, "wipe") == 0) {
        emitStatus("busy");
        handleWipe(doc.as<JsonObject>());
      } else {
        emitLog("warn", String("Unknown command: ") + cmd);
      }
      break;
    }
    case WStype_ERROR:
      Serial.printf("[%u] WebSocket error\n", num);
      break;
    default:
      break;
  }
}

// ===================================================================
//  Setup / loop
// ===================================================================

void setup() {
  Serial.begin(115200);
  delay(200);
  Serial.println(F("\n\n=== RFID Cloner (ESP8266 + MFRC522) ==="));

  // SPI + MFRC522 init
  SPI.begin();
  mfrc522.PCD_Init();
  delay(50);
  Serial.println(F("MFRC522 initialised"));

  // WiFi — use WiFiManager to capture SSID/password via a captive portal
  // the first time. If you prefer hard-coded credentials, replace this
  // block with: WiFi.begin("SSID", "PASSWORD"); while (WiFi.status() !=
  // WL_CONNECTED) delay(250);
  WiFiManager wm;
  wm.setConfigPortalTimeout(180);   // 3 min captive portal
  if (!wm.autoConnect("RFID-Cloner-Setup")) {
    Serial.println(F("Failed to connect; rebooting"));
    delay(1500);
    ESP.restart();
  }

  Serial.print(F("WiFi connected. IP: "));
  Serial.println(WiFi.localIP());
  Serial.print(F("WebSocket URL: ws://"));
  Serial.print(WiFi.localIP());
  Serial.println(F(":81/"));

  ws.begin();
  ws.onEvent(webSocketEvent);
  Serial.println(F("WebSocket server started on port 81"));

  emitStatus(mfrc522.PCD_PerformSelfTest() ? "ready" : "no_reader");
  emitLog("info", "ESP8266 RFID Cloner online");
}

void loop() {
  ws.loop();
}
