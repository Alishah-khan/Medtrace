/*
  MedTrace firmware - ESP32 (arduino-esp32 core 3.x)
  - signs every reading with ECDSA P-256 and links records in a hash chain
  - works fully offline; uploads to the backend when WiFi is available
  - two-card handover (sender, then receiver) creates a signed condition snapshot
  Libraries: MFRC522, OneWire, DallasTemperature, Adafruit SSD1306, Adafruit GFX, RTClib
*/
#include <Arduino.h>
#include <Adafruit_GFX.h>
#include <Adafruit_SSD1306.h>
#include <DallasTemperature.h>
#include <DHT.h>
#include <HTTPClient.h>
#include <LittleFS.h>
#include <MFRC522.h>
#include <OneWire.h>
#include <Preferences.h>
#include <RTClib.h>
#include <SPI.h>
#include <WiFi.h>
#include <Wire.h>
#include <time.h>

#include "config.h"
#include "mt_record.h"

// ---------- devices ----------
MFRC522 rfid(PIN_RFID_SS, PIN_RFID_RST);
OneWire oneWire(PIN_ONEWIRE);
DallasTemperature ds(&oneWire);
Adafruit_SSD1306 oled(128, 64, &Wire, -1);
RTC_DS3231 rtc;
DHT dht(PIN_DHT22, DHT22);
Preferences prefs;

mt::Signer signer;
mt::Chain chain;

bool haveRtc = false, haveMpu = false, haveOled = false;
uint32_t timeBase = 0;  // epoch at millis()==0 when no RTC is present

// ---------- sync state ----------
uint32_t syncedSeq = 0;     // last record number the backend confirmed
uint32_t syncedOffset = 0;  // byte position in the log after that record
uint32_t nextSync = 0;
bool syncRejected = false;

// ---------- live state ----------
float lastTemp = NAN;
float lastHumidity = NAN;
bool tempOut = false, humidOut = false, doorOpen = false, tilted = false, sensorErr = false;
float minT = 999, maxT = -999;
uint16_t excursions = 0, doorEvents = 0;  // counters since the last handover
uint32_t lastRead = 0, lastMotion = 0, lastDraw = 0, lastShake = 0;
float prevMag = 1.0f;

enum HState { H_IDLE, H_WAIT_RECEIVER };
HState hstate = H_IDLE;
String senderUid;
uint32_t hstateSince = 0;

String banner1, banner2;
uint32_t bannerUntil = 0;
bool bannerBad = false;
uint32_t buzzUntil = 0;

// ---------- small helpers ----------
static long extractNum(const String& s, const char* key) {
  int i = s.indexOf(key);
  if (i < 0) return -1;
  return s.substring(i + strlen(key)).toInt();
}

static String extractStr(const String& s, const char* key) {
  int i = s.indexOf(key);
  if (i < 0) return "";
  i += strlen(key);
  int j = s.indexOf('"', i);
  return (j < 0) ? String("") : s.substring(i, j);
}

void beep(uint32_t ms) {
  digitalWrite(PIN_BUZZER, HIGH);
  buzzUntil = millis() + ms;
}

void showBanner(const String& a, const String& b, bool bad, uint32_t ms) {
  banner1 = a;
  banner2 = b;
  bannerBad = bad;
  bannerUntil = millis() + ms;
}

// ---------- clock ----------
uint32_t nowEpoch() {
  if (haveRtc) return rtc.now().unixtime();
  if (timeBase) return timeBase + millis() / 1000;
  return millis() / 1000;
}

bool clockLooksValid() { return nowEpoch() > 1700000000UL; }

void setClock(uint32_t epoch) {
  if (haveRtc) rtc.adjust(DateTime(epoch));
  else timeBase = epoch - millis() / 1000;
}

void ntpClock(bool force) {
  if (WiFi.status() != WL_CONNECTED) return;
  configTime(0, 0, "pool.ntp.org", "time.google.com");
  uint32_t t0 = millis();
  while (time(nullptr) < 1700000000 && millis() - t0 < 6000) delay(200);
  time_t now = time(nullptr);
  if (now > 1700000000 && (force || !clockLooksValid())) setClock((uint32_t)now);
}

// ---------- log storage ----------
bool validLine(const String& l) {
  return l.length() > 40 && l[0] == '{' && l[l.length() - 1] == '}' && l.indexOf("\"g\":\"") > 0;
}

void truncateLog(size_t keepBytes) {
  File src = LittleFS.open(LOG_PATH, "r");
  File dst = LittleFS.open("/log.tmp", "w");
  if (!src || !dst) return;
  uint8_t buf[256];
  size_t left = keepBytes;
  while (left > 0) {
    size_t want = (left < sizeof(buf)) ? left : sizeof(buf);
    size_t n = src.read(buf, want);
    if (n == 0) break;
    dst.write(buf, n);
    left -= n;
  }
  src.close();
  dst.close();
  LittleFS.remove(LOG_PATH);
  LittleFS.rename("/log.tmp", LOG_PATH);
}

// Rebuild chain position from the last valid line; cut a half-written last line (power loss).
void restoreChain() {
  chain.box = BOX_ID;
  chain.signer = &signer;
  File f = LittleFS.open(LOG_PATH, "r");
  if (!f) return;
  String last;
  size_t goodEnd = 0;
  while (f.available()) {
    String l = f.readStringUntil('\n');
    size_t pos = f.position();
    l.trim();
    if (validLine(l)) {
      last = l;
      goodEnd = pos;
    }
  }
  size_t total = f.size();
  f.close();
  if (goodEnd < total) truncateLog(goodEnd);
  if (last.length()) {
    chain.seq = (uint32_t)extractNum(last, "\"s\":");
    chain.lastHash = extractStr(last, "\"h\":\"").c_str();
  }
  if (syncedOffset > goodEnd) syncedOffset = 0;
}

bool logRecord(char kind, const String& data) {
  // keep some space free so important events can still be stored
  if (kind == 'R' && (LittleFS.totalBytes() - LittleFS.usedBytes()) < 40000) return false;
  mt::Rec r = chain.build(kind, data.c_str(), nowEpoch());
  if (!r.ok) {
    Serial.println("ERROR: signing failed");
    return false;
  }
  File f = LittleFS.open(LOG_PATH, FILE_APPEND);
  if (!f) return false;
  size_t n = f.print(r.line.c_str());
  n += f.print('\n');
  f.close();
  if (n != r.line.size() + 1) return false;  // chain is NOT advanced; fragment is repaired at next boot
  chain.commit(r);
  Serial.printf("#%u %c %s\n", (unsigned)r.seq, kind, data.c_str());
  return true;
}

// ---------- sensors ----------
void initMpu() {
  Wire.beginTransmission(MPU_ADDR);
  Wire.write(0x6B);  // wake up
  Wire.write(0);
  haveMpu = (Wire.endTransmission(true) == 0);
}

bool readAccel(float& ax, float& ay, float& az) {
  Wire.beginTransmission(MPU_ADDR);
  Wire.write(0x3B);
  if (Wire.endTransmission(false) != 0) return false;
  if (Wire.requestFrom((int)MPU_ADDR, 6, (int)true) != 6) return false;
  int16_t x = Wire.read() << 8;
  x |= Wire.read();
  int16_t y = Wire.read() << 8;
  y |= Wire.read();
  int16_t z = Wire.read() << 8;
  z |= Wire.read();
  ax = x / 16384.0f;
  ay = y / 16384.0f;
  az = z / 16384.0f;
  return true;
}

void takeReading() {
  ds.requestTemperatures();
  float t = ds.getTempCByIndex(0);
  if (t == DEVICE_DISCONNECTED_C || t < -100) {
    if (!sensorErr) {
      sensorErr = true;
      logRecord('E', "SENSOR_ERR;temp");
    }
    return;
  }
  sensorErr = false;
  lastTemp = t;
  if (t < minT) minT = t;
  if (t > maxT) maxT = t;
  bool out = (t < TEMP_MIN_C || t > TEMP_MAX_C);

  // Read humidity from DHT22
  float h = dht.readHumidity();
  if (isnan(h)) {
    h = -1.0f;  // sentinel: sensor not connected or read failed
  } else {
    lastHumidity = h;
  }

  char buf[64];
  snprintf(buf, sizeof(buf), "%.2f;%d;%d;%.2f", t, doorOpen ? 1 : 0, tilted ? 1 : 0, h);
  logRecord('R', buf);

  // Temperature excursion events
  if (out && !tempOut) {
    excursions++;
    snprintf(buf, sizeof(buf), "TEMP_OUT;%.2f", t);
    logRecord('E', buf);
    beep(600);
  } else if (!out && tempOut) {
    snprintf(buf, sizeof(buf), "TEMP_OK;%.2f", t);
    logRecord('E', buf);
  }
  tempOut = out;

  // Humidity excursion events
  if (h >= 0) {  // only check if sensor returned a valid value
    bool hOut = (h < HUMID_MIN_RH || h > HUMID_MAX_RH);
    if (hOut && !humidOut) {
      snprintf(buf, sizeof(buf), "HUMID_OUT;%.2f", h);
      logRecord('E', buf);
      beep(400);
    } else if (!hOut && humidOut) {
      snprintf(buf, sizeof(buf), "HUMID_OK;%.2f", h);
      logRecord('E', buf);
    }
    humidOut = hOut;
  }
}

void handleDoor() {
  static bool lastRaw = false;
  static uint32_t changed = 0;
  bool raw = (digitalRead(PIN_REED) == HIGH);  // magnet away from switch = lid open
  if (raw != lastRaw) {
    lastRaw = raw;
    changed = millis();
  }
  if (millis() - changed > 60 && raw != doorOpen) {
    doorOpen = raw;
    if (doorOpen) {
      doorEvents++;
      logRecord('E', "DOOR_OPEN;1");
      beep(300);
    } else {
      logRecord('E', "DOOR_CLOSE;0");
    }
  }
}

void handleMotion() {
  if (!haveMpu || millis() - lastMotion < 200) return;
  lastMotion = millis();
  float ax, ay, az;
  if (!readAccel(ax, ay, az)) return;
  float mag = sqrtf(ax * ax + ay * ay + az * az);
  if (fabsf(mag - prevMag) > SHAKE_DELTA_G && millis() - lastShake > 5000) {
    lastShake = millis();
    logRecord('E', "SHAKE;" + String(fabsf(mag - prevMag), 2));
    beep(200);
  }
  prevMag = mag;
  if (mag < 0.3f) return;  // free fall, angle is meaningless
  float c = az / mag;
  if (c > 1.0f) c = 1.0f;
  if (c < -1.0f) c = -1.0f;
  float angle = acosf(c) * 57.2958f;
  bool nowTilted = angle > TILT_DEG;
  if (nowTilted != tilted) {
    tilted = nowTilted;
    if (tilted) {
      logRecord('E', "TILT;" + String(angle, 0));
      beep(200);
    } else {
      logRecord('E', "TILT_OK;0");
    }
  }
}

// ---------- RFID handover ----------
String uidHex() {
  String s;
  for (byte i = 0; i < rfid.uid.size; i++) {
    if (rfid.uid.uidByte[i] < 16) s += "0";
    s += String(rfid.uid.uidByte[i], HEX);
  }
  s.toUpperCase();
  return s;
}

bool isAuthorized(const String& uid) {
  for (size_t i = 0; i < N_AUTHORIZED; i++)
    if (uid == AUTHORIZED_UIDS[i]) return true;
  return false;
}

void doHandover(const String& from, const String& to) {
  String mn = (minT > maxT) ? String("NA") : String(minT, 2);
  String mx = (minT > maxT) ? String("NA") : String(maxT, 2);
  String data = from + ";" + to + ";" + mn + ";" + mx + ";" + String(excursions) + ";" + String(doorEvents);
  if (logRecord('H', data)) {
    minT = 999;
    maxT = -999;
    excursions = 0;
    doorEvents = 0;
    showBanner("HANDOVER OK", from.substring(0, 8) + ">" + to.substring(0, 8), false, 4000);
    beep(150);
  } else {
    showBanner("HANDOVER FAILED", "try again", true, 3000);
    beep(1000);
  }
}

void onCardTap(const String& uid) {
  Serial.println("Card tapped: " + uid);
  if (!isAuthorized(uid)) {
    logRecord('E', "UNAUTH_CARD;" + uid);
    hstate = H_IDLE;
    showBanner("UNAUTHORIZED", uid, true, 4000);
    beep(1500);
    return;
  }
  if (hstate == H_IDLE) {
    senderUid = uid;
    hstate = H_WAIT_RECEIVER;
    hstateSince = millis();
    showBanner("SENDER OK", "tap receiver card", false, HANDOVER_WINDOW_MS);
    beep(80);
  } else {
    if (uid == senderUid) {
      showBanner("SAME CARD", "use receiver card", true, 2000);
      return;
    }
    doHandover(senderUid, uid);
    hstate = H_IDLE;
  }
}

void handleRfid() {
  static uint32_t lastTap = 0;
  if (hstate == H_WAIT_RECEIVER && millis() - hstateSince > HANDOVER_WINDOW_MS) {
    hstate = H_IDLE;
    showBanner("TIMED OUT", "start again", true, 2000);
  }
  if (!rfid.PICC_IsNewCardPresent() || !rfid.PICC_ReadCardSerial()) return;
  String uid = uidHex();
  rfid.PICC_HaltA();
  rfid.PCD_StopCrypto1();
  if (millis() - lastTap < 800) return;
  lastTap = millis();
  onCardTap(uid);
}

// ---------- WiFi + sync ----------
void wifiTick() {
  static uint32_t lastTry = 0;
  if (WiFi.status() == WL_CONNECTED) return;
  if (millis() - lastTry > 15000) {
    lastTry = millis();
    WiFi.disconnect();
    WiFi.begin(WIFI_SSID, WIFI_PASS);
  }
}

bool doSync() {
  File f = LittleFS.open(LOG_PATH, "r");
  if (!f) return false;
  if (syncedOffset > f.size()) syncedOffset = 0;
  f.seek(syncedOffset);
  String body = "{\"box\":\"" BOX_ID "\",\"records\":[";
  int count = 0;
  uint32_t endOff = syncedOffset;
  long lastSeq = 0;
  while (f.available() && count < SYNC_BATCH) {
    String l = f.readStringUntil('\n');
    endOff = f.position();
    l.trim();
    if (!validLine(l)) continue;
    long s = extractNum(l, "\"s\":");
    if (s <= (long)syncedSeq) continue;
    if (count) body += ',';
    body += l;
    count++;
    lastSeq = s;
  }
  f.close();
  if (count == 0) return true;
  body += "]}";

  WiFiClient client;
  HTTPClient http;
  http.setTimeout(6000);
  if (!http.begin(client, BACKEND_URL)) return false;
  http.addHeader("Content-Type", "application/json");
  int code = http.POST(body);
  String resp = http.getString();
  http.end();

  if (code == 200) {
    long acked = extractNum(resp, "\"acked_seq\":");
    long st = extractNum(resp, "\"server_time\":");
    if (acked >= 0) {
      syncedSeq = (uint32_t)acked;
      if (acked == lastSeq) syncedOffset = endOff;
      prefs.putUInt("synced", syncedSeq);
      prefs.putUInt("soff", syncedOffset);
    }
    if (st > 1700000000L && !clockLooksValid()) setClock((uint32_t)st);
    syncRejected = false;
    Serial.printf("synced up to #%u\n", (unsigned)syncedSeq);
    return true;
  }
  Serial.printf("sync failed: HTTP %d %s\n", code, resp.c_str());
  syncRejected = (code >= 400 && code < 500);
  return false;
}

void syncTick() {
  if (WiFi.status() != WL_CONNECTED || hstate != H_IDLE) return;
  if (chain.seq <= syncedSeq || millis() < nextSync) return;
  bool ok = doSync();
  nextSync = millis() + (ok ? (chain.seq > syncedSeq ? 1000 : SYNC_INTERVAL_MS) : 30000);
}

// ---------- display, LEDs, buzzer ----------
void drawOled() {
  if (!haveOled) return;
  oled.clearDisplay();
  oled.setTextSize(1);
  oled.setTextColor(SSD1306_WHITE);
  oled.setCursor(0, 0);
  oled.print("MEDTRACE ");
  oled.print(BOX_ID);

  oled.setCursor(0, 12);
  if (std::isnan(lastTemp)) oled.print("T --.-C");
  else oled.printf("T %.1fC", lastTemp);
  if (std::isnan(lastHumidity)) oled.print(" H --%");
  else oled.printf(" H %.0f%%", lastHumidity);

  oled.setCursor(0, 24);
  oled.printf("Log #%u  Pending %u", (unsigned)chain.seq, (unsigned)(chain.seq - syncedSeq));

  oled.setCursor(0, 36);
  if (syncRejected) oled.print("SYNC REJECTED!");
  else oled.print(WiFi.status() == WL_CONNECTED ? "WiFi online" : "OFFLINE (logging)");

  oled.setCursor(0, 48);
  if (tempOut) oled.print("ALERT: TEMP OUT");
  else if (humidOut) oled.print("ALERT: HUMID OUT");
  else if (tilted) oled.print("ALERT: TILTED");
  else oled.print("Status: OK");

  if (millis() < bannerUntil) {
    oled.fillRect(0, 22, 128, 30, SSD1306_BLACK);
    oled.drawRect(0, 22, 128, 30, SSD1306_WHITE);
    oled.setCursor(4, 27);
    oled.print(banner1);
    oled.setCursor(4, 39);
    oled.print(banner2);
  }
  oled.display();
}

void updateLeds() {
  bool alert = tempOut || humidOut || doorOpen || tilted || (millis() < bannerUntil && bannerBad);
  digitalWrite(PIN_LED_RED, alert ? HIGH : LOW);
  digitalWrite(PIN_LED_GREEN, alert ? LOW : HIGH);
  if (buzzUntil && millis() > buzzUntil) {
    digitalWrite(PIN_BUZZER, LOW);
    buzzUntil = 0;
  }
}

// ---------- serial commands ----------
void printIdentity() {
  Serial.println("\n===== MEDTRACE BOX IDENTITY =====");
  Serial.println(String("Box ID: ") + BOX_ID);
  Serial.println("Public key (copy the block below into pubkey.pem and register it on the backend):");
  Serial.println(signer.publicPem().c_str());
  Serial.println("=================================");
}

void handleSerial() {
  if (!Serial.available()) return;
  String cmd = Serial.readStringUntil('\n');
  cmd.trim();
  cmd.toUpperCase();
  if (cmd == "PUB") {
    printIdentity();
  } else if (cmd == "STATUS") {
    Serial.printf("seq=%u synced=%u wifi=%d clock_ok=%d rtc=%d mpu=%d\n", (unsigned)chain.seq,
                  (unsigned)syncedSeq, WiFi.status() == WL_CONNECTED, clockLooksValid(), haveRtc, haveMpu);
  } else if (cmd == "CLOCK") {
    ntpClock(true);
    Serial.printf("clock now %u\n", (unsigned)nowEpoch());
  } else if (cmd == "ERASE YES") {
    LittleFS.remove(LOG_PATH);
    prefs.putUInt("synced", 0);
    prefs.putUInt("soff", 0);
    Serial.println("Log erased. Also reset the backend (delete medtrace.db, restart chain, redeploy) or use a new BOX_ID.");
    delay(500);
    ESP.restart();
  }
}

// ---------- setup / loop ----------
void setup() {
  Serial.begin(115200);
  delay(300);
  pinMode(PIN_REED, INPUT_PULLUP);
  pinMode(PIN_BUZZER, OUTPUT);
  pinMode(PIN_LED_GREEN, OUTPUT);
  pinMode(PIN_LED_RED, OUTPUT);
  digitalWrite(PIN_BUZZER, LOW);

  Wire.begin(PIN_SDA, PIN_SCL);
  haveOled = oled.begin(SSD1306_SWITCHCAPVCC, 0x3C);
  if (haveOled) {
    oled.clearDisplay();
    oled.setTextSize(1);
    oled.setTextColor(SSD1306_WHITE);
    oled.setCursor(0, 0);
    oled.println("MedTrace starting...");
    oled.display();
  }

  if (!LittleFS.begin(true)) {
    Serial.println("ERROR: LittleFS failed");
    while (true) delay(1000);
  }
  haveRtc = rtc.begin();
  SPI.begin(PIN_RFID_SCK, PIN_RFID_MISO, PIN_RFID_MOSI, PIN_RFID_SS);
  rfid.PCD_Init();
  ds.begin();
  ds.setResolution(10);
  dht.begin();
  initMpu();

  prefs.begin("mt", false);
  String pem = prefs.getString("priv", "");
  if (!signer.begin(pem.c_str())) {
    Serial.println("ERROR: key init failed");
    while (true) delay(1000);
  }
  if (pem.length() == 0) prefs.putString("priv", signer.privatePem().c_str());
  syncedSeq = prefs.getUInt("synced", 0);
  syncedOffset = prefs.getUInt("soff", 0);
  restoreChain();

  WiFi.mode(WIFI_STA);
  WiFi.begin(WIFI_SSID, WIFI_PASS);
  uint32_t t0 = millis();
  while (WiFi.status() != WL_CONNECTED && millis() - t0 < 10000) delay(250);
  ntpClock(false);
  if (!clockLooksValid())
    Serial.println("WARNING: clock not set. Power the box once with WiFi so it can set its clock.");

  Serial.printf("RTC:%d MPU:%d OLED:%d\n", haveRtc, haveMpu, haveOled);
  printIdentity();
  logRecord('E', "BOOT;0");
}

void loop() {
  handleRfid();
  handleDoor();
  handleMotion();
  if (millis() - lastRead >= READ_INTERVAL_MS) {
    lastRead = millis();
    takeReading();
  }
  wifiTick();
  syncTick();
  updateLeds();
  if (millis() - lastDraw >= 500) {
    lastDraw = millis();
    drawOled();
  }
  handleSerial();
}
