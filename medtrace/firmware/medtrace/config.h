// config.h - edit the values in the "EDIT THESE" block, then upload.
#pragma once

// ===================== EDIT THESE =====================
#define BOX_ID       "BOX-001"                              // unique name of this box
#define WIFI_SSID    "YourHotspot"                          // phone hotspot or WiFi name
#define WIFI_PASS    "YourPassword"
#define BACKEND_URL  "http://192.168.1.10:8000/api/sync"    // IP of the laptop running the backend

// Authorized RFID card UIDs (uppercase hex, no spaces). Tap a card once: its UID is printed
// on the Serial Monitor ("Card tapped: ..."). Register the same UIDs on the backend.
static const char* const AUTHORIZED_UIDS[] = {"04A1B2C3", "04D4E5F6", "04112233"};
// ======================================================

#define N_AUTHORIZED (sizeof(AUTHORIZED_UIDS) / sizeof(AUTHORIZED_UIDS[0]))

// Temperature limits for the vaccine profile (deg C)
#define TEMP_MIN_C 2.0f
#define TEMP_MAX_C 8.0f

// Humidity limits (% RH) - WHO recommends 30-60% for most pharmaceuticals
#define HUMID_MIN_RH 30.0f
#define HUMID_MAX_RH 60.0f

// Timing
#define READ_INTERVAL_MS     10000   // one signed reading every 10 s
#define SYNC_INTERVAL_MS     15000   // try to upload every 15 s when WiFi is up
#define HANDOVER_WINDOW_MS   20000   // receiver must tap within 20 s of the sender
#define SYNC_BATCH           30      // max records per upload

// Motion (MPU6050 mounted flat inside the box, Z axis up)
#define MPU_ADDR        0x69         // 0x68 if the DS3231 clock is not used
#define SHAKE_DELTA_G   0.6f         // change in acceleration that counts as a shake
#define TILT_DEG        45.0f        // angle from upright that counts as tilted

// Pins (ESP32 DevKit)
#define PIN_RFID_SS    5
#define PIN_RFID_SCK   18
#define PIN_RFID_MISO  19
#define PIN_RFID_MOSI  23
#define PIN_RFID_RST   27
#define PIN_SDA        21
#define PIN_SCL        22
#define PIN_ONEWIRE    4
#define PIN_REED       14
#define PIN_BUZZER     25            // active buzzer: HIGH = sound
#define PIN_LED_GREEN  32
#define PIN_LED_RED    33
#define PIN_DHT22      26            // DHT22 data pin (humidity + temperature)

#define LOG_PATH "/log.jsonl"
