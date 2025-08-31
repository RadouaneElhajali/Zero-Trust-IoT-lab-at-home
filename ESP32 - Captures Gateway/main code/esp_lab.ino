#include <WiFi.h>
#include <WiFiClientSecure.h>
#include <PubSubClient.h>
#include <LittleFS.h>
#include <time.h>

// Wi-Fi network credentials (set your SSID and password)
const char* WIFI_SSID     = "IOT_VLAN_SSID";
const char* WIFI_PASSWORD = "00001111";

// ThingsBoard MQTT server details
const char* THINGSBOARD_HOST = "mqtt.eu.thingsboard.cloud";  // adjust for region if needed, e.g. "mqtt.eu.thingsboard.cloud"
const uint16_t THINGSBOARD_PORT = 8883;

// File paths in LittleFS
const char* CA_CERT_PATH     = "/aaa.pem";
const char* CLIENT_CERT_PATH = "/cert.pem";
const char* PRIVATE_KEY_PATH = "/key.pem";

// Global variables for TLS certificate contents
String caCert;
String clientCert;
String privateKey;

// WiFi and MQTT clients
WiFiClientSecure secureClient;
PubSubClient mqttClient(secureClient);

// Function to read a text file from LittleFS into a String
bool readFileToString(fs::FS &fs, const char* path, String &dest) {
  File file = fs.open(path, "r");
  if (!file) {
    Serial.printf("Failed to open file: %s\n", path);
    return false;
  }
  dest.clear();
  // Reserve capacity to avoid fragmentation (optional)
  dest.reserve(file.size());
  while (file.available()) {
    // Read file character by character to preserve all contents (including newlines)
    dest += char(file.read());
  }
  file.close();
  // Debug: print file size loaded
  Serial.printf("Loaded %s (%d bytes)\n", path, dest.length());
  return true;
}

// Ensure time is initialized (required for TLS)
void syncTime() {
  configTime(0, 0, "pool.ntp.org", "time.nist.gov");  // UTC timezone
  Serial.print("Synchronizing time via NTP");
  struct tm timeinfo;
  const uint8_t MAX_RETRIES = 30;
  uint8_t attempt = 0;
  // Wait for time to be set or until MAX_RETRIES reached
  while (attempt < MAX_RETRIES) {
    if (getLocalTime(&timeinfo)) {
      Serial.println(" - Time synchronized!");
      Serial.printf("Current time: %04d-%02d-%02d %02d:%02d:%02d UTC\n",
                    timeinfo.tm_year + 1900, timeinfo.tm_mon + 1, timeinfo.tm_mday,
                    timeinfo.tm_hour, timeinfo.tm_min, timeinfo.tm_sec);
      return;
    }
    Serial.print(".");
    delay(500);
    attempt++;
  }
  Serial.println(" - Failed to synchronize time!");
}

// Attempt to (re)connect to ThingsBoard MQTT
void reconnectMQTT() {
  // Generate a unique client ID based on MAC address
  String clientId = "ESP32-";
  clientId += WiFi.macAddress();
  clientId.replace(":", "");  // remove colons from MAC

  while (!mqttClient.connected()) {
    Serial.print("Connecting to ThingsBoard MQTT...");
    // Note: using client certificate authentication, no username/password required
    if (mqttClient.connect(clientId.c_str())) {
      Serial.println(" connected.");
      // You can subscribe to topics or publish a message here if needed
    } else {
      Serial.printf(" failed, rc=%d. Retrying in 5 seconds...\n", mqttClient.state());
      delay(5000);
    }
  }
}

void setup() {
  Serial.begin(115200);
  delay(100);  // small delay to let Serial init

  Serial.println();
  Serial.println("=== Device booting... ===");

  // Initialize LittleFS
  Serial.println("Mounting LittleFS...");
  if (!LittleFS.begin()) {
    Serial.println("ERROR: LittleFS Mount failed! Halting.");
    while (true) { delay(100); }
  }
  Serial.println("LittleFS mounted successfully.");

  // Load TLS certificates/keys from LittleFS
  Serial.println("Reading TLS credentials from LittleFS...");
  bool ok = true;
  ok &= readFileToString(LittleFS, CA_CERT_PATH, caCert);
  ok &= readFileToString(LittleFS, CLIENT_CERT_PATH, clientCert);
  ok &= readFileToString(LittleFS, PRIVATE_KEY_PATH, privateKey);
  if (!ok) {
    Serial.println("ERROR: Failed to load one or more PEM files. Check LittleFS contents.");
    while (true) { delay(100); }
  }

  // Connect to Wi-Fi
  Serial.printf("Connecting to WiFi SSID: %s\n", WIFI_SSID);
  WiFi.begin(WIFI_SSID, WIFI_PASSWORD);
  // Wait for connection
  uint8_t attempt = 0;
  while (WiFi.status() != WL_CONNECTED) {
    delay(500);
    Serial.print(".");
    if (++attempt % 40 == 0) {  // print a newline every 40 * 0.5s = 20s
      Serial.println();
    }
  }
  Serial.println("\nWiFi connected.");
  Serial.print("IP address: ");
  Serial.println(WiFi.localIP());

  // Sync time for TLS
  syncTime();

  // Configure the secure client with certificates
  Serial.println("Configuring TLS credentials...");
  secureClient.setCACert(caCert.c_str());
  secureClient.setCertificate(clientCert.c_str());
  secureClient.setPrivateKey(privateKey.c_str());

  // Optionally, disable certificate verification for testing (NOT recommended in production)
  // secureClient.setInsecure();  // **Do not use in production, for debug only**

  // Configure MQTT server and port
  mqttClient.setServer(THINGSBOARD_HOST, THINGSBOARD_PORT);
  // Optionally, set callback for incoming messages (not used in this example)
  // mqttClient.setCallback(mqttCallback);

  // Attempt initial MQTT connection
  reconnectMQTT();
}

void loop() {
  if (!mqttClient.connected()) {
    reconnectMQTT();
  }
  mqttClient.loop();

  static unsigned long lastSend = 0;
  if (millis() - lastSend > 10000) {
    lastSend = millis();
    const char* payload = "{\"temperature\":99}";
    mqttClient.publish("v1/devices/me/telemetry", payload);
    Serial.println("↗ Published telemetry to ThingsBoard");
  }
}
