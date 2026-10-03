package io.github.rezabakhshi.embedra.analyzers.ctf;

/**
 * Specific entity type for discovered firmware leads and CTF artifacts (AN-002).
 */
public enum CtfEntityType {
    URL("URL Endpoint"),
    IP_ADDRESS("IP Address"),
    DOMAIN("Domain / Hostname"),
    MQTT_TOPIC("MQTT Topic"),
    BLE_UUID("BLE UUID"),
    MAC_ADDRESS("MAC Address"),
    WIFI_CREDENTIAL("Wi-Fi Credential"),
    API_TOKEN("API Token"),
    JWT("JSON Web Token"),
    SSH_KEY("SSH Key"),
    PEM_CERTIFICATE("PEM Certificate"),
    PEM_KEY("PEM Key"),
    DER_CERTIFICATE("DER Certificate"),
    BASE64_BLOB("Base64 Encoded Blob"),
    HEX_BLOB("Hex Encoded Blob"),
    FLAG("CTF Flag");

    private final String displayName;

    CtfEntityType(String displayName) {
        this.displayName = displayName;
    }

    public String displayName() {
        return displayName;
    }
}
