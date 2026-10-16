package io.github.rezabakhshi.embedra.targets.nordic.softdevice;

/**
 * Enumeration of Nordic Semiconductor SoftDevice wireless protocol stacks.
 */
public enum NordicSoftDeviceType {
    S110("S110", "BLE Peripheral stack for nRF51"),
    S112("S112", "Memory-optimized BLE Peripheral stack for nRF52"),
    S120("S120", "BLE Central stack for nRF51"),
    S130("S130", "BLE Central + Peripheral stack for nRF51"),
    S132("S132", "BLE Central + Peripheral stack for nRF52832"),
    S140("S140", "BLE Central + Peripheral + Long Range + Coded PHY stack for nRF52840/nRF52833"),
    UNKNOWN("UNKNOWN", "Unrecognized SoftDevice stack");

    private final String name;

    private final String description;

    NordicSoftDeviceType(String name, String description) {
        this.name = name;
        this.description = description;
    }

    public String stackName() {
        return name;
    }

    public String description() {
        return description;
    }
}
