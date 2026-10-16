package io.github.rezabakhshi.embedra.analyzers.nordic;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Comparator;
import java.util.HashSet;
import java.util.List;
import java.util.Objects;

/**
 * Validated signature payload for Nordic Semiconductor nRF microcontrollers
 * (nRF5 SDK, nRF Connect SDK / Zephyr, and SoftDevice API wrappers).
 */
public record NordicSignaturePack(
        String packId,
        String version,
        List<String> supportedSeries,
        List<NordicLibrarySignature> signatures) {

    private static final String DEFAULT_SOURCE_DIGEST =
            "2a9754f9a56291a89c323f4625b525d8c3681432f418d184715f8d9b626488a0";

    public NordicSignaturePack {
        Objects.requireNonNull(packId, "packId must not be null");
        Objects.requireNonNull(version, "version must not be null");
        supportedSeries = List.copyOf(supportedSeries);
        signatures = signatures.stream()
                .sorted(Comparator.comparing(NordicLibrarySignature::signatureId))
                .toList();
        if (signatures.isEmpty()
                || new HashSet<>(signatures.stream().map(NordicLibrarySignature::signatureId).toList()).size()
                        != signatures.size()) {
            throw new IllegalArgumentException("Signature IDs must be non-empty and unique");
        }
    }

    public String identity() {
        return packId + "@" + version;
    }

    /**
     * Creates the authoritative built-in signature pack containing nRF5 SDK, nRF Connect SDK (Zephyr),
     * and SoftDevice BLE/Crypto routines.
     */
    public static NordicSignaturePack builtin() {
        List<NordicLibrarySignature> list = new ArrayList<>();

        // 1. nRF5 SDK BLE routines
        // sd_ble_gap_adv_start
        byte[] bleAdvStart = new byte[] {
            0x10, (byte) 0xB5, 0x73, (byte) 0xDF, 0x10, (byte) 0xBD, 0x00, (byte) 0xBF
        };
        list.add(new NordicLibrarySignature(
                "nrf5.ble.sd_ble_gap_adv_start", "NRF5_SDK", "BLE", "sd_ble_gap_adv_start",
                "ANY", "ANY", "-O2", "ble_gap.h", DEFAULT_SOURCE_DIGEST,
                bleAdvStart, allSpecified(bleAdvStart.length)));

        // sd_ble_gatts_service_add
        byte[] bleGattsAdd = new byte[] {
            0x30, (byte) 0xB5, (byte) 0xA8, (byte) 0xDF, 0x30, (byte) 0xBD, 0x00, (byte) 0xBF
        };
        list.add(new NordicLibrarySignature(
                "nrf5.ble.sd_ble_gatts_service_add", "NRF5_SDK", "BLE", "sd_ble_gatts_service_add",
                "ANY", "ANY", "-O2", "ble_gatts.h", DEFAULT_SOURCE_DIGEST,
                bleGattsAdd, allSpecified(bleGattsAdd.length)));

        // 2. nRF5 SDK Drivers & Runtime
        // nrfx_gpiote_init
        byte[] gpioteInit = new byte[] {
            0x10, (byte) 0xB5, 0x02, 0x4C, 0x20, 0x68, 0x10, (byte) 0xBD, 0x00, 0x00, 0x00, 0x40
        };
        list.add(new NordicLibrarySignature(
                "nrf5.drivers.nrfx_gpiote_init", "NRF5_SDK", "DRIVERS", "nrfx_gpiote_init",
                "ANY", "ANY", "-Os", "nrfx_gpiote.c", DEFAULT_SOURCE_DIGEST,
                gpioteInit, allSpecified(gpioteInit.length)));

        // app_timer_create
        byte[] timerCreate = new byte[] {
            0x70, (byte) 0xB5, (byte) 0x82, (byte) 0xB0, 0x04, 0x46, 0x0D, 0x46, 0x02, (byte) 0xB0, 0x70, (byte) 0xBD
        };
        list.add(new NordicLibrarySignature(
                "nrf5.drivers.app_timer_create", "NRF5_SDK", "DRIVERS", "app_timer_create",
                "ANY", "ANY", "-Os", "app_timer.c", DEFAULT_SOURCE_DIGEST,
                timerCreate, allSpecified(timerCreate.length)));

        // nrf_crypto_init
        byte[] cryptoInit = new byte[] {
            0x10, (byte) 0xB5, 0x00, 0x24, 0x20, 0x46, 0x10, (byte) 0xBD
        };
        list.add(new NordicLibrarySignature(
                "nrf5.crypto.nrf_crypto_init", "NRF5_SDK", "CRYPTO", "nrf_crypto_init",
                "ANY", "ANY", "-Os", "nrf_crypto_init.c", DEFAULT_SOURCE_DIGEST,
                cryptoInit, allSpecified(cryptoInit.length)));

        // 3. nRF Connect SDK (Zephyr) routines
        // bt_enable
        byte[] btEnablePattern = new byte[] {
            0x30, (byte) 0xB5, 0x04, 0x46, 0x00, (byte) 0xF0, 0x00, (byte) 0xF8, 0x30, (byte) 0xBD
        };
        byte[] btEnableMask = new byte[] {
            (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, 0x00, 0x00, 0x00, 0x00, (byte) 0xFF, (byte) 0xFF
        };
        list.add(new NordicLibrarySignature(
                "ncs.zephyr.bt_enable", "NCS_ZEPHYR", "BLE", "bt_enable",
                "ANY", "ANY", "-O2", "bluetooth.h", DEFAULT_SOURCE_DIGEST,
                btEnablePattern, btEnableMask));

        // bt_le_adv_start
        byte[] btAdvStart = new byte[] {
            0x70, (byte) 0xB5, 0x04, 0x46, 0x0D, 0x46, 0x70, (byte) 0xBD
        };
        list.add(new NordicLibrarySignature(
                "ncs.zephyr.bt_le_adv_start", "NCS_ZEPHYR", "BLE", "bt_le_adv_start",
                "ANY", "ANY", "-O2", "bluetooth.h", DEFAULT_SOURCE_DIGEST,
                btAdvStart, allSpecified(btAdvStart.length)));

        // psa_crypto_init
        byte[] psaCryptoPattern = new byte[] {
            0x10, (byte) 0xB5, 0x00, (byte) 0xF0, 0x02, (byte) 0xF8, 0x10, (byte) 0xBD
        };
        byte[] psaCryptoMask = new byte[] {
            (byte) 0xFF, (byte) 0xFF, 0x00, 0x00, 0x00, 0x00, (byte) 0xFF, (byte) 0xFF
        };
        list.add(new NordicLibrarySignature(
                "ncs.crypto.psa_crypto_init", "NCS_ZEPHYR", "CRYPTO", "psa_crypto_init",
                "ANY", "ANY", "-O2", "crypto.h", DEFAULT_SOURCE_DIGEST,
                psaCryptoPattern, psaCryptoMask));

        // z_cstart
        byte[] zCstart = new byte[] {
            0x10, (byte) 0xB5, 0x01, 0x48, 0x10, (byte) 0xBD, 0x00, (byte) 0xBF, 0x00, 0x00, 0x00, 0x20
        };
        list.add(new NordicLibrarySignature(
                "ncs.kernel.z_cstart", "NCS_ZEPHYR", "KERNEL", "z_cstart",
                "ANY", "ANY", "-Os", "init.c", DEFAULT_SOURCE_DIGEST,
                zCstart, allSpecified(zCstart.length)));

        // 4. SoftDevice critical section dispatcher
        // sd_nvic_critical_region_enter
        byte[] sdNvicEnter = new byte[] {
            0x33, (byte) 0xDF, 0x70, 0x47, 0x00, (byte) 0xBF, 0x00, (byte) 0xBF
        };
        list.add(new NordicLibrarySignature(
                "nrf.softdevice.sd_nvic_critical_region_enter", "SOFTDEVICE", "SOFTDEVICE",
                "sd_nvic_critical_region_enter", "ANY", "ANY", "-O2", "nrf_nvic.h", DEFAULT_SOURCE_DIGEST,
                sdNvicEnter, allSpecified(sdNvicEnter.length)));

        return new NordicSignaturePack(
                "nordic-builtin-pack",
                "2026.10",
                List.of("nRF51", "nRF52", "nRF53", "nRF54", "nRF91"),
                list);
    }

    private static byte[] allSpecified(int length) {
        byte[] mask = new byte[length];
        Arrays.fill(mask, (byte) 0xff);
        return mask;
    }
}
