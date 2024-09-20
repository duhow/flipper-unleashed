#include "nfc_supported_card_plugin.h"
#include <flipper_application.h>

#include <nfc/protocols/mf_classic/mf_classic_poller_sync.h>

#include <bit_lib.h>

#define TAG "Renfe & Tu"

static const uint64_t renfe_key = 0x749934CC8ED3;
static const uint64_t empty_key = 0xC0C1C2C3C4C5;
static const uint8_t renfe_sector = 2;
static const uint8_t empty_sector = 9;

bool verify_block_number(Nfc* nfc, int sector, uint64_t valid_key) {
    uint8_t block_num = mf_classic_get_first_block_num_of_sector(sector);
    FURI_LOG_D(TAG, "Verifying sector %u", sector);

    MfClassicKey key = {};
    bit_lib_num_to_bytes_be(valid_key, COUNT_OF(key.data), key.data);

    MfClassicAuthContext auth_ctx = {};
    MfClassicError error =
        mf_classic_poller_sync_auth(nfc, block_num, &key, MfClassicKeyTypeA, &auth_ctx);
    
    return (error == MfClassicErrorNone);
}

bool renfe_verify(Nfc* nfc) {
    bool verified = false;
    FURI_LOG_I(TAG, "verify");

    do {
        if(!verify_block_number(nfc, renfe_sector, renfe_key)) {
            FURI_LOG_D(TAG, "Failed to read block %u", renfe_sector);
            break;
        }

        // If can read this block with default empty key,
        // this card may be Mobilis Valencia
        if(verify_block_number(nfc, empty_sector, empty_key)) {
            FURI_LOG_D(TAG, "Did not expect to read block %u, skipping", renfe_sector);
            break;
        }

        verified = true;
    } while(false);

    return verified;
}

static bool renfe_read(Nfc* nfc, NfcDevice* device) {
    furi_assert(nfc);
    furi_assert(device);

    bool is_read = false;
    FURI_LOG_I(TAG, "read");

    MfClassicData* data = mf_classic_alloc();
    nfc_device_copy_data(device, NfcProtocolMfClassic, data);

    do {
        MfClassicType type = MfClassicType1k;
        MfClassicError error = mf_classic_poller_sync_detect_type(nfc, &type);
        if(error != MfClassicErrorNone) break;

        data->type = type;
        if(type != MfClassicType1k) break;

        MfClassicDeviceKeys keys = {};
        for(size_t i = 0; i < mf_classic_get_total_sectors_num(data->type); i++) {
            bit_lib_num_to_bytes_be(renfe_key, sizeof(MfClassicKey), keys.key_a[i].data);
            FURI_BIT_SET(keys.key_a_mask, i);
            bit_lib_num_to_bytes_be(renfe_key, sizeof(MfClassicKey), keys.key_b[i].data);
            FURI_BIT_SET(keys.key_b_mask, i);
        }

        error = mf_classic_poller_sync_read(nfc, &keys, data);
        if(error == MfClassicErrorNotPresent) {
            FURI_LOG_W(TAG, "Failed to read data");
            break;
        }

        nfc_device_set_data(device, NfcProtocolMfClassic, data);

        is_read = (error == MfClassicErrorNone);
    } while(false);

    mf_classic_free(data);

    return is_read;
}

static bool renfe_parse(const NfcDevice* device, FuriString* parsed_data) {
    furi_assert(device);
    furi_assert(parsed_data);

    FURI_LOG_I(TAG, "parse");

    const MfClassicData* data = nfc_device_get_data(device, NfcProtocolMfClassic);

    bool parsed = false;

    do {
        // Verify key
        MfClassicSectorTrailer* sec_tr = mf_classic_get_sector_trailer_by_sector(data, renfe_sector);
        uint64_t key = bit_lib_bytes_to_num_be(sec_tr->key_a.data, 6);
        if(key != renfe_key) return false;

        // Discard if can read sector with default key
        for(uint8_t sector = 15; sector >= empty_sector; sector--) {
            MfClassicSectorTrailer* sec_tr2 = mf_classic_get_sector_trailer_by_sector(data, sector);
            uint64_t key2 = bit_lib_bytes_to_num_be(sec_tr2->key_a.data, 6);
            if(key2 == empty_key) return false;
        }

        // Verify card type
        if(data->type != MfClassicType1k) return false;

        /* uint32_t renfe_card_id = 0;

        for(size_t i = 7; i < 11; i++) {
            tmobilitat_card_id = (tmobilitat_card_id << 8) | hist_bytes[i];
        } */

        furi_string_printf(
            parsed_data, "\e#+Renfe & Tu\n");

        parsed = true;
    } while(false);

    return parsed;
}

/* Actual implementation of app<>plugin interface */
static const NfcSupportedCardsPlugin renfe_plugin = {
    .protocol = NfcProtocolMfClassic,
    .verify = renfe_verify,
    .read = renfe_read,
    .parse = renfe_parse,
};

/* Plugin descriptor to comply with basic plugin specification */
static const FlipperAppPluginDescriptor renfe_plugin_descriptor = {
    .appid = NFC_SUPPORTED_CARD_PLUGIN_APP_ID,
    .ep_api_version = NFC_SUPPORTED_CARD_PLUGIN_API_VERSION,
    .entry_point = &renfe_plugin,
};

/* Plugin entry point - must return a pointer to const descriptor  */
const FlipperAppPluginDescriptor* renfe_plugin_ep(void) {
    return &renfe_plugin_descriptor;
}
