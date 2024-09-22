#include "nfc_supported_card_plugin.h"
#include <flipper_application.h>

#include <nfc/protocols/mf_classic/mf_classic_poller_sync.h>

#include <bit_lib.h>

#define TAG "Renfe & Tu"

#define UID_LENGTH    4

static const uint64_t renfe_key = 0x749934CC8ED3;
static const uint64_t empty_key = 0xC0C1C2C3C4C5;
static const uint8_t renfe_sector = 2;
static const uint8_t empty_sector = 9;
static const uint8_t renfe_trip_sector = 4;

bool verify_sector_number(Nfc* nfc, int sector, uint64_t valid_key) {
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
        if(!verify_sector_number(nfc, renfe_sector, renfe_key)) {
            FURI_LOG_D(TAG, "Failed to read sector %u", renfe_sector);
            break;
        }

        // If can read this block with default empty key,
        // this card may be Mobilis Valencia
        if(verify_sector_number(nfc, empty_sector, empty_key)) {
            FURI_LOG_D(TAG, "Did not expect to read sector %u, skipping", renfe_sector);
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

void datetime_printf(FuriString* parsed_data, uint64_t date_block) {
    if(date_block > 0) {
        uint8_t dt_minute = date_block >> (32 - 6);
        uint8_t dt_hour = date_block >> (32 - 6 - 5) & 0x1F;
        uint8_t dt_day = date_block >> (32 - 6 - 5 - 5) & 0x1F;
        uint8_t dt_month = date_block >> (32 - 6 - 5 - 5 - 4) & 0xF;
        uint8_t dt_year = date_block >> (32 - 6 - 5 - 5 - 4 - 6) & 0x3F;

        furi_string_cat_printf(parsed_data, "%d-%d-20%d %d:%02d", dt_day, dt_month, dt_year, dt_hour, dt_minute);
    }
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

        // TODO assert Block 13 == Block 14
        // TODO assert Block 28 == Block 29

        // should be 13
        const uint8_t* trip = &data->block[renfe_trip_sector*4-3].data[4];
        uint64_t date_trip = bit_lib_bytes_to_num_le(&data->block[renfe_trip_sector*4-3].data[7], 4);

        uint64_t city = bit_lib_bytes_to_num_be(trip, 2) >> 4;
        bool starts_trip = bit_lib_get_bit(trip, 12); // TODO CHECK? 12-13 are C107 when leaving, 0004 when entering

        furi_string_printf(parsed_data, "\e#Renfe & Tu\n");

        uint8_t uid[UID_LENGTH];
        memcpy(uid, data->iso14443_3a_data->uid, UID_LENGTH);

        for(size_t i = 0; i < UID_LENGTH; i++) {
            furi_string_cat_printf(parsed_data, "%02X", uid[i]);
        }

        if (city == 0 && date_trip == 0) {
            furi_string_cat_printf(parsed_data, "\nSin usar\n");
        } else {
            furi_string_cat_printf(parsed_data, "\nCiudad %llu, ", city);
            if(starts_trip){
                furi_string_cat_printf(parsed_data, "entra\n");
            }else{ furi_string_cat_printf(parsed_data, "sale\n"); }
        }

        if (date_trip > 0) {
            datetime_printf(parsed_data, date_trip);
            furi_string_cat_printf(parsed_data, "\n");
        }

        uint64_t date_purchase = bit_lib_bytes_to_num_le(&data->block[15*4-3].data[10], 4);

        if (date_purchase > 0) {
            datetime_printf(parsed_data, date_purchase);
            furi_string_cat_printf(parsed_data, " recarga\n");
        }

        uint64_t date_previous_purchase = bit_lib_bytes_to_num_le(&data->block[16*4-3].data[10], 4);

        if (date_previous_purchase > 0) {
            datetime_printf(parsed_data, date_previous_purchase);
            furi_string_cat_printf(parsed_data, " anterior");
        }

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
