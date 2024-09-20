#include "nfc_supported_card_plugin.h"
#include <flipper_application.h>

#include <nfc/protocols/mf_classic/mf_classic_poller_sync.h>

#include <bit_lib.h>

#define TAG "Mobilis"

#define KEY_LENGTH       6
#define UID_LENGTH       4

typedef struct {
    uint64_t a;
    uint64_t b;
} MfClassicKeyPair;

static MfClassicKeyPair mobilis_1k_keys[] = {
    {.a = 0xA8844B0BCA06, .b = 0x86CCAAE576A2}, // 000
    {.a = 0xCB5ED0E57B08, .b = 0x68C867397AD5}, // 001
    {.a = 0x749934CC8ED3, .b = 0x4427385D72AB}, // 002
    {.a = 0xAE381EA0811B, .b = 0x9B2C3E00B561}, // 003
    {.a = 0x40454EE64229, .b = 0x120A7837BB5D}, // 004
    {.a = 0x66A4932816D3, .b = 0xB19A0664ECA6}, // 005
    {.a = 0xB54D99618ADC, .b = 0xB456E1951216}, // 006
    {.a = 0x08D6A7765640, .b = 0xE87E3554727E}, // 007
    {.a = 0x3E0557273982, .b = 0x8D96A0BA7234}, // 008
    {.a = 0x944B47EC55C8, .b = 0xF347273136FB}, // 009
    {.a = 0xC0C1C2C3C4C5, .b = 0xB0B1B2B3B4B5}, // 010
    {.a = 0xC0C1C2C3C4C5, .b = 0xB0B1B2B3B4B5}, // 011
    {.a = 0xC0C1C2C3C4C5, .b = 0xB0B1B2B3B4B5}, // 012
    {.a = 0xC0C1C2C3C4C5, .b = 0xB0B1B2B3B4B5}, // 013
    {.a = 0xC0C1C2C3C4C5, .b = 0xB0B1B2B3B4B5}, // 014
    {.a = 0xC0C1C2C3C4C5, .b = 0xB0B1B2B3B4B5}, // 015
};

static bool mobilis_verify(Nfc* nfc) {
    bool verified = false;

    do {
        const uint8_t block_num = mf_classic_get_first_block_num_of_sector(0);
        FURI_LOG_D(TAG, "Verifying sector %d", 0);

        MfClassicKey key = {0};
        bit_lib_num_to_bytes_be(mobilis_1k_keys[0].b, COUNT_OF(key.data), key.data);

        MfClassicAuthContext auth_context;
        MfClassicError error =
            mf_classic_poller_sync_auth(nfc, block_num, &key, MfClassicKeyTypeB, &auth_context);
        if(error != MfClassicErrorNone) {
            FURI_LOG_D(
                TAG, "Failed to read block %u: %d", block_num, error);
            break;
        }
        verified = true;
    } while(false);

    return verified;
}

static bool mobilis_read(Nfc* nfc, NfcDevice* device) {
    furi_assert(nfc);
    furi_assert(device);

    bool is_read = false;

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
            bit_lib_num_to_bytes_be(mobilis_1k_keys[i].a, sizeof(MfClassicKey), keys.key_a[i].data);
            FURI_BIT_SET(keys.key_a_mask, i);
            bit_lib_num_to_bytes_be(mobilis_1k_keys[i].b, sizeof(MfClassicKey), keys.key_b[i].data);
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

static bool mobilis_parse(const NfcDevice* device, FuriString* parsed_data) {
    furi_assert(device);
    furi_assert(parsed_data);

    const MfClassicData* data = nfc_device_get_data(device, NfcProtocolMfClassic);

    bool parsed = false;

    do {
        // Verify key
        MfClassicSectorTrailer* sec_tr =
            mf_classic_get_sector_trailer_by_sector(data, 0);
        uint64_t key = bit_lib_bytes_to_num_be(sec_tr->key_b.data, 6);
        if(key != mobilis_1k_keys[0].b) return false;

        //Get UID
        // little-endian from UID + block 0 byte 5
        const uint8_t* uid_data = &data->block[0].data[0];
        uint64_t uid = (bit_lib_bytes_to_num_le(uid_data, 4) * 100) + (uid_data[4] % 100) ;
        
        const int UID_BLOCK = 10000;
        //parse data
        furi_string_cat_printf(parsed_data, "\e#Mobilis\n");
        furi_string_cat_printf(parsed_data, "%04llu %04llu %04llu\n",
            (uid / (UID_BLOCK*UID_BLOCK)) % UID_BLOCK,
            (uid / UID_BLOCK) % UID_BLOCK,
            uid % UID_BLOCK
        );

        parsed = true;
    } while(false);

    return parsed;
}

/* Actual implementation of app<>plugin interface */
static const NfcSupportedCardsPlugin mobilis_plugin = {
    .protocol = NfcProtocolMfClassic,
    .verify = mobilis_verify,
    .read = mobilis_read,
    .parse = mobilis_parse,
};

/* Plugin descriptor to comply with basic plugin specification */
static const FlipperAppPluginDescriptor mobilis_plugin_descriptor = {
    .appid = NFC_SUPPORTED_CARD_PLUGIN_APP_ID,
    .ep_api_version = NFC_SUPPORTED_CARD_PLUGIN_API_VERSION,
    .entry_point = &mobilis_plugin,
};

/* Plugin entry point - must return a pointer to const descriptor  */
const FlipperAppPluginDescriptor* mobilis_plugin_ep(void) {
    return &mobilis_plugin_descriptor;
}
