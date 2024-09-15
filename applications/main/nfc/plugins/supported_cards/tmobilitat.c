#include "nfc_supported_card_plugin.h"
#include <flipper_application.h>

#include <nfc/protocols/iso14443_4a/iso14443_4a.h>
#include <nfc/protocols/mf_desfire/mf_desfire.h>

#include <bit_lib.h>

#define TAG "T-Mobilitat"

static const MfDesfireApplicationId tmobilitat_id = {.data = {0x05, 0x00, 0x00}};
static const uint8_t tmobilitat_atr[4] = {0x2A, 0x26, 0xA7, 0xA1};

static void tmobilitat_text_output(FuriString* parsed_data, const uint8_t* hist_bytes) {
    furi_string_printf(parsed_data, "\e#T-Mobilitat\n");

    switch (hist_bytes[4]){
        case 0x04:
            furi_string_cat_printf(parsed_data, "Personal DESFire EV2\n");
            break;
        case 0x0c:
            furi_string_cat_printf(parsed_data, "Personal CIPURSE\n");
            break;
        case 0x14:
            furi_string_cat_printf(parsed_data, "Anonima DESFire EV2\n");
            break;
        default:
            furi_string_cat_printf(parsed_data, "Desconocido\n");
            break;
    }

    uint32_t tmobilitat_card_id = 0;

    for(size_t i = 7; i < 11; i++) {
        tmobilitat_card_id = (tmobilitat_card_id << 8) | hist_bytes[i];
    }
    furi_string_cat_printf(parsed_data, "%ld", tmobilitat_card_id);
}

static bool tmobilitat_ev2_parse(const NfcDevice* device, FuriString* parsed_data) {
    furi_assert(device);
    furi_assert(parsed_data);

    bool parsed = false;

    do {
        const MfDesfireData* data = nfc_device_get_data(device, NfcProtocolMfDesfire);
        const Iso14443_4aData* data_iso14443 = nfc_device_get_data(device, NfcProtocolIso14443_4a);
        const MfDesfireApplication* app = mf_desfire_get_application(data, &tmobilitat_id);
        if(app == NULL) break;

        // ---
        uint32_t hist_bytes_count;
        const uint8_t* hist_bytes = iso14443_4a_get_historical_bytes(data_iso14443, &hist_bytes_count);

        if(hist_bytes_count != 11) break;

        for(size_t i = 0; i < 4; i++) {
            if(hist_bytes[i] != tmobilitat_atr[i]) break;
        }
        // ---

        tmobilitat_text_output(parsed_data, hist_bytes);

        parsed = true;
    } while(false);

    return parsed;
}

static bool tmobilitat_cipurse_parse(const NfcDevice* device, FuriString* parsed_data) {
    furi_assert(device);
    furi_assert(parsed_data);

    bool parsed = false;

    do {
        const Iso14443_4aData* data = nfc_device_get_data(device, NfcProtocolIso14443_4a);
        // const MfDesfireApplication* app = mf_desfire_get_application(data_des2, &tmobilitat_id);
        // if(app == NULL) FURI_LOG_W(TAG, "application not found!");

        // ---
        uint32_t hist_bytes_count;
        const uint8_t* hist_bytes = iso14443_4a_get_historical_bytes(data, &hist_bytes_count);

        if(hist_bytes_count != 11) break;

        for(size_t i = 0; i < 4; i++) {
            if(hist_bytes[i] != tmobilitat_atr[i]) break;
        }
        // ---

        tmobilitat_text_output(parsed_data, hist_bytes);

        parsed = true;
    } while(false);

    return parsed;
}

static const NfcSupportedCardsPlugin tmobilitat_ev2_plugin = {
    .protocol = NfcProtocolMfDesfire,
    .verify = NULL,
    .read = NULL,
    .parse = tmobilitat_ev2_parse,
};

static const NfcSupportedCardsPlugin tmobilitat_cipurse_plugin = {
    .protocol = NfcProtocolIso14443_4a,
    .verify = NULL,
    .read = NULL,
    .parse = tmobilitat_cipurse_parse,
};

static const FlipperAppPluginDescriptor tmobilitat_ev2_plugin_descriptor = {
    .appid = NFC_SUPPORTED_CARD_PLUGIN_APP_ID,
    .ep_api_version = NFC_SUPPORTED_CARD_PLUGIN_API_VERSION,
    .entry_point = &tmobilitat_ev2_plugin,
};

static const FlipperAppPluginDescriptor tmobilitat_cipurse_plugin_descriptor = {
    .appid = NFC_SUPPORTED_CARD_PLUGIN_APP_ID,
    .ep_api_version = NFC_SUPPORTED_CARD_PLUGIN_API_VERSION,
    .entry_point = &tmobilitat_cipurse_plugin,
};

const FlipperAppPluginDescriptor* tmobilitat_ev2_plugin_ep(void) {
    return &tmobilitat_ev2_plugin_descriptor;
}

const FlipperAppPluginDescriptor* tmobilitat_cipurse_plugin_ep(void) {
    return &tmobilitat_cipurse_plugin_descriptor;
}