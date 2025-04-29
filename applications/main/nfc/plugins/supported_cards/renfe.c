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

const char* city_name(uint64_t city) {
    switch (city){
        case 72400: return "Aeroport";
        case 78505: return "Aguilar de Segarra";
        case 73101: return "Alcover";
        case 71502: return "Altafulla-Tamarit";
        case 78407: return "Anglesola";
        case 79600: return "Arenys de Mar";
        case 71211: return "Ascó";
        case 79404: return "Badalona";
        case 77106: return "Balenyà-Els Hostalets";
        case 77107: return "Balenyà-Tona-Seva";
        case 78705: return "Barberà del Vallès";
        case 78804: return "Barcelona-Arc de Triomf";
        case 79009: return "Barcelona-El Clot";
        case 79400: return "Barcelona-Estació de França";
        case 78802: return "Barcelona-Fabra i Puig";
        case 78806: return "Barcelona-La Sagrera-Meridiana";
        case 71802: return "Barcelona-Passeig de Gràcia";
        case 78805: return "Barcelona-Plaça de Catalunya";
        case 79004: return "Barcelona-Sant Andreu";
        case 71801: return "Barcelona-Sants";
        case 78801: return "Barcelona-Torre Baró | Vallbona";
        case 78402: return "Bell-lloc d'Urgell";
        case 78406: return "Bellpuig";
        case 71708: return "Bellvitge | Gornal";
        case 79606: return "Blanes";
        case 79302: return "Bordils-Juià";
        case 77112: return "Borgonyà";
        case 79412: return "Cabrera de Mar-Vilassar de Mar";
        case 78503: return "Calaf";
        case 71601: return "Calafell";
        case 79502: return "Caldes d'Estrac";
        case 79203: return "Caldes de Malavella";
        case 79603: return "Calella";
        case 79305: return "Camallera";
        case 65403: return "Camarles-Deltebre";
        case 65422: return "Cambrils";
        case 65401: return "Camp-redó";
        case 77301: return "Campdevànol";
        case 79601: return "Canet de Mar";
        case 71302: return "Capçanes";
        case 79101: return "Cardedeu";
        case 78605: return "Castellbell i el Vilar-Monistrol de Mont";
        case 72210: return "Castellbisbal";
        case 71705: return "Castelldefels";
        case 78405: return "Castellnou de Seana";
        case 79301: return "Celrà";
        case 77105: return "Centelles";
        case 79316: return "Cerbère";
        case 78706: return "Cerdanyola del Vallès";
        case 72503: return "Cerdanyola-Universitat";
        case 78500: return "Cervera";
        case 79314: return "Colera";
        case 72303: return "Cornellà";
        case 71604: return "Cubelles";
        case 71603: return "Cunit";
        case 71305: return "Duesaigües-L'Argentera";
        case 79407: return "El Masnou";
        case 72211: return "El Papiol";
        case 71707: return "El Prat de Llobregat";
        case 72201: return "El Vendrell";
        case 71301: return "Els Guiamets";
        case 72203: return "Els Monjos";
        case 77103: return "Figaró";
        case 79309: return "Figueres";
        case 79303: return "Flaçà";
        case 71210: return "Flix";
        case 79205: return "Fornells de la Selva";
        case 71703: return "Garraf";
        case 71706: return "Gavà";
        case 72208: return "Gelida";
        case 79300: return "Girona";
        case 78404: return "Golmés";
        case 79100: return "Granollers Centre";
        case 77006: return "Granollers-Canovelles";
        case 79105: return "Gualba";
        case 79107: return "Hostalric";
        case 73002: return "Juneda";
        case 65402: return "L'Aldea-Amposta";
        case 65405: return "L'Ametlla de Mar";
        case 65404: return "L'Ampolla-Perelló-Deltebre";
        case 72202: return "L'Arboç";
        case 73007: return "L'Espluga de Francolí";
        case 72305: return "L'Hospitalet de Llobregat";
        case 65420: return "L'Hospitalet de l'Infant";
        case 77114: return "La Farga de Bebié";
        case 73004: return "La Floresta";
        case 77102: return "La Garriga";
        case 72205: return "La Granada";
        case 79011: return "La Llagosta";
        case 77306: return "La Molina";
        case 73100: return "La Plana-Picamoixons";
        case 73010: return "La Riba";
        case 73102: return "La Selva del Camp";
        case 77310: return "La Tor de Querol-Enveig";
        case 72206: return "Lavern-Subirats";
        case 73003: return "Les Borges Blanques";
        case 71307: return "Les Borges del Camp";
        case 77100: return "Les Franqueses del Vallès";
        case 79109: return "Les Franqueses-Granollers Nord";
        case 79312: return "Llançà";
        case 78400: return "Lleida-Pirineus";
        case 79102: return "Llinars del Vallès";
        case 79605: return "Malgrat de Mar";
        case 77110: return "Manlleu";
        case 78600: return "Manresa";
        case 72209: return "Martorell Central";
        case 71303: return "Marçà-Falset";
        case 79500: return "Mataró";
        case 79200: return "Maçanet-Massanes";
        case 72300: return "Molins de Rei";
        case 78403: return "Mollerussa";
        case 79006: return "Mollet-Sant Fost";
        case 77004: return "Mollet-Santa Rosa";
        case 73008: return "Montblanc";
        case 78800: return "Montcada Bifurcació";
        case 77002: return "Montcada Ripollet";
        case 79005: return "Montcada i Reixac";
        case 78708: return "Montcada i Reixac-Manresa";
        case 78707: return "Montcada i Reixac-Santa Maria";
        case 79405: return "Montgat";
        case 79406: return "Montgat Nord";
        case 79007: return "Montmeló";
        case 71300: return "Móra la Nova";
        case 76003: return "Nulles-Bràfim";
        case 79408: return "Ocata";
        case 79103: return "Palautordera";
        case 77005: return "Parets del Vallès";
        case 79604: return "Pineda de Mar";
        case 77304: return "Planoles";
        case 71704: return "Platja de Castelldefels";
        case 79315: return "Portbou";
        case 71304: return "Pradell";
        case 79409: return "Premià de Mar";
        case 77309: return "Puigcerdà";
        case 73001: return "Puigverd de Lleida-Artesa de Lleida";
        case 78506: return "Rajadell";
        case 71400: return "Reus";
        case 71209: return "Riba-roja d'Ebre";
        case 77303: return "Ribes de Freser";
        case 79106: return "Riells i Viabrea-Breda";
        case 77200: return "Ripoll";
        case 71306: return "Riudecanyes-Botarell";
        case 79204: return "Riudellots";
        case 72100: return "Roda de Barà";
        case 72101: return "Roda de Mar";
        case 72501: return "Rubí Can Vallhonrat";
        case 78704: return "Sabadell Centre";
        case 78709: return "Sabadell Nord";
        case 78703: return "Sabadell Sud";
        case 76001: return "Salomó";
        case 65411: return "Salou - Port Aventura";
        case 79403: return "Sant Adrià de Besòs";
        case 79501: return "Sant Andreu de Llavaneres";
        case 79104: return "Sant Celoni";
        case 72502: return "Sant Cugat Coll Favà";
        case 72301: return "Sant Feliu de Llobregat";
        case 78501: return "Sant Guim de Freixenet";
        case 72302: return "Sant Joan Despí";
        case 79304: return "Sant Jordi Desvalls";
        case 78502: return "Sant Martí Sesgueioles";
        case 77104: return "Sant Martí de Centelles";
        case 79306: return "Sant Miquel de Fluvià";
        case 78610: return "Sant Miquel de Gonteres-Viladecavalls";
        case 79602: return "Sant Pol de Mar";
        case 77113: return "Sant Quirze de Besora";
        case 72207: return "Sant Sadurní d'Anoia";
        case 71600: return "Sant Vicenç de Calders";
        case 78604: return "Sant Vicenç de Castellet";
        case 77003: return "Santa Perpètua de Mogoda La Florida";
        case 72508: return "Santa Perpètua de Mogoda Riera de Caldes";
        case 79608: return "Santa Susanna";
        case 78504: return "Seguers-Sant Pere Sallavinera";
        case 71602: return "Segur de Calafell";
        case 79202: return "Sils";
        case 71701: return "Sitges";
        case 71500: return "Tarragona";
        case 78710: return "Terrassa Est";
        case 78700: return "Terrassa Estació del Nord";
        case 79607: return "Tordera";
        case 77111: return "Torelló";
        case 71503: return "Torredembarra";
        case 65400: return "Tortosa";
        case 77305: return "Toses";
        case 78408: return "Tàrrega";
        case 65314: return "Ulldecona-Alcanar-La Sénia";
        case 77307: return "Urtx-Alp";
        case 78606: return "Vacarisses";
        case 78607: return "Vacarisses-Torreblanca";
        case 76004: return "Valls";
        case 77109: return "Vic";
        case 71401: return "Vila-seca";
        case 76002: return "Vilabella";
        case 71709: return "Viladecans";
        case 78609: return "Viladecavalls";
        case 72204: return "Vilafranca del Penedès";
        case 79311: return "Vilajuïga";
        case 79308: return "Vilamalla";
        case 71700: return "Vilanova i la Geltrú";
        case 79410: return "Vilassar de Mar";
        case 73009: return "Vilaverd";
        case 73006: return "Vimbodí";
        case 73005: return "Vinaixa";
        default: return "Desconocido"; break;
    }
}

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
        const uint8_t* trip = &data->block[renfe_trip_sector*4-3].data[5];
        uint64_t date_trip = bit_lib_bytes_to_num_le(&data->block[renfe_trip_sector*4-3].data[7], 4);

        uint64_t city = bit_lib_bytes_to_num_le(trip, 3) >> (1+4);
        bool starts_trip = bit_lib_get_bit(trip, 4); // TODO CHECK? 12-13 are C107 when leaving, 0004 when entering

        furi_string_printf(parsed_data, "\e#Renfe & Tu\n");

        uint8_t uid[UID_LENGTH];
        memcpy(uid, data->iso14443_3a_data->uid, UID_LENGTH);

        for(size_t i = 0; i < UID_LENGTH; i++) {
            furi_string_cat_printf(parsed_data, "%02X", uid[i]);
        }

        if (city == 0 && date_trip == 0) {
            furi_string_cat_printf(parsed_data, "\nSin usar\n");
        } else {
            //furi_string_cat_printf(parsed_data, "\n%06llX, ", city);
            furi_string_cat_printf(parsed_data, "\n%s, ", city_name(city));
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
