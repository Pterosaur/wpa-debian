/*
 * Driver interaction with Linux MACsec kernel module
 * Copyright (c) 2016, Sabrina Dubroca <sd@queasysnail.net> and Red Hat, Inc.
 * Copyright (c) 2019, The Linux Foundation
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#include "includes.h"

#include <inttypes.h>
#include <stdarg.h>

#include "utils/common.h"
#include "driver.h"
#include "driver_wired_common.h"
#include "sonic_operators.h"

#define DRV_PREFIX "macsec_sonic"

#define LOG_FORMAT(FORMAT, ...) \
    DRV_PREFIX"(%s) : %s "FORMAT"\n",drv->ifname,__PRETTY_FUNCTION__,__VA_ARGS__

#define STD_PRINT_LOG(FORMAT, ...) \
    printf(LOG_FORMAT(FORMAT,__VA_ARGS__))

#define WPA_PRINT_LOG(FORMAT, ...) \
    wpa_printf(MSG_DEBUG, LOG_FORMAT(FORMAT, __VA_ARGS__))

#define PRINT_LOG(FORMAT, ...) \
    STD_PRINT_LOG(FORMAT, __VA_ARGS__); \
    WPA_PRINT_LOG(FORMAT, __VA_ARGS__);

#define ENTER_LOG \
    PRINT_LOG("%s", "")

#define DEFAULT_KEY_SEPARATOR  ":"

static char * create_buffer(const char * fmt, ...)
{
    va_list args;
    va_start(args, fmt);
    unsigned int length = vsnprintf(NULL, 0, fmt, args) + 1;
    va_end(args);
    if (length < 1)
    {
        return NULL;
    }
    char * buffer = (char *)malloc(length);
    if (buffer == NULL)
    {
        return NULL;
    }
    va_start(args, fmt);
    vsnprintf(buffer, length, fmt, args);
    va_end(args);
    return buffer;
}

#define CREATE_SC_KEY(IFNAME, SC)       \
    create_buffer(                      \
        "%s"                            \
        DEFAULT_KEY_SEPARATOR "%llu",  \
        IFNAME,                         \
        mka_sci_u64(&SC->sci))

#define CREATE_SA_KEY(IFNAME, SA)       \
    create_buffer(                      \
        "%s"                            \
        DEFAULT_KEY_SEPARATOR "%llu"   \
        DEFAULT_KEY_SEPARATOR "%u",     \
        IFNAME,                         \
        mka_sci_u64(&SA->sc->sci),      \
        (unsigned int)(SA->an))

char * create_binary_hex(const void * binary, unsigned long long length)
{
    if (binary == NULL || length == 0)
    {
        return NULL;
    }
    char * buffer = (char *)malloc(2 * length + 1);
    if (buffer == NULL)
    {
        return NULL;
    }
    const char * input = (const char *)binary;
    for (unsigned long long i = 0; i < length; i++)
    {
        snprintf(&buffer[i * 2], 3, "%02X", input[i]);
    }
    return buffer;
}

struct macsec_sonic_data
{
    struct driver_wired_common_data common;

    const char * ifname;
    sonic_db_handle sonic_mamager;
};

static void *macsec_sonic_wpa_init(void *ctx, const char *ifname)
{
    struct macsec_sonic_data *drv;

    drv = os_zalloc(sizeof(*drv));
    if (!drv)
        return NULL;

    if (driver_wired_init_common(&drv->common, ifname, ctx) < 0)
    {
        os_free(drv);
        return NULL;
    }

    drv->ifname = ifname;
    drv->sonic_mamager = sonic_db_get_manager();

    ENTER_LOG;
    return drv;
}

static void macsec_sonic_wpa_deinit(void *priv)
{
    struct macsec_sonic_data *drv = priv;

    ENTER_LOG;

    driver_wired_deinit_common(&drv->common);
    os_free(drv);
}

static int macsec_sonic_macsec_init(void *priv, struct macsec_init_params *params)
{
    struct macsec_sonic_data *drv = priv;
    ENTER_LOG;

    int ret = SONIC_DB_SUCCESS;
    const struct sonic_db_name_value_pair pairs[] = 
    {
        {"enable", "false"}
    };
    if ((ret = sonic_db_set(drv->sonic_mamager, APPL_DB, APP_MACSEC_PORT_TABLE_NAME, drv->ifname, pairs, 1))
        != SONIC_DB_SUCCESS)
    {
        return ret;
    }
    if ((ret = sonic_db_wait(drv->sonic_mamager, STATE_DB, STATE_MACSEC_PORT_TABLE_NAME, SET_COMMAND, drv->ifname, NULL, 0))
        != SONIC_DB_SUCCESS)
    {
        return ret;
    }
    return ret;
}

static int macsec_sonic_macsec_deinit(void *priv)
{
    struct macsec_sonic_data *drv = priv;
    ENTER_LOG;

    int ret = SONIC_DB_SUCCESS;
    if ((ret = sonic_db_del(drv->sonic_mamager, APPL_DB, APP_MACSEC_PORT_TABLE_NAME, drv->ifname))
        != SONIC_DB_SUCCESS)
    {
        return ret;
    }
    if ((ret = sonic_db_wait(drv->sonic_mamager, STATE_DB, STATE_MACSEC_PORT_TABLE_NAME, DEL_COMMAND, drv->ifname, NULL, 0))
        != SONIC_DB_SUCCESS)
    {
        return ret;
    }

    return ret;
}

static int macsec_sonic_get_capability(void *priv, enum macsec_cap *cap)
{
    struct macsec_sonic_data *drv = priv;

    ENTER_LOG;

    *cap = MACSEC_CAP_INTEG_AND_CONF;

    return 0;
}

/**
 * macsec_sonic_enable_protect_frames - Set protect frames status
 * @priv: Private driver interface data
 * @enabled: TRUE = protect frames enabled
 *           FALSE = protect frames disabled
 * Returns: 0 on success, -1 on failure (or if not supported)
 */
static int macsec_sonic_enable_protect_frames(void *priv, Boolean enabled)
{
    struct macsec_sonic_data *drv = priv;
    PRINT_LOG("%s", enabled ? "TRUE" : "FALSE");

    const struct sonic_db_name_value_pair pairs[] = 
    {
        {"enable_protect", enabled ? "true" : "false"}
    };
    return sonic_db_set(drv->sonic_mamager, APPL_DB, APP_MACSEC_PORT_TABLE_NAME, drv->ifname, pairs, 1);
}

/**
 * macsec_sonic_enable_encrypt - Set protect frames status
 * @priv: Private driver interface data
 * @enabled: TRUE = protect frames enabled
 *           FALSE = protect frames disabled
 * Returns: 0 on success, -1 on failure (or if not supported)
 */
static int macsec_sonic_enable_encrypt(void *priv, Boolean enabled)
{
    struct macsec_sonic_data *drv = priv;
    PRINT_LOG("%s", enabled ? "TRUE" : "FALSE");

    const struct sonic_db_name_value_pair pairs[] = 
    {
        {"enable_encrypt", enabled ? "true" : "false"}
    };
    return sonic_db_set(drv->sonic_mamager, APPL_DB, APP_MACSEC_PORT_TABLE_NAME, drv->ifname, pairs, 1);
}

/**
 * macsec_sonic_set_replay_protect - Set replay protect status and window size
 * @priv: Private driver interface data
 * @enabled: TRUE = replay protect enabled
 *           FALSE = replay protect disabled
 * @window: replay window size, valid only when replay protect enabled
 * Returns: 0 on success, -1 on failure (or if not supported)
 */
static int macsec_sonic_set_replay_protect(void *priv, Boolean enabled,
                                           u32 window)
{
    struct macsec_sonic_data *drv = priv;
    PRINT_LOG("%s %u", enabled ? "TRUE" : "FALSE", window);

    char * buffer = create_buffer("%u", window);
    const struct sonic_db_name_value_pair pairs[] = 
    {
        {"enable_replay_protect", enabled ? "true" : "false"},
        {"replay_window", buffer}
    };
    int ret = sonic_db_set(drv->sonic_mamager, APPL_DB, APP_MACSEC_PORT_TABLE_NAME, drv->ifname, pairs, 2);
    free(buffer);

    return ret;
}

/**
 * macsec_sonic_set_current_cipher_suite - Set current cipher suite
 * @priv: Private driver interface data
 * @cs: EUI64 identifier
 * Returns: 0 on success, -1 on failure (or if not supported)
 */
static int macsec_sonic_set_current_cipher_suite(void *priv, u64 cs)
{
    struct macsec_sonic_data *drv = priv;

    const char * cipher_suite = NULL;
    if (cs == CS_ID_GCM_AES_128)
    {
        cipher_suite = "GCM-AES-128";
    }
    else if (cs == CS_ID_GCM_AES_256)
    {
        cipher_suite = "GCM-AES-256";
    }
    else
    {
        return -1;
    }
    PRINT_LOG("%s(%016" PRIx64 ")", cipher_suite, cs);

    const struct sonic_db_name_value_pair pairs[] = 
    {
        {"cipher_suite", (char *)(cipher_suite)},
    };
    return sonic_db_set(drv->sonic_mamager, APPL_DB, APP_MACSEC_PORT_TABLE_NAME, drv->ifname, pairs, 1);
}

/**
 * macsec_sonic_enable_controlled_port - Set controlled port status
 * @priv: Private driver interface data
 * @enabled: TRUE = controlled port enabled
 *           FALSE = controlled port disabled
 * Returns: 0 on success, -1 on failure (or if not supported)
 */
static int macsec_sonic_enable_controlled_port(void *priv, Boolean enabled)
{
    struct macsec_sonic_data *drv = priv;
    PRINT_LOG("%s", enabled ? "TRUE" : "FALSE");

    const struct sonic_db_name_value_pair pairs[] = 
    {
        {"enable_encrypt", enabled ? "true" : "false"}
    };
    return sonic_db_set(drv->sonic_mamager, APPL_DB, APP_MACSEC_PORT_TABLE_NAME, drv->ifname, pairs, 1);
}

/**
 * macsec_sonic_get_receive_lowest_pn - Get receive lowest PN
 * @priv: Private driver interface data
 * @sa: secure association
 * Returns: 0 on success, -1 on failure (or if not supported)
 */
static int macsec_sonic_get_receive_lowest_pn(void *priv, struct receive_sa *sa)
{
    struct macsec_sonic_data *drv = priv;

    char * key = CREATE_SA_KEY(drv->ifname, sa);
    PRINT_LOG("%s", key);
    struct sonic_db_name_value_pairs * pairs = sonic_db_malloc_name_value_pairs();
    int ret = sonic_db_get(drv->sonic_mamager, COUNTERS_DB, COUNTERS_MACSEC_TABLE, key, pairs);
    if (ret == SONIC_DB_SUCCESS)
    {
        for (unsigned int i = 0; i < pairs->pair_count; i++)
        {
            if ((pairs->pairs[i].name != NULL)
                && (strcmp("SAI_MACSEC_SA_ATTR_MINIMUM_XPN", pairs->pairs[i].name ) == 0)
                )
            {
                sa->next_pn = strtoul(pairs->pairs[i].value, NULL, 10);
            }
        }
    }
    sonic_db_free_name_value_pairs(pairs);
    free(key);
    return ret;
}

/**
 * macsec_sonic_set_receive_lowest_pn - Set receive lowest PN
 * @priv: Private driver interface data
 * @sa: secure association
 * Returns: 0 on success, -1 on failure (or if not supported)
 */
static int macsec_sonic_set_receive_lowest_pn(void *priv, struct receive_sa *sa)
{
    struct macsec_sonic_data *drv = priv;

    char * key = CREATE_SA_KEY(drv->ifname, sa);
    PRINT_LOG("%s - %u", key, sa->next_pn);
    char * buffer = create_buffer("%u", sa->next_pn);
    const struct sonic_db_name_value_pair pairs[] = 
    {
        {"lowest_acceptable_pn", buffer}
    };
    int ret = sonic_db_set(drv->sonic_mamager, APPL_DB, APP_MACSEC_INGRESS_SA_TABLE_NAME, key, pairs, 1);
    free(buffer);
    free(key);

    return ret;
}

/**
 * macsec_sonic_get_transmit_next_pn - Get transmit next PN
 * @priv: Private driver interface data
 * @sa: secure association
 * Returns: 0 on success, -1 on failure (or if not supported)
 */
static int macsec_sonic_get_transmit_next_pn(void *priv, struct transmit_sa *sa)
{
    struct macsec_sonic_data *drv = priv;

    char * key = CREATE_SA_KEY(drv->ifname, sa);
    PRINT_LOG("%s", key);

    struct sonic_db_name_value_pairs * pairs = sonic_db_malloc_name_value_pairs();
    int ret = sonic_db_get(drv->sonic_mamager, COUNTERS_DB, COUNTERS_MACSEC_TABLE, key, pairs);
    if (ret == SONIC_DB_SUCCESS)
    {
        for (unsigned int i = 0; i < pairs->pair_count; i++)
        {
            if ((pairs->pairs[i].name != NULL)
                && (strcmp("SAI_MACSEC_SA_ATTR_XPN", pairs->pairs[i].name ) == 0)
                )
            {
                sa->next_pn = strtoul(pairs->pairs[i].value, NULL, 10);
            }
        }
    }
    sonic_db_free_name_value_pairs(pairs);
    free(key);

    return 0;
}

/**
 * macsec_sonic_set_transmit_next_pn - Set transmit next pn
 * @priv: Private driver interface data
 * @sa: secure association
 * Returns: 0 on success, -1 on failure (or if not supported)
 */
static int macsec_sonic_set_transmit_next_pn(void *priv, struct transmit_sa *sa)
{
    struct macsec_sonic_data *drv = priv;

    char * key = CREATE_SA_KEY(drv->ifname, sa);
    PRINT_LOG("%s - %u", key, sa->next_pn);
    char * buffer = create_buffer("%u", sa->next_pn);
    const struct sonic_db_name_value_pair pairs[] = 
    {
        {"init_pn", buffer}
    };
    int ret = sonic_db_set(drv->sonic_mamager, APPL_DB, APP_MACSEC_EGRESS_SA_TABLE_NAME, key, pairs, 1);
    free(buffer);
    free(key);

    return ret;
}

#define SCISTR MACSTR "::%hx"
#define SCI2STR(addr, port) MAC2STR(addr), htons(port)

/**
 * macsec_sonic_create_receive_sc - Create secure channel for receiving
 * @priv: Private driver interface data
 * @sc: secure channel
 * @sci_addr: secure channel identifier - address
 * @sci_port: secure channel identifier - port
 * @conf_offset: confidentiality offset (0, 30, or 50)
 * @validation: frame validation policy (0 = Disabled, 1 = Checked,
 *	2 = Strict)
 * Returns: 0 on success, -1 on failure (or if not supported)
 */
static int macsec_sonic_create_receive_sc(void *priv, struct receive_sc *sc,
                                          unsigned int conf_offset,
                                          int validation)
{
    struct macsec_sonic_data *drv = priv;

    char * key = CREATE_SC_KEY(drv->ifname, sc);
    PRINT_LOG("%s (conf_offset=%u validation=%d)",
        key,
        conf_offset,
        validation);
    // TODO 
    // Validation
    // OFFSET
    int ret = sonic_db_set(drv->sonic_mamager, APPL_DB, APP_MACSEC_INGRESS_SC_TABLE_NAME, key, NULL, 0);
    free(key);

    return ret;
}

/**
 * macsec_sonic_delete_receive_sc - Delete secure connection for receiving
 * @priv: private driver interface data from init()
 * @sc: secure channel
 * Returns: 0 on success, -1 on failure
 */
static int macsec_sonic_delete_receive_sc(void *priv, struct receive_sc *sc)
{
    struct macsec_sonic_data *drv = priv;

    char * key = CREATE_SC_KEY(drv->ifname, sc);
    PRINT_LOG("%s", key);
    int ret = sonic_db_del(drv->sonic_mamager, APPL_DB, APP_MACSEC_INGRESS_SC_TABLE_NAME, key);
    free(key);

    return ret;
}

/**
 * macsec_sonic_create_receive_sa - Create secure association for receive
 * @priv: private driver interface data from init()
 * @sa: secure association
 * Returns: 0 on success, -1 on failure
 */
static int macsec_sonic_create_receive_sa(void *priv, struct receive_sa *sa)
{
    struct macsec_sonic_data *drv = priv;

    char * key = CREATE_SA_KEY(drv->ifname, sa);
    char * sak_id = create_binary_hex(&sa->pkey->key_identifier, sizeof(sa->pkey->key_identifier));
    char * sak = create_binary_hex(sa->pkey->key, sa->pkey->key_len);
    char * pn = create_buffer("%u", sa->next_pn);
    PRINT_LOG("%s (enable_receive=%d next_pn=%u) %s %s",
        key,
        sa->enable_receive,
        sa->next_pn,
        sak_id,
        sak);

    // TODO
    // AUTH_KEY
    // SALT
    const struct sonic_db_name_value_pair pairs[] = 
    {
        {"active", "false"},
        {"sak", sak},
        {"auth_key", ""},
        {"lowest_acceptable_pn", pn},
        {"salt", ""}
    };
    int ret = sonic_db_set(drv->sonic_mamager, APPL_DB, APP_MACSEC_INGRESS_SA_TABLE_NAME, key, pairs, 5);
    free(key);
    free(sak_id);
    free(sak);
    free(pn);

    return ret;
}

/**
 * macsec_sonic_delete_receive_sa - Delete secure association for receive
 * @priv: private driver interface data from init()
 * @sa: secure association
 * Returns: 0 on success, -1 on failure
 */
static int macsec_sonic_delete_receive_sa(void *priv, struct receive_sa *sa)
{
    struct macsec_sonic_data *drv = priv;

    char * key = CREATE_SA_KEY(drv->ifname, sa);
    PRINT_LOG("%s", key);
    int ret = sonic_db_del(drv->sonic_mamager, APPL_DB, APP_MACSEC_INGRESS_SA_TABLE_NAME, key);
    free(key);

    return ret;
}

/**
 * macsec_sonic_enable_receive_sa - Enable the SA for receive
 * @priv: private driver interface data from init()
 * @sa: secure association
 * Returns: 0 on success, -1 on failure
 */
static int macsec_sonic_enable_receive_sa(void *priv, struct receive_sa *sa)
{
    struct macsec_sonic_data *drv = priv;

    char * key = CREATE_SA_KEY(drv->ifname, sa);
    PRINT_LOG("%s", key);
    const struct sonic_db_name_value_pair pairs[] = 
    {
        {"active", "true"},
    };
    int ret = sonic_db_set(drv->sonic_mamager, APPL_DB, APP_MACSEC_INGRESS_SA_TABLE_NAME, key, pairs, 1);
    free(key);

    return ret;
}

/**
 * macsec_sonic_disable_receive_sa - Disable SA for receive
 * @priv: private driver interface data from init()
 * @sa: secure association
 * Returns: 0 on success, -1 on failure
 */
static int macsec_sonic_disable_receive_sa(void *priv, struct receive_sa *sa)
{
    struct macsec_sonic_data *drv = priv;

    char * key = CREATE_SA_KEY(drv->ifname, sa);
    PRINT_LOG("%s", key);
    const struct sonic_db_name_value_pair pairs[] = 
    {
        {"active", "false"},
    };
    int ret = sonic_db_set(drv->sonic_mamager, APPL_DB, APP_MACSEC_INGRESS_SA_TABLE_NAME, key, pairs, 1);
    free(key);

    return ret;
}

/**
 * macsec_sonic_create_transmit_sc - Create secure connection for transmit
 * @priv: private driver interface data from init()
 * @sc: secure channel
 * @conf_offset: confidentiality offset
 * Returns: 0 on success, -1 on failure
 */
static int macsec_sonic_create_transmit_sc(
    void *priv, struct transmit_sc *sc,
    unsigned int conf_offset)
{
    struct macsec_sonic_data *drv = priv;

    char * key = CREATE_SC_KEY(drv->ifname, sc);
    PRINT_LOG("%s (conf_offset=%u)",
        key,
        conf_offset);
    // TODO 
    // Validation
    const struct sonic_db_name_value_pair pairs[] = 
    {
        {"encoding_an", "0"},
    };
    int ret = sonic_db_set(drv->sonic_mamager, APPL_DB, APP_MACSEC_EGRESS_SC_TABLE_NAME, key, pairs, 1);
    free(key);

    return ret;
}

/**
 * macsec_sonic_delete_transmit_sc - Delete secure connection for transmit
 * @priv: private driver interface data from init()
 * @sc: secure channel
 * Returns: 0 on success, -1 on failure
 */
static int macsec_sonic_delete_transmit_sc(void *priv, struct transmit_sc *sc)
{

    struct macsec_sonic_data *drv = priv;

    char * key = CREATE_SC_KEY(drv->ifname, sc);
    PRINT_LOG("%s", key);
    int ret = sonic_db_del(drv->sonic_mamager, APPL_DB, APP_MACSEC_EGRESS_SC_TABLE_NAME, key);
    free(key);

    return ret;
}

/**
 * macsec_sonic_create_transmit_sa - Create secure association for transmit
 * @priv: private driver interface data from init()
 * @sa: secure association
 * Returns: 0 on success, -1 on failure
 */
static int macsec_sonic_create_transmit_sa(void *priv, struct transmit_sa *sa)
{
    struct macsec_sonic_data *drv = priv;

    char * key = CREATE_SA_KEY(drv->ifname, sa);
    char * sak_id = create_binary_hex(&sa->pkey->key_identifier, sizeof(sa->pkey->key_identifier));
    char * sak = create_binary_hex(sa->pkey->key, sa->pkey->key_len);
    char * pn = create_buffer("%u", sa->next_pn);
    PRINT_LOG("%s (enable_receive=%d next_pn=%u) %s %s",
        key,
        sa->enable_transmit,
        sa->next_pn,
        sak_id,
        sak);

    // TODO
    // AUTH_KEY
    // SALT
    const struct sonic_db_name_value_pair pairs[] = 
    {
        {"active", "false"},
        {"sak", sak},
        {"auth_key", ""},
        {"init_pn", pn},
        {"salt", ""}
    };
    int ret = sonic_db_set(drv->sonic_mamager, APPL_DB, APP_MACSEC_EGRESS_SA_TABLE_NAME, key, pairs, 5);
    free(key);
    free(sak_id);
    free(sak);
    free(pn);

    return ret;
}

/**
 * macsec_sonic_delete_transmit_sa - Delete secure association for transmit
 * @priv: private driver interface data from init()
 * @sa: secure association
 * Returns: 0 on success, -1 on failure
 */
static int macsec_sonic_delete_transmit_sa(void *priv, struct transmit_sa *sa)
{
    struct macsec_sonic_data *drv = priv;

    char * key = CREATE_SA_KEY(drv->ifname, sa);
    PRINT_LOG("%s", key);
    int ret = sonic_db_del(drv->sonic_mamager, APPL_DB, APP_MACSEC_EGRESS_SA_TABLE_NAME, key);
    free(key);

    return ret;
}

/**
 * macsec_sonic_enable_transmit_sa - Enable SA for transmit
 * @priv: private driver interface data from init()
 * @sa: secure association
 * Returns: 0 on success, -1 on failure
 */
static int macsec_sonic_enable_transmit_sa(void *priv, struct transmit_sa *sa)
{
    struct macsec_sonic_data *drv = priv;

    char * key = CREATE_SA_KEY(drv->ifname, sa);
    PRINT_LOG("%s", key);
    const struct sonic_db_name_value_pair pairs[] = 
    {
        {"active", "true"},
    };
    int ret = sonic_db_set(drv->sonic_mamager, APPL_DB, APP_MACSEC_EGRESS_SA_TABLE_NAME, key, pairs, 1);
    free(key);

    return ret;
}

/**
 * macsec_sonic_disable_transmit_sa - Disable SA for transmit
 * @priv: private driver interface data from init()
 * @sa: secure association
 * Returns: 0 on success, -1 on failure
 */
static int macsec_sonic_disable_transmit_sa(void *priv, struct transmit_sa *sa)
{
    struct macsec_sonic_data *drv = priv;

    char * key = CREATE_SA_KEY(drv->ifname, sa);
    PRINT_LOG("%s", key);
    const struct sonic_db_name_value_pair pairs[] = 
    {
        {"active", "false"},
    };
    int ret = sonic_db_set(drv->sonic_mamager, APPL_DB, APP_MACSEC_EGRESS_SA_TABLE_NAME, key, pairs, 1);
    free(key);

    return ret;
}

static int macsec_sonic_status(void *priv, char *buf, size_t buflen)
{
    struct macsec_sonic_data *drv = priv;
    int res;
    char *pos, *end;

    pos = buf;
    end = buf + buflen;

    res = os_snprintf(pos, end - pos,
                      "ifname=%s\n",
                      drv->ifname);
    if (os_snprintf_error(end - pos, res))
        return pos - buf;
    pos += res;

    return pos - buf;
}

const struct wpa_driver_ops wpa_driver_macsec_sonic_ops = {
    .name = "macsec_sonic",
    .desc = "MACsec Ethernet driver for SONiC",
    .get_ssid = driver_wired_get_ssid,
    .get_bssid = driver_wired_get_bssid,
    .get_capa = driver_wired_get_capa,
    .init = macsec_sonic_wpa_init,
    .deinit = macsec_sonic_wpa_deinit,

    .macsec_init = macsec_sonic_macsec_init,
    .macsec_deinit = macsec_sonic_macsec_deinit,
    .macsec_get_capability = macsec_sonic_get_capability,
    .enable_protect_frames = macsec_sonic_enable_protect_frames,
    .enable_encrypt = macsec_sonic_enable_encrypt,
    .set_replay_protect = macsec_sonic_set_replay_protect,
    .set_current_cipher_suite = macsec_sonic_set_current_cipher_suite,
    .enable_controlled_port = macsec_sonic_enable_controlled_port,
    .get_receive_lowest_pn = macsec_sonic_get_receive_lowest_pn,
    .set_receive_lowest_pn = macsec_sonic_set_receive_lowest_pn,
    .get_transmit_next_pn = macsec_sonic_get_transmit_next_pn,
    .set_transmit_next_pn = macsec_sonic_set_transmit_next_pn,
    .create_receive_sc = macsec_sonic_create_receive_sc,
    .delete_receive_sc = macsec_sonic_delete_receive_sc,
    .create_receive_sa = macsec_sonic_create_receive_sa,
    .delete_receive_sa = macsec_sonic_delete_receive_sa,
    .enable_receive_sa = macsec_sonic_enable_receive_sa,
    .disable_receive_sa = macsec_sonic_disable_receive_sa,
    .create_transmit_sc = macsec_sonic_create_transmit_sc,
    .delete_transmit_sc = macsec_sonic_delete_transmit_sc,
    .create_transmit_sa = macsec_sonic_create_transmit_sa,
    .delete_transmit_sa = macsec_sonic_delete_transmit_sa,
    .enable_transmit_sa = macsec_sonic_enable_transmit_sa,
    .disable_transmit_sa = macsec_sonic_disable_transmit_sa,

    .status = macsec_sonic_status,
};
