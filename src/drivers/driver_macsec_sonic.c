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

#include "utils/common.h"
#include "driver.h"
#include "driver_wired_common.h"

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

struct macsec_sonic_data
{
    struct driver_wired_common_data common;

    const char * ifname;
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

    return 0;
}

static int macsec_sonic_macsec_deinit(void *priv)
{
    struct macsec_sonic_data *drv = priv;

    ENTER_LOG;

    return 0;
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

    return 0;
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

    return 0;
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

    return 0;
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

    PRINT_LOG("%s -> %016" PRIx64, __func__, cs);

    return 0;
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

    return 0;
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
    int err = 0;

    ENTER_LOG;

    return err;
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

    PRINT_LOG("%d - %d", sa->an, sa->next_pn);

    return 0;
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

    ENTER_LOG;

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

    PRINT_LOG("%d - %d", sa->an, sa->next_pn);

    return 0;
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

    PRINT_LOG(SCISTR " (conf_offset=%u validation=%d)",
        SCI2STR(
            sc->sci.addr,
            sc->sci.port),
        conf_offset,
        validation);

    return 0;
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

    PRINT_LOG(SCISTR, SCI2STR(sc->sci.addr, sc->sci.port));

    return 0;
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

    PRINT_LOG(SCISTR" (enable_receive=%d next_pn=%u)",
        SCI2STR(
            sa->sc->sci.addr,
            sa->sc->sci.port),
        sa->enable_receive,
        sa->next_pn);

    wpa_hexdump(MSG_DEBUG, DRV_PREFIX "SA keyid",
                &sa->pkey->key_identifier,
                sizeof(sa->pkey->key_identifier));
    wpa_hexdump_key(MSG_DEBUG, DRV_PREFIX "SA key",
                    sa->pkey->key, sa->pkey->key_len);

    return 0;
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

    PRINT_LOG("%d on "SCISTR, sa->an, SCI2STR(sa->sc->sci.addr, sa->sc->sci.port));

    return 0;
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

    PRINT_LOG("%d on "SCISTR, sa->an, SCI2STR(sa->sc->sci.addr, sa->sc->sci.port));

    return 0;
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

    PRINT_LOG("%d on "SCISTR, sa->an, SCI2STR(sa->sc->sci.addr, sa->sc->sci.port));

    return 0;
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

    PRINT_LOG(SCISTR "(conf_offset=%d)", SCI2STR(sc->sci.addr, sc->sci.port), conf_offset);

    return 0;
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

    PRINT_LOG(SCISTR, SCI2STR(sc->sci.addr, sc->sci.port));

    return 0;
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

    PRINT_LOG(SCISTR" (enable_transmit=%d next_pn=%u)",
        SCI2STR(
            sa->sc->sci.addr,
            sa->sc->sci.port),
        sa->enable_transmit,
        sa->next_pn);
    wpa_hexdump(MSG_DEBUG, DRV_PREFIX "SA keyid",
                &sa->pkey->key_identifier,
                sizeof(sa->pkey->key_identifier));
    wpa_hexdump_key(MSG_DEBUG, DRV_PREFIX "SA key",
                    sa->pkey->key, sa->pkey->key_len);

    return 0;
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

    PRINT_LOG("%d on "SCISTR, sa->an, SCI2STR(sa->sc->sci.addr, sa->sc->sci.port));

    return 0;
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

    PRINT_LOG("%d on "SCISTR, sa->an, SCI2STR(sa->sc->sci.addr, sa->sc->sci.port));

    return 0;
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

    PRINT_LOG("%d on "SCISTR, sa->an, SCI2STR(sa->sc->sci.addr, sa->sc->sci.port));

    return 0;
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
