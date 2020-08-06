/*
 * wpa_supplicant - 
 * Copyright (c) 
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#ifndef SONIC_OPERATORS_H
#define SONIC_OPERATORS_H

// The following definitions should be moved to schema.h
#define APPL_DB         0
#define COUNTERS_DB     2
#define STATE_DB        6

#define APP_MACSEC_PORT_TABLE_NAME          "MACSEC_PORT_TABLE"
#define APP_MACSEC_EGRESS_SC_TABLE_NAME     "MACSEC_EGRESS_SC_TABLE"
#define APP_MACSEC_INGRESS_SC_TABLE_NAME    "MACSEC_INGRESS_SC_TABLE"
#define APP_MACSEC_EGRESS_SA_TABLE_NAME     "MACSEC_EGRESS_SA_TABLE"
#define APP_MACSEC_INGRESS_SA_TABLE_NAME    "MACSEC_INGRESS_SA_TABLE"

#define STATE_MACSEC_PORT_TABLE_NAME        "MACSEC_PORT_TABLE"

#define COUNTERS_MACSEC_NAME_MAP            "COUNTERS_MACSEC_NAME_MAP"
#define COUNTERS_MACSEC_TABLE               "COUNTERS_MACSEC"

#define SET_COMMAND "SET"
#define DEL_COMMAND "DEL"
// End define

#define SONIC_DB_SUCCESS (0)
#define SONIC_DB_FAIL    (-1)
#define UNSET_POINTER    (NULL)

struct sonic_db_name_value_pair
{
    char * name;
    char * value;
};

struct sonic_db_name_value_pairs
{
    unsigned int pair_count;
    struct sonic_db_name_value_pair * pairs;
};

typedef void * sonic_db_handle;

#ifdef __cplusplus
extern "C" {
#endif

sonic_db_handle sonic_db_get_manager();

int sonic_db_set(
    sonic_db_handle sonic_manager,
    int db_id,
    const char * table_name,
    const char * key,
    const struct sonic_db_name_value_pair * pairs,
    unsigned int pair_count);

int sonic_db_get(
    sonic_db_handle sonic_manager,
    int db_id,
    const char * table_name,
    const char * key,
    struct sonic_db_name_value_pairs * pairs);

int sonic_db_del(
    sonic_db_handle sonic_manager,
    int db_id,
    const char * table_name,
    const char * key);

int sonic_db_wait(
    sonic_db_handle sonic_manager,
    int db_id,
    const char * table,
    const char * op,
    const char * key,
    const struct sonic_db_name_value_pair * pairs,
    unsigned int pair_count);

struct sonic_db_name_value_pairs * sonic_db_malloc_name_value_pairs();

void sonic_db_free_name_value_pairs(struct sonic_db_name_value_pairs * pairs);

#ifdef __cplusplus
};
#endif

#endif
