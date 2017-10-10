/*
 * Copyright (c) 2014-2017 Cesanta Software Limited
 * All rights reserved
 */

/*
 * Interface to sys_config over BLE GATT service.
 * See README.md for high-level description.
 */

#include <stdlib.h>

#include "common/cs_dbg.h"
#include "common/mbuf.h"
#include "common/mg_str.h"

#include "mgos_config_util.h"
#include "mgos_hal.h"
#include "mgos_sys_config.h"
#include "mgos_utils.h"

#include "esp32_bt.h"

/* Note: UUIDs below are in reverse, because that's how ESP wants them. */
static const esp_bt_uuid_t mos_cfg_svc_uuid = {
    .len = ESP_UUID_LEN_128,
    .uuid.uuid128 =
        {
         /* _mOS_CFG_SVC_ID_, 5f6d4f53-5f43-4647-5f53-56435f49445f */
         0x5f, 0x44, 0x49, 0x5f, 0x43, 0x56, 0x53, 0x5f, 0x47, 0x46, 0x43, 0x5f,
         0x53, 0x4f, 0x6d, 0x5f,
        },
};

static const esp_bt_uuid_t mos_cfg_key_uuid = {
    .len = ESP_UUID_LEN_128,
    .uuid.uuid128 =
        {
         /* 0mOS_CFG_key___0, 306d4f53-5f43-4647-5f6b-65795f5f5f30 */
         0x30, 0x5f, 0x5f, 0x5f, 0x79, 0x65, 0x6b, 0x5f, 0x47, 0x46, 0x43, 0x5f,
         0x53, 0x4f, 0x6d, 0x30,
        },
};
static uint16_t mos_cfg_key_ah;

static const esp_bt_uuid_t mos_cfg_value_uuid = {
    .len = ESP_UUID_LEN_128,
    .uuid.uuid128 =
        {
         /* 1mOS_CFG_value_1, 316d4f53-5f43-4647-5f76-616c75655f31 */
         0x31, 0x5f, 0x65, 0x75, 0x6c, 0x61, 0x76, 0x5f, 0x47, 0x46, 0x43, 0x5f,
         0x53, 0x4f, 0x6d, 0x31,
        },
};
static uint16_t mos_cfg_value_ah;

static const esp_bt_uuid_t mos_cfg_save_uuid = {
    .len = ESP_UUID_LEN_128,
    .uuid.uuid128 =
        {
         /* 2mOS_CFG_save__2, 326d4f53-5f43-4647-5f73-6176655f5f32 */
         0x32, 0x5f, 0x5f, 0x65, 0x76, 0x61, 0x73, 0x5f, 0x47, 0x46, 0x43, 0x5f,
         0x53, 0x4f, 0x6d, 0x32,
        },
};
static uint16_t mos_cfg_save_ah;

const esp_gatts_attr_db_t mos_cfg_gatt_db[7] = {
    {
     .attr_control = {.auto_rsp = ESP_GATT_AUTO_RSP},
     .att_desc =
         {
          .uuid_length = ESP_UUID_LEN_16,
          .uuid_p = (uint8_t *) &primary_service_uuid,
          .perm = ESP_GATT_PERM_READ,
          .max_length = ESP_UUID_LEN_128,
          .length = ESP_UUID_LEN_128,
          .value = (uint8_t *) mos_cfg_svc_uuid.uuid.uuid128,
         },
    },

    /* key */
    {{ESP_GATT_AUTO_RSP},
     {ESP_UUID_LEN_16, (uint8_t *) &char_decl_uuid, ESP_GATT_PERM_READ, 1, 1,
      (uint8_t *) &char_prop_write}},
    {{ESP_GATT_RSP_BY_APP},
     {ESP_UUID_LEN_128, (uint8_t *) mos_cfg_key_uuid.uuid.uuid128,
      ESP_GATT_PERM_WRITE, 0, 0, NULL}},

    /* value */
    {{ESP_GATT_AUTO_RSP},
     {ESP_UUID_LEN_16, (uint8_t *) &char_decl_uuid, ESP_GATT_PERM_READ, 1, 1,
      (uint8_t *) &char_prop_read_write}},
    {{ESP_GATT_RSP_BY_APP},
     {ESP_UUID_LEN_128, (uint8_t *) mos_cfg_value_uuid.uuid.uuid128,
      ESP_GATT_PERM_READ | ESP_GATT_PERM_WRITE, 0, 0, NULL}},

    /* save */
    {{ESP_GATT_AUTO_RSP},
     {ESP_UUID_LEN_16, (uint8_t *) &char_decl_uuid, ESP_GATT_PERM_READ, 1, 1,
      (uint8_t *) &char_prop_write}},
    {{ESP_GATT_RSP_BY_APP},
     {ESP_UUID_LEN_128, (uint8_t *) mos_cfg_save_uuid.uuid.uuid128,
      ESP_GATT_PERM_WRITE, 0, 0, NULL}},
};

enum bt_cfg_state {
  BT_CFG_STATE_KEY_ENTRY = 0,
  BT_CFG_STATE_VALUE_ENTRY = 1,
  BT_CFG_STATE_VALUE_READ = 2,
  BT_CFG_STATE_SAVE = 3,
};

struct bt_cfg_svc_data {
  struct mbuf key;
  struct mbuf value;
  enum bt_cfg_state state;
};

static bool mgos_bt_svc_config_set(struct bt_cfg_svc_data *sd) {
  bool ret = false;
  const struct mgos_conf_entry *e = mgos_conf_find_schema_entry_s(
      mg_mk_str_n(sd->key.buf, sd->key.len), mgos_config_schema());
  if (e == NULL) {
    LOG(LL_ERROR,
        ("Config key '%.*s' not found", (int) sd->key.len, sd->key.buf));
    return false;
  }
  /* Make sure value is NUL-terminated, for simplicity. */
  mbuf_append(&sd->value, "", 1);
  sd->value.len--;
  const char *vt = NULL;
  char *vp = (((char *) &mgos_sys_config) + e->offset);
  /* For simplicity, we only allow setting leaf values. */
  switch (e->type) {
    case CONF_TYPE_INT: {
      int *ivp = (int *) vp;
      char *endptr = NULL;
      int v = strtol(sd->value.buf, &endptr, 0);
      vt = "int";
      if (endptr - sd->value.buf == sd->value.len) {
        *ivp = v;
        ret = true;
        LOG(LL_INFO, ("'%.*s' = %d", (int) sd->key.len, sd->key.buf, *ivp));
      }
      break;
    }
    case CONF_TYPE_DOUBLE: {
      double *dvp = (double *) vp;
      char *endptr = NULL;
      double v = strtod(sd->value.buf, &endptr);
      vt = "float";
      if (endptr - sd->value.buf == sd->value.len) {
        *dvp = v;
        ret = true;
        LOG(LL_INFO, ("'%.*s' = %f", (int) sd->key.len, sd->key.buf, *dvp));
      }
      break;
    }
    case CONF_TYPE_STRING: {
      vt = "string";
      char **svp = (char **) vp;
      mgos_conf_set_str(svp, sd->value.buf);
      LOG(LL_INFO, ("'%.*s' = '%s'", (int) sd->key.len, sd->key.buf, *svp));
      ret = true;
      break;
    }
    case CONF_TYPE_BOOL: {
      bool *bvp = (bool *) vp;
      const struct mg_str vs = mg_mk_str_n(sd->value.buf, sd->value.len);
      vt = "bool";
      if (mg_vcmp(&vs, "true") == 0 || mg_vcmp(&vs, "false") == 0) {
        *bvp = (mg_vcmp(&vs, "true") == 0);
        LOG(LL_INFO, ("'%.*s' = %s", (int) sd->key.len, sd->key.buf,
                      (*bvp ? "true" : "false")));
        ret = true;
      }
      break;
    }
    case CONF_TYPE_OBJECT: {
      LOG(LL_ERROR, ("Setting objects is not allowed (%.*s)", (int) sd->key.len,
                     sd->key.buf));
      break;
    }
  }
  if (!ret && vt != NULL) {
    LOG(LL_ERROR, ("'%.*s': invalid %s value '%.*s'", (int) sd->key.len,
                   sd->key.buf, vt, (int) sd->value.len, sd->value.buf));
  }
  return ret;
}

static bool mgos_bt_svc_config_ev(struct esp32_bt_session *bs,
                                  esp_gatts_cb_event_t ev,
                                  esp_ble_gatts_cb_param_t *ep) {
  bool ret = false;
  struct bt_cfg_svc_data *sd = NULL;
  struct esp32_bt_connection *bc = NULL;
  if (bs != NULL) { /* CREAT_ATTR_TAB is not associated with any session. */
    bc = bs->bc;
    sd = (struct bt_cfg_svc_data *) bs->user_data;
  }
  switch (ev) {
    case ESP_GATTS_CREAT_ATTR_TAB_EVT: {
      const struct gatts_add_attr_tab_evt_param *p = &ep->add_attr_tab;
      uint16_t svch = p->handles[0];
      mos_cfg_key_ah = p->handles[2];
      mos_cfg_value_ah = p->handles[4];
      mos_cfg_save_ah = p->handles[6];
      LOG(LL_DEBUG, ("svch = %d key_ah = %d value_ah = %d save_ah = %d", svch,
                     mos_cfg_key_ah, mos_cfg_value_ah, mos_cfg_save_ah));
      break;
    }
    case ESP_GATTS_CONNECT_EVT: {
      sd = (struct bt_cfg_svc_data *) calloc(1, sizeof(*sd));
      if (sd == NULL) break;
      mbuf_init(&sd->key, 0);
      mbuf_init(&sd->value, 0);
      sd->state = BT_CFG_STATE_KEY_ENTRY;
      bs->user_data = sd;
      break;
    }
    case ESP_GATTS_READ_EVT: {
      const struct gatts_read_evt_param *p = &ep->read;
      if (sd == NULL || p->handle != mos_cfg_value_ah) break;
      if (sd->key.len == 0) {
        LOG(LL_ERROR, ("Key to read is not set"));
        break;
      }
      sd->state = BT_CFG_STATE_VALUE_READ;
      const struct mgos_conf_entry *e = mgos_conf_find_schema_entry_s(
          mg_mk_str_n(sd->key.buf, sd->key.len), mgos_config_schema());
      if (e == NULL) {
        LOG(LL_ERROR,
            ("Config key '%.*s' not found", (int) sd->key.len, sd->key.buf));
        break;
      }
      struct mbuf vb;
      mbuf_init(&vb, 0);
      mgos_conf_emit_cb(&mgos_sys_config, NULL /* base */, e,
                        false /* pretty */, &vb, NULL /* cb */,
                        NULL /* cb_param */);
      uint16_t to_send = bc->mtu - 1;
      if (p->offset > vb.len) break;
      if (vb.len - p->offset < to_send) to_send = vb.len - p->offset;
      LOG(LL_INFO,
          ("Read '%.*s' %d @ %d = '%.*s'", (int) sd->key.len, sd->key.buf,
           (int) to_send, (int) p->offset, (int) to_send, vb.buf + p->offset));
      esp_gatt_rsp_t rsp = {.attr_value = {.handle = mos_cfg_value_ah,
                                           .offset = p->offset,
                                           .len = to_send}};
      memcpy(rsp.attr_value.value, vb.buf + p->offset, to_send);
      esp_ble_gatts_send_response(bc->gatt_if, bc->conn_id, p->trans_id,
                                  ESP_GATT_OK, &rsp);
      ret = true;
      mbuf_free(&vb);
      break;
    }
    case ESP_GATTS_WRITE_EVT: {
      const struct gatts_write_evt_param *p = &ep->write;
      if (sd == NULL) break;
      if (p->handle == mos_cfg_key_ah) {
        if (sd->state != BT_CFG_STATE_KEY_ENTRY) {
          mbuf_free(&sd->key);
          mbuf_free(&sd->value);
          mbuf_init(&sd->key, p->len);
          sd->state = BT_CFG_STATE_KEY_ENTRY;
        }
        mbuf_append(&sd->key, p->value, p->len);
        LOG(LL_DEBUG, ("Key = '%.*s'", (int) sd->key.len, sd->key.buf));
        ret = true;
      } else if (p->handle == mos_cfg_value_ah) {
        if (sd->state != BT_CFG_STATE_VALUE_ENTRY) {
          mbuf_free(&sd->value);
          mbuf_init(&sd->value, p->len);
          sd->state = BT_CFG_STATE_VALUE_ENTRY;
        }
        if (p->len == 1 && p->value[0] == 0) {
          mbuf_free(&sd->value);
          mbuf_init(&sd->value, 0);
        } else {
          mbuf_append(&sd->value, p->value, p->len);
        }
        LOG(LL_DEBUG, ("Value = '%.*s'", (int) sd->value.len,
                       (sd->value.buf ? sd->value.buf : "")));
        ret = true;
      } else if (p->handle == mos_cfg_save_ah) {
        sd->state = BT_CFG_STATE_SAVE;
        /* NULL value is a legal value, so we check for state here. */
        if (sd->key.len > 0 && sd->state != BT_CFG_STATE_VALUE_ENTRY) {
          ret = mgos_bt_svc_config_set(sd);
        } else {
          ret = true; /* Allow save and reboot without setting anything. */
        }
        if (ret) {
          if (p->len == 1 && (p->value[0] == '1' || p->value[0] == '2')) {
            char *msg = NULL;
            ret = save_cfg(&mgos_sys_config, &msg);
            if (!ret) {
              LOG(LL_ERROR, ("Error saving config: %s", msg));
            } else if (p->value[0] == '2') {
              mgos_system_restart_after(100);
            }
          }
        }
      }
      break;
    }
    case ESP_GATTS_DISCONNECT_EVT: {
      if (sd != NULL) {
        mbuf_free(&sd->key);
        mbuf_free(&sd->value);
        free(sd);
        bs->user_data = NULL;
      }
      break;
    }
    default:
      break;
  }
  return ret;
}

bool mgos_bt_service_config_init(void) {
  mgos_bt_gatts_register_service(
      mos_cfg_gatt_db, sizeof(mos_cfg_gatt_db) / sizeof(mos_cfg_gatt_db[0]),
      mgos_bt_svc_config_ev);
  return true;
}
