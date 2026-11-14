
/*
 * Copyright (C) Hanada
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#if (NGX_EXPR)
#include <ngx_http_expr_module.h>
#endif

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/rsa.h>
#include <openssl/ec.h>


#define NGX_HTTP_SECURE_LINK_SIGN_TIMESTAMP     1
#define NGX_HTTP_SECURE_LINK_SIGN_MSTIMESTAMP   2
#define NGX_HTTP_SECURE_LINK_SIGN_HEXTIMESTAMP  3
#define NGX_HTTP_SECURE_LINK_SIGN_DATE          4

#define NGX_HTTP_SECURE_LINK_SIGN_HEX           1
#define NGX_HTTP_SECURE_LINK_SIGN_BASE64URL     2
#define NGX_HTTP_SECURE_LINK_SIGN_BASE64        3
#define NGX_HTTP_SECURE_LINK_SIGN_BIN           4

typedef const EVP_MD *(*ngx_http_secure_link_sign_digest_pt)(void);


typedef struct {
    ngx_http_complex_value_t                *time;
    ngx_http_complex_value_t                *start;
    ngx_http_complex_value_t                *end;
    ngx_uint_t                               time_mode;
    ngx_str_t                                time_format;
    time_t                                   time_offset;
} ngx_http_secure_link_sign_time_conf_t;


typedef struct {
    ngx_http_complex_value_t                *token;
    ngx_uint_t                               token_digest;
} ngx_http_secure_link_sign_token_conf_t;


typedef struct {
    ngx_http_complex_value_t                 value;
    EVP_PKEY                                *pkey;
} ngx_http_secure_link_sign_key_t;


typedef struct {
    ngx_str_t                                name;
    int                                      type;
    ngx_http_secure_link_sign_digest_pt      digest;
    int                                      padding;
    ngx_uint_t                               p1363;
} ngx_http_secure_link_sign_algorithm_t;


typedef struct {
#if (NGX_EXPR)
    ngx_array_t                             *enable;
    ngx_array_t                             *time;
    ngx_array_t                             *token;
    ngx_array_t                             *message;
    ngx_array_t                             *public_key;
    ngx_array_t                             *algorithm;
#else
    ngx_flag_t                               enable;
    ngx_http_secure_link_sign_time_conf_t   *time;
    ngx_http_secure_link_sign_token_conf_t  *token;
    ngx_http_complex_value_t                *message;
    ngx_http_secure_link_sign_key_t         *public_key;
    ngx_http_secure_link_sign_algorithm_t   *algorithm;
#endif
} ngx_http_secure_link_sign_conf_t;


static ngx_int_t ngx_http_secure_link_sign_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t  *v, uintptr_t data);
static void *ngx_http_secure_link_sign_create_conf(ngx_conf_t *cf);
static char *ngx_http_secure_link_sign_merge_conf(ngx_conf_t *cf, void *parent,
    void  *child);

static ngx_int_t ngx_http_secure_link_sign_hex_decode(ngx_str_t *dst,
    ngx_str_t  *src);
static ngx_int_t ngx_http_secure_link_sign_parse_offset(ngx_str_t *value,
    time_t  *offset);
static ngx_int_t ngx_http_secure_link_sign_decode_base64(ngx_str_t *dst,
    ngx_str_t  *src, ngx_uint_t url);
static char *ngx_http_secure_link_sign_check_time(ngx_conf_t *cf,
    ngx_command_t  *cmd, void *conf);
static char *ngx_http_secure_link_sign_check_token(ngx_conf_t *cf,
    ngx_command_t  *cmd, void *conf);
static ngx_int_t ngx_http_secure_link_sign_add_variables(ngx_conf_t *cf);


static char *ngx_http_secure_link_sign_set_slot(ngx_conf_t *cf,
    ngx_command_t  *cmd, void *conf, void *value);
static char *ngx_http_secure_link_sign_public_key(ngx_conf_t *cf,
    ngx_command_t  *cmd, void *conf);
static char *ngx_http_secure_link_sign_algorithm(ngx_conf_t *cf,
    ngx_command_t  *cmd, void *conf);
static EVP_PKEY *ngx_http_secure_link_sign_read_key(ngx_pool_t *pool,
    ngx_str_t  *prefix, ngx_str_t *value, char **err);
static ngx_int_t ngx_http_secure_link_sign_check_expiration(
    ngx_http_request_t  *r, ngx_http_secure_link_sign_time_conf_t *time_conf);
static ngx_int_t ngx_http_secure_link_sign_verify(ngx_http_request_t *r,
    EVP_PKEY *key, ngx_http_secure_link_sign_algorithm_t *algorithm,
    ngx_http_secure_link_sign_token_conf_t  *token, ngx_str_t *message);


static ngx_command_t  ngx_http_secure_link_sign_commands[] = {

    { ngx_string("secure_link_sign"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF
#if (NGX_EXPR)
                        |NGX_HTTP_MAIN_WHEN_CONF|NGX_HTTP_SRV_WHEN_CONF
                        |NGX_HTTP_LOC_WHEN_CONF
#endif
                        |NGX_CONF_TAKE1,
#if (NGX_EXPR)
      ngx_conf_set_conditional_flag_slot,
#else
      ngx_conf_set_flag_slot,
#endif
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_secure_link_sign_conf_t, enable),
      NULL },

    { ngx_string("secure_link_sign_check_time"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF
#if (NGX_EXPR)
                        |NGX_HTTP_MAIN_WHEN_CONF|NGX_HTTP_SRV_WHEN_CONF
                        |NGX_HTTP_LOC_WHEN_CONF
#endif
                        |NGX_CONF_1MORE,
      ngx_http_secure_link_sign_check_time,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_secure_link_sign_conf_t, time),
      NULL },

    { ngx_string("secure_link_sign_check_token"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF
#if (NGX_EXPR)
                        |NGX_HTTP_MAIN_WHEN_CONF|NGX_HTTP_SRV_WHEN_CONF
                        |NGX_HTTP_LOC_WHEN_CONF
#endif
                        |NGX_CONF_TAKE12,
      ngx_http_secure_link_sign_check_token,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_secure_link_sign_conf_t, token),
      NULL },

    { ngx_string("secure_link_sign_message"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF
#if (NGX_EXPR)
                        |NGX_HTTP_MAIN_WHEN_CONF|NGX_HTTP_SRV_WHEN_CONF
                        |NGX_HTTP_LOC_WHEN_CONF
#endif
                        |NGX_CONF_TAKE1,
#if (NGX_EXPR)
      ngx_http_set_expr_complex_value_slot,
#else
      ngx_http_set_complex_value_slot,
#endif
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_secure_link_sign_conf_t, message),
      NULL },

    { ngx_string("secure_link_sign_public_key"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF
#if (NGX_EXPR)
                        |NGX_HTTP_MAIN_WHEN_CONF|NGX_HTTP_SRV_WHEN_CONF
                        |NGX_HTTP_LOC_WHEN_CONF
#endif
                        |NGX_CONF_TAKE1,
      ngx_http_secure_link_sign_public_key,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_secure_link_sign_conf_t, public_key),
      NULL },

    { ngx_string("secure_link_sign_algorithm"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF
#if (NGX_EXPR)
                        |NGX_HTTP_MAIN_WHEN_CONF|NGX_HTTP_SRV_WHEN_CONF
                        |NGX_HTTP_LOC_WHEN_CONF
#endif
                        |NGX_CONF_TAKE12,
      ngx_http_secure_link_sign_algorithm,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_secure_link_sign_conf_t, algorithm),
      NULL },

      ngx_null_command
};


static ngx_http_module_t  ngx_http_secure_link_sign_module_ctx = {
    ngx_http_secure_link_sign_add_variables,  /* preconfiguration */
    NULL,                                     /* postconfiguration */

    NULL,                                     /* create main configuration */
    NULL,                                     /* init main configuration */

    NULL,                                     /* create server conf */
    NULL,                                     /* merge server configuration */

    ngx_http_secure_link_sign_create_conf,    /* create location conf */
    ngx_http_secure_link_sign_merge_conf      /* merge location conf */
};


ngx_module_t  ngx_http_secure_link_sign_module = {
    NGX_MODULE_V1,
    &ngx_http_secure_link_sign_module_ctx,    /* module context */
    ngx_http_secure_link_sign_commands,       /* module directives */
    NGX_HTTP_MODULE,                          /* module type */
    NULL,                                     /* init master */
    NULL,                                     /* init module */
    NULL,                                     /* init process */
    NULL,                                     /* init thread */
    NULL,                                     /* exit thread */
    NULL,                                     /* exit process */
    NULL,                                     /* exit master */
    NGX_MODULE_V1_PADDING
};


static ngx_http_variable_t  ngx_http_secure_link_sign_vars[] = {

    { ngx_string("secure_link_sign"), NULL,
      ngx_http_secure_link_sign_variable,
      0, NGX_HTTP_VAR_CHANGEABLE|NGX_HTTP_VAR_NOCACHEABLE, 0 },

      ngx_http_null_variable
};


static ngx_http_secure_link_sign_algorithm_t
    ngx_http_secure_link_sign_algorithms[] =
{

    { ngx_string("rsa-sha256"), EVP_PKEY_RSA,
      EVP_sha256, RSA_PKCS1_PADDING, 0 },
    { ngx_string("rsa-sha1"), EVP_PKEY_RSA,
      EVP_sha1, RSA_PKCS1_PADDING, 0 },
    { ngx_string("rsa-sha384"), EVP_PKEY_RSA,
      EVP_sha384, RSA_PKCS1_PADDING, 0 },
    { ngx_string("rsa-sha512"), EVP_PKEY_RSA,
      EVP_sha512, RSA_PKCS1_PADDING, 0 },
    { ngx_string("rsa-pss-sha256"), EVP_PKEY_RSA,
      EVP_sha256, RSA_PKCS1_PSS_PADDING, 0 },
    { ngx_string("rsa-pss-sha384"), EVP_PKEY_RSA,
      EVP_sha384, RSA_PKCS1_PSS_PADDING, 0 },
    { ngx_string("rsa-pss-sha512"), EVP_PKEY_RSA,
      EVP_sha512, RSA_PKCS1_PSS_PADDING, 0 },
    { ngx_string("ecdsa-sha256"), EVP_PKEY_EC,
      EVP_sha256, 0, 0 },
    { ngx_string("ecdsa-sha384"), EVP_PKEY_EC,
      EVP_sha384, 0, 0 },
    { ngx_string("ecdsa-sha512"), EVP_PKEY_EC,
      EVP_sha512, 0, 0 },
    { ngx_string("ed25519"), EVP_PKEY_ED25519, NULL, 0, 0 },

    { ngx_null_string, 0, NULL, 0, 0 }
};


static ngx_int_t
ngx_http_secure_link_sign_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    char                                    *err;
    EVP_PKEY                                *pkey;
    ngx_int_t                                rc;
    ngx_str_t                                value, message;
    ngx_flag_t                               enable;
    ngx_http_complex_value_t                *message_conf;
    ngx_http_secure_link_sign_conf_t        *conf;
    ngx_http_secure_link_sign_time_conf_t   *time_conf;
    ngx_http_secure_link_sign_token_conf_t  *token_conf;
    ngx_http_secure_link_sign_key_t         *key;
    ngx_http_secure_link_sign_algorithm_t   *algorithm;

    conf = ngx_http_get_module_loc_conf(r, ngx_http_secure_link_sign_module);

#if (NGX_EXPR)
    enable = ngx_http_get_expr_flag_value(r, conf->enable);
    time_conf = ngx_http_get_expr_ptr_value(r, conf->time);
    token_conf = ngx_http_get_expr_ptr_value(r, conf->token);
    message_conf = ngx_http_get_expr_ptr_value(r, conf->message);
    key = ngx_http_get_expr_ptr_value(r, conf->public_key);
    algorithm = ngx_http_get_expr_ptr_value(r, conf->algorithm);
#else
    enable = conf->enable;
    time_conf = conf->time;
    token_conf = conf->token;
    message_conf = conf->message;
    key = conf->public_key;
    algorithm = conf->algorithm;
#endif

    if (enable != 1 || token_conf == NULL || message_conf == NULL
        || key == NULL || algorithm == NULL)
    {
        goto not_found;
    }

    rc = ngx_http_secure_link_sign_check_expiration(r, time_conf);
    if (rc == NGX_ERROR) {
        return NGX_ERROR;
    }

    if (rc != NGX_OK) {
        goto not_found;
    }

    if (ngx_http_complex_value(r, message_conf, &message) != NGX_OK) {
        return NGX_ERROR;
    }

    pkey = key->pkey;

    if (pkey == NULL) {
        if (ngx_http_complex_value(r, &key->value, &value) != NGX_OK) {
            return NGX_ERROR;
        }

        pkey = ngx_http_secure_link_sign_read_key(r->pool,
                                  (ngx_str_t *) &ngx_cycle->conf_prefix,
                                  &value, &err);
        if (pkey == NULL) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "secure link sign: %s", err);
            goto not_found;
        }
    }

    rc = ngx_http_secure_link_sign_verify(r, pkey, algorithm,
                                          token_conf, &message);

    if (key->pkey == NULL) {
        EVP_PKEY_free(pkey);
    }

    if (rc == NGX_ERROR) {
        return NGX_ERROR;
    }

    if (rc != NGX_OK) {
        goto not_found;
    }

    v->data = (u_char *) "1";
    v->len = 1;
    v->valid = 1;
    v->no_cacheable = 1;
    v->not_found = 0;

    return NGX_OK;

not_found:

    v->not_found = 1;
    v->no_cacheable = 1;

    return NGX_OK;
}


static ngx_int_t
ngx_http_secure_link_sign_check_expiration(ngx_http_request_t *r,
    ngx_http_secure_link_sign_time_conf_t *time_conf)
{
    char      *date, *last;
    time_t     timestamp, now, start, end;
    ngx_tm_t   tm;
    ngx_str_t  value;
    ngx_int_t  start_set, end_set;

    /* no time range is set, no check for expiration */
    if (time_conf == NULL
        || (time_conf->start == NULL && time_conf->end == NULL))
    {
        return NGX_OK;
    }

    start = 0;
    end = 0;
    start_set = (time_conf->start != NULL);
    end_set = (time_conf->end != NULL);

    if (start_set) {
        if (ngx_http_complex_value(r, time_conf->start, &value) != NGX_OK) {
            return NGX_ERROR;
        }

        if (ngx_http_secure_link_sign_parse_offset(&value, &start) != NGX_OK) {
            return NGX_DECLINED;
        }
    }

    if (end_set) {
        if (ngx_http_complex_value(r, time_conf->end, &value) != NGX_OK) {
            return NGX_ERROR;
        }

        if (ngx_http_secure_link_sign_parse_offset(&value, &end) != NGX_OK) {
            return NGX_DECLINED;
        }
    }

    /* invalid time range */
    if ((start_set == 0 && end_set == 0)
        || (start_set == 1 && end_set == 1 && start > end))
    {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "secure link sign: invalid time range");
        return NGX_DECLINED;
    }

    if (ngx_http_complex_value(r, time_conf->time, &value) != NGX_OK) {
        return NGX_ERROR;
    }

    if (value.len == 0) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "secure link sign: time is empty");
        return NGX_DECLINED;
    }

    if (time_conf->time_mode == NGX_HTTP_SECURE_LINK_SIGN_TIMESTAMP) {
        timestamp = ngx_atotm(value.data, value.len);

    } else if (time_conf->time_mode == NGX_HTTP_SECURE_LINK_SIGN_MSTIMESTAMP) {

        if (value.len < 4
            || ngx_atoi(value.data + value.len - 3, 3) == NGX_ERROR)
        {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "secure link sign: time len too short");
            return NGX_DECLINED;
        }

        /* cut off the milliseconds part */
        timestamp = ngx_atotm(value.data, value.len - 3);

    } else if (time_conf->time_mode == NGX_HTTP_SECURE_LINK_SIGN_HEXTIMESTAMP) {
        timestamp = (time_t) ngx_hextoi(value.data, value.len);

    } else { /* NGX_HTTP_SECURE_LINK_SIGN_DATE */
        ngx_memzero(&tm, sizeof(ngx_tm_t));

        date = ngx_pnalloc(r->pool, value.len + 1);
        if (date == NULL) {
            return NGX_ERROR;
        }

        ngx_memcpy(date, value.data, value.len);
        date[value.len] = '\0';

        last = strptime(date, (char *) time_conf->time_format.data, &tm);
        if (last != date + value.len) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "failed to parse date string");
            return NGX_ERROR;
        }

        /* Convert to unix_time */
        timestamp = timegm(&tm);

        if (timestamp == (time_t) NGX_ERROR) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "secure link sign: date conversion failed");
            return NGX_DECLINED;
        }

        if ((time_conf->time_offset > 0
             && timestamp < time_conf->time_offset)
            || (time_conf->time_offset < 0
                && timestamp > NGX_MAX_TIME_T_VALUE + time_conf->time_offset))
        {
            return NGX_DECLINED;
        }

        timestamp -= time_conf->time_offset;
    }

    if (timestamp <= 0) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "secure link sign: timestamp must be positive num");
        return NGX_DECLINED;
    }

    now = ngx_time();
    if ((start_set && now - timestamp < start)
        || (end_set && now - timestamp > end))
    {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "secure link sign: request not yet valid or expired");
        return NGX_DECLINED;
    }

    return NGX_OK;
}


static void *
ngx_http_secure_link_sign_create_conf(ngx_conf_t *cf)
{
    ngx_http_secure_link_sign_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_secure_link_sign_conf_t));
    if (conf == NULL) {
        return NULL;
    }

#if (NGX_EXPR)
    conf->enable = NGX_CONF_UNSET_PTR;
    conf->time = NGX_CONF_UNSET_PTR;
    conf->token = NGX_CONF_UNSET_PTR;
    conf->message = NGX_CONF_UNSET_PTR;
    conf->public_key = NGX_CONF_UNSET_PTR;
    conf->algorithm = NGX_CONF_UNSET_PTR;
#else
    conf->enable = NGX_CONF_UNSET;
    conf->time = NGX_CONF_UNSET_PTR;
    conf->token = NGX_CONF_UNSET_PTR;
    conf->message = NGX_CONF_UNSET_PTR;
    conf->public_key = NGX_CONF_UNSET_PTR;
    conf->algorithm = NGX_CONF_UNSET_PTR;
#endif

    return conf;
}


static char *
ngx_http_secure_link_sign_merge_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_secure_link_sign_conf_t  *prev = parent;
    ngx_http_secure_link_sign_conf_t  *conf = child;

#if (NGX_EXPR)
    if (ngx_conf_merge_expr_flag_value(cf, &conf->enable, prev->enable, 0)
        != NGX_OK
        || ngx_conf_merge_expr_ptr_value(cf, &conf->time, prev->time, NULL)
           != NGX_OK
        || ngx_conf_merge_expr_ptr_value(cf, &conf->token, prev->token, NULL)
           != NGX_OK
        || ngx_conf_merge_expr_ptr_value(cf, &conf->message,
                                         prev->message, NULL)
           != NGX_OK
        || ngx_conf_merge_expr_ptr_value(cf, &conf->public_key,
                                         prev->public_key, NULL)
           != NGX_OK
        || ngx_conf_merge_expr_ptr_value(cf, &conf->algorithm, prev->algorithm,
                                       &ngx_http_secure_link_sign_algorithms[0])
           != NGX_OK)
    {
        return NGX_CONF_ERROR;
    }
#else
    ngx_conf_merge_value(conf->enable, prev->enable, 0);
    ngx_conf_merge_ptr_value(conf->time, prev->time, NULL);
    ngx_conf_merge_ptr_value(conf->token, prev->token, NULL);
    ngx_conf_merge_ptr_value(conf->message, prev->message, NULL);
    ngx_conf_merge_ptr_value(conf->public_key, prev->public_key, NULL);
    ngx_conf_merge_ptr_value(conf->algorithm, prev->algorithm,
                            &ngx_http_secure_link_sign_algorithms[0]);
#endif

    return NGX_CONF_OK;
}


static ngx_int_t
ngx_http_secure_link_sign_parse_offset(ngx_str_t *value, time_t *offset)
{
    ngx_str_t   s;
    ngx_int_t   n;
    ngx_uint_t  negative;

    s = *value;
    if (s.len == 0) {
        return NGX_ERROR;
    }

    negative = (s.data[0] == '-');
    if (negative) {
        s.data++;
        s.len--;
    }

    if (s.len > 2 && s.data[0] == '0' && s.data[1] == 'x') {
        n = ngx_hextoi(s.data + 2, s.len - 2);
        if (n == NGX_ERROR || (uint64_t) n > NGX_MAX_TIME_T_VALUE) {
            return NGX_ERROR;
        }

        *offset = (time_t) n;

    } else {
        *offset = ngx_atotm(s.data, s.len);
        if (*offset == (time_t) NGX_ERROR) {
            return NGX_ERROR;
        }
    }

    if (negative) {
        *offset = -*offset;
    }

    return NGX_OK;
}


static char *
ngx_http_secure_link_sign_check_time(ngx_conf_t *cf,
    ngx_command_t *cmd, void *conf)
{
    time_t                                  time_offset, offset;
    ngx_str_t                               s, *value;
    ngx_uint_t                              i, j, format_set, timezone_set;
    ngx_http_compile_complex_value_t        ccv;
    ngx_http_secure_link_sign_time_conf_t  *time_conf;

    time_conf = ngx_pcalloc(cf->pool,
                            sizeof(ngx_http_secure_link_sign_time_conf_t));
    if (time_conf == NULL) {
        return NGX_CONF_ERROR;
    }

    format_set = 0;
    timezone_set = 0;
    time_conf->time_mode = NGX_HTTP_SECURE_LINK_SIGN_TIMESTAMP;
    ngx_str_set(&time_conf->time_format, "%s");

    value = cf->args->elts;

    ngx_memzero(&ccv, sizeof(ngx_http_compile_complex_value_t));

    ccv.cf = cf;
    ccv.value = &value[1];
    ccv.complex_value = ngx_palloc(cf->pool,
                                   sizeof(ngx_http_complex_value_t));
    if (ccv.complex_value == NULL) {
        return NGX_CONF_ERROR;
    }

    if (ngx_http_compile_complex_value(&ccv) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    time_conf->time = ccv.complex_value;

    for (i = 2; i < cf->args->nelts; i++) {

        if (value[i].len > 7
            && ngx_strncmp(value[i].data, "format=", 7) == 0)
        {
            if (format_set) {
                return "has a duplicate format parameter";
            }

            format_set = 1;

            s.len = value[i].len - 7;
            s.data = value[i].data + 7;

            if (s.len == 2 && s.data[0] == '%' && s.data[1] == 's') {
                time_conf->time_mode = NGX_HTTP_SECURE_LINK_SIGN_TIMESTAMP;
                continue;
            }

            if (s.len == 3 && s.data[0] == '%'
                && s.data[1] == 'm' && s.data[2] == 's')
            {
                time_conf->time_mode = NGX_HTTP_SECURE_LINK_SIGN_MSTIMESTAMP;
                continue;
            }

            if (s.len == 2 && s.data[0] == '%' && s.data[1] == 'x') {
                time_conf->time_mode = NGX_HTTP_SECURE_LINK_SIGN_HEXTIMESTAMP;
                continue;
            }

            time_conf->time_mode = NGX_HTTP_SECURE_LINK_SIGN_DATE;
            time_conf->time_format = s;

            continue;
        }

        if (value[i].len > 9
            && ngx_strncmp(value[i].data, "timezone=", 9) == 0)
        {
            if (timezone_set) {
                return "has a duplicate timezone parameter";
            }

            timezone_set = 1;

            s.len = value[i].len - 9;
            s.data = value[i].data + 9;

            if (s.len < 3 || ngx_strncmp(s.data, "gmt", 3) != 0) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "invalid timezone format");
                return NGX_CONF_ERROR;
            }

            if (s.len == 3) {
                time_conf->time_offset = 0;
                continue;
            }

            if (s.len != 8
                || (s.data[3] != '+' && s.data[3] != '-'))
            {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "invalid timezone format");
                return NGX_CONF_ERROR;
            }

            for (j = 4; j < 8; j++) {
                if (s.data[j] < '0' || s.data[j] > '9') {
                    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                       "invalid timezone value");
                    return NGX_CONF_ERROR;
                }
            }

            if (ngx_atoi(s.data + 4, 2) > 23
                || ngx_atoi(s.data + 6, 2) > 59)
            {
                return "has an invalid timezone offset";
            }

            /* Parse timezone offset, e.g., +0800 or -0200 */
            time_offset = ((s.data[4] - '0') * 10
                           + (s.data[5] - '0')) * 3600;
            time_offset += ((s.data[6] - '0') * 10
                            + (s.data[7] - '0')) * 60;

            if (s.data[3] == '-') {
                time_offset = -time_offset;
            }

            time_conf->time_offset = time_offset;

            continue;
        }

        if (value[i].len >= 12
            && ngx_strncmp(value[i].data, "range_start=", 12) == 0)
        {
            if (time_conf->start != NULL) {
                return "has a duplicate range_start parameter";
            }

            s.len = value[i].len - 12;
            s.data = value[i].data + 12;

            if (ngx_strlchr(s.data, s.data + s.len, '$') == NULL) {
                if (ngx_http_secure_link_sign_parse_offset(&s, &offset)
                    != NGX_OK)
                {
                    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                        "invalid numeric value in start parameter \"%V\"", &s);
                    return NGX_CONF_ERROR;
                }
            }

            ccv.cf = cf;
            ccv.value = &s;
            ccv.complex_value = ngx_palloc(cf->pool,
                                           sizeof(ngx_http_complex_value_t));
            if (ccv.complex_value == NULL) {
                return NGX_CONF_ERROR;
            }

            if (ngx_http_compile_complex_value(&ccv) != NGX_OK) {
                return NGX_CONF_ERROR;
            }

            time_conf->start = ccv.complex_value;

            continue;
        }

        if (value[i].len >= 10
            && ngx_strncmp(value[i].data, "range_end=", 10) == 0)
        {
            if (time_conf->end != NULL) {
                return "has a duplicate range_end parameter";
            }

            s.len = value[i].len - 10;
            s.data = value[i].data + 10;

            if (ngx_strlchr(s.data, s.data + s.len, '$') == NULL) {
                if (ngx_http_secure_link_sign_parse_offset(&s, &offset)
                    != NGX_OK)
                {
                    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                        "invalid numeric value in end parameter \"%V\"", &s);
                    return NGX_CONF_ERROR;
                }
            }

            ccv.cf = cf;
            ccv.value = &s;
            ccv.complex_value = ngx_palloc(cf->pool,
                                           sizeof(ngx_http_complex_value_t));
            if (ccv.complex_value == NULL) {
                return NGX_CONF_ERROR;
            }

            if (ngx_http_compile_complex_value(&ccv) != NGX_OK) {
                return NGX_CONF_ERROR;
            }

            time_conf->end = ccv.complex_value;
            continue;
        }

        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "invalid parameter \"%V\"", &value[i]);
        return NGX_CONF_ERROR;
    }

    return ngx_http_secure_link_sign_set_slot(cf, cmd, conf, time_conf);
}


static char *
ngx_http_secure_link_sign_check_token(ngx_conf_t *cf,
    ngx_command_t *cmd, void *conf)
{
    ngx_str_t                               *value;
    ngx_http_compile_complex_value_t         ccv;
    ngx_http_secure_link_sign_token_conf_t  *token_conf;

    token_conf = ngx_pcalloc(cf->pool,
                             sizeof(ngx_http_secure_link_sign_token_conf_t));
    if (token_conf == NULL) {
        return NGX_CONF_ERROR;
    }

    token_conf->token_digest = NGX_HTTP_SECURE_LINK_SIGN_BASE64;

    value = cf->args->elts;

    ngx_memzero(&ccv, sizeof(ngx_http_compile_complex_value_t));

    ccv.cf = cf;
    ccv.value = &value[1];
    ccv.complex_value = ngx_palloc(cf->pool,
                                   sizeof(ngx_http_complex_value_t));
    if (ccv.complex_value == NULL) {
        return NGX_CONF_ERROR;
    }

    if (ngx_http_compile_complex_value(&ccv) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    token_conf->token = ccv.complex_value;

    if (cf->args->nelts == 3) {

        if (value[2].len == 10
            && ngx_strncmp(value[2].data, "digest=hex", 10) == 0)
        {
            token_conf->token_digest = NGX_HTTP_SECURE_LINK_SIGN_HEX;

        } else if (value[2].len == 16
                   && ngx_strncmp(value[2].data, "digest=base64url", 16) == 0)
        {
            token_conf->token_digest = NGX_HTTP_SECURE_LINK_SIGN_BASE64URL;

        } else if (value[2].len == 13
                   && ngx_strncmp(value[2].data, "digest=base64", 13) == 0)
        {
            token_conf->token_digest = NGX_HTTP_SECURE_LINK_SIGN_BASE64;

        } else if (value[2].len == 10
                   && ngx_strncmp(value[2].data, "digest=bin", 10) == 0)
        {
            token_conf->token_digest = NGX_HTTP_SECURE_LINK_SIGN_BIN;

        } else {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "invalid token format: \"%V\"", &value[2]);
            return NGX_CONF_ERROR;
        }

    }

    return ngx_http_secure_link_sign_set_slot(cf, cmd, conf, token_conf);
}


static ngx_int_t
ngx_http_secure_link_sign_hex_decode(ngx_str_t *dst, ngx_str_t *src)
{
    size_t     i, half_len;
    u_char    *p;
    ngx_int_t  n;

    if (src->len % 2 != 0) {
        return NGX_ERROR;
    }

    half_len = src->len / 2;

    if (dst->len < half_len) {
        return NGX_ERROR;
    }

    p = src->data;
    for (i = 0; i < half_len; i++) {

        n = ngx_hextoi(p, 2);
        if (n == NGX_ERROR || n > 255) {
            return NGX_ERROR;
        }

        dst->data[i] = (u_char) n;
        p += 2;
    }

    dst->len = half_len;

    return NGX_OK;
}


static ngx_int_t
ngx_http_secure_link_sign_add_variables(ngx_conf_t *cf)
{
    ngx_http_variable_t  *var, *v;

    for (v = ngx_http_secure_link_sign_vars; v->name.len; v++) {
        var = ngx_http_add_variable(cf, &v->name, v->flags);
        if (var == NULL) {
            return NGX_ERROR;
        }

        var->get_handler = v->get_handler;
        var->data = v->data;
    }

    return NGX_OK;
}


static EVP_PKEY *
ngx_http_secure_link_sign_read_key(ngx_pool_t *pool, ngx_str_t *prefix,
    ngx_str_t *value, char **err)
{
    u_char    *p;
    BIO       *bio;
    EVP_PKEY  *key;
    ngx_str_t  path;

    *err = "invalid public key";

    if (value->len == 0 || value->len > INT_MAX
        || ngx_strlchr(value->data, value->data + value->len, '\0') != NULL)
    {
        return NULL;
    }

    ERR_clear_error();

    if (value->len > 5 && ngx_strncmp(value->data, "data:", 5) == 0) {
        bio = BIO_new_mem_buf(value->data + 5, (int) (value->len - 5));

    } else {
        path = *value;

        if (ngx_get_full_name(pool, prefix, &path) != NGX_OK) {
            return NULL;
        }

        p = ngx_pnalloc(pool, path.len + 1);
        if (p == NULL) {
            return NULL;
        }

        ngx_memcpy(p, path.data, path.len);
        p[path.len] = '\0';
        bio = BIO_new_file((char *) p, "r");
    }

    if (bio == NULL) {
        *err = "could not open public key";
        ERR_clear_error();
        return NULL;
    }

    key = PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL);
    BIO_free(bio);
    ERR_clear_error();

    if (key == NULL) {
        *err = "could not parse PEM public key";
    }

    return key;
}


static void
ngx_http_secure_link_sign_free_key(void *data)
{
    EVP_PKEY_free(data);
}


static char *
ngx_http_secure_link_sign_set_slot(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf, void *value)
{
#if (NGX_EXPR)
    ngx_array_t             **slot;
    ngx_expr_when_id_t        expr_id;
    ngx_conf_expr_ptr_ctx_t  *ctx;

    slot = (ngx_array_t **) ((u_char *) conf + cmd->offset);
    expr_id = ngx_expr_get_associated_when_id(cf);

    if (*slot != NULL && *slot != NGX_CONF_UNSET_PTR) {
        if (ngx_expr_find_ctx(*slot, expr_id,
                              sizeof(ngx_conf_expr_ptr_ctx_t),
                              offsetof(ngx_conf_expr_ptr_ctx_t, expr_id))
            != NULL)
        {
            return "is duplicate";
        }

    } else {
        *slot = ngx_array_create(cf->pool, 2, sizeof(ngx_conf_expr_ptr_ctx_t));
        if (*slot == NULL) {
            return NGX_CONF_ERROR;
        }
    }

    ctx = ngx_array_push(*slot);
    if (ctx == NULL) {
        return NGX_CONF_ERROR;
    }

    ctx->value = value;
    ctx->expr_id = expr_id;
#else
    void  **slot;

    slot = (void **) ((u_char *) conf + cmd->offset);

    if (*slot != NULL && *slot != NGX_CONF_UNSET_PTR) {
        return "is duplicate";
    }

    *slot = value;
#endif

    return NGX_CONF_OK;
}


static char *
ngx_http_secure_link_sign_public_key(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf)
{
    char                             *err;
    ngx_str_t                        *value;
    ngx_pool_cleanup_t               *cln;
    ngx_http_compile_complex_value_t  ccv;
    ngx_http_secure_link_sign_key_t  *key;

    value = cf->args->elts;
    key = ngx_pcalloc(cf->pool, sizeof(ngx_http_secure_link_sign_key_t));
    if (key == NULL) {
        return NGX_CONF_ERROR;
    }

    ngx_memzero(&ccv, sizeof(ngx_http_compile_complex_value_t));
    ccv.cf = cf;
    ccv.value = &value[1];
    ccv.complex_value = &key->value;

    if (ngx_http_compile_complex_value(&ccv) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    if (key->value.lengths == NULL) {
        key->pkey = ngx_http_secure_link_sign_read_key(cf->pool,
                                    &cf->cycle->conf_prefix, &value[1], &err);
        if (key->pkey == NULL) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "secure link sign: %s", err);
            return NGX_CONF_ERROR;
        }

        cln = ngx_pool_cleanup_add(cf->pool, 0);
        if (cln == NULL) {
            EVP_PKEY_free(key->pkey);
            return NGX_CONF_ERROR;
        }

        cln->handler = ngx_http_secure_link_sign_free_key;
        cln->data = key->pkey;
    }

    return ngx_http_secure_link_sign_set_slot(cf, cmd, conf, key);
}


static char *
ngx_http_secure_link_sign_algorithm(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf)
{
    ngx_str_t                              *value;
    ngx_uint_t                              i;
    ngx_http_secure_link_sign_algorithm_t  *algorithm;

    value = cf->args->elts;

    for (i = 0; ngx_http_secure_link_sign_algorithms[i].name.len; i++) {
        algorithm = &ngx_http_secure_link_sign_algorithms[i];

        if (value[1].len == algorithm->name.len
            && ngx_strncmp(value[1].data, algorithm->name.data,
                           value[1].len) == 0)
        {
            break;
        }
    }

    if (ngx_http_secure_link_sign_algorithms[i].name.len == 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "invalid signature algorithm \"%V\"", &value[1]);
        return NGX_CONF_ERROR;
    }

    algorithm = ngx_palloc(cf->pool,
                          sizeof(ngx_http_secure_link_sign_algorithm_t));
    if (algorithm == NULL) {
        return NGX_CONF_ERROR;
    }

    *algorithm = ngx_http_secure_link_sign_algorithms[i];

    if (cf->args->nelts == 3) {
        if (algorithm->type != EVP_PKEY_EC) {
            return "supports format= only with ECDSA";
        }

        if (ngx_strcmp(value[2].data, "format=ieee-p1363") == 0) {
            algorithm->p1363 = 1;

        } else if (ngx_strcmp(value[2].data, "format=der") != 0) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "invalid parameter \"%V\"", &value[2]);
            return NGX_CONF_ERROR;
        }
    }

    return ngx_http_secure_link_sign_set_slot(cf, cmd, conf, algorithm);
}


static ngx_int_t
ngx_http_secure_link_sign_decode_base64(ngx_str_t *dst, ngx_str_t *src,
    ngx_uint_t url)
{
    u_char     c;
    size_t     i, len, padding, decoded;
    ngx_int_t  n;

    if (src->len == 0 || src->len > ngx_base64_encoded_length(dst->len)) {
        return NGX_ERROR;
    }

    len = src->len;

    while (len && src->data[len - 1] == '=') {
        len--;
    }

    padding = src->len - len;

    if (len == 0 || len % 4 == 1 || padding > 2
        || (padding && (src->len % 4 != 0 || padding != (4 - len % 4))))
    {
        return NGX_ERROR;
    }

    decoded = len / 4 * 3 + (len % 4 ? len % 4 - 1 : 0);
    if (decoded > dst->len) {
        return NGX_ERROR;
    }

    n = 0;

    for (i = 0; i < len; i++) {
        c = src->data[i];

        if (c >= 'A' && c <= 'Z') {
            n = c - 'A';

        } else if (c >= 'a' && c <= 'z') {
            n = c - 'a' + 26;

        } else if (c >= '0' && c <= '9') {
            n = c - '0' + 52;

        } else if (c == (url ? '-' : '+')) {
            n = 62;

        } else if (c == (url ? '_' : '/')) {
            n = 63;

        } else {
            return NGX_ERROR;
        }
    }

    if ((len % 4 == 2 && (n & 15)) || (len % 4 == 3 && (n & 3))) {
        return NGX_ERROR;
    }

    return url ? ngx_decode_base64url(dst, src) : ngx_decode_base64(dst, src);
}


static ngx_int_t
ngx_http_secure_link_sign_p1363(ngx_http_request_t *r, EVP_PKEY *key,
    ngx_str_t *signature)
{
    int         len;
    size_t      size;
    u_char     *p;
    BIGNUM     *x, *y;
    ECDSA_SIG  *sig;

    size = (EVP_PKEY_bits(key) + 7) / 8;

    if (size == 0 || signature->len != size * 2) {
        return NGX_DECLINED;
    }

    sig = ECDSA_SIG_new();
    if (sig == NULL) {
        return NGX_ERROR;
    }

    x = BN_bin2bn(signature->data, (int) size, NULL);
    y = BN_bin2bn(signature->data + size, (int) size, NULL);

    if (x == NULL || y == NULL || ECDSA_SIG_set0(sig, x, y) != 1) {
        BN_free(x);
        BN_free(y);
        ECDSA_SIG_free(sig);
        return NGX_ERROR;
    }

    len = i2d_ECDSA_SIG(sig, NULL);
    if (len <= 0) {
        ECDSA_SIG_free(sig);
        return NGX_ERROR;
    }

    p = ngx_pnalloc(r->pool, len);
    if (p == NULL) {
        ECDSA_SIG_free(sig);
        return NGX_ERROR;
    }

    signature->data = p;
    signature->len = len;
    len = i2d_ECDSA_SIG(sig, &p);
    ECDSA_SIG_free(sig);

    return len == (int) signature->len ? NGX_OK : NGX_ERROR;
}


static ngx_int_t
ngx_http_secure_link_sign_verify(ngx_http_request_t *r, EVP_PKEY *key,
    ngx_http_secure_link_sign_algorithm_t *algorithm,
    ngx_http_secure_link_sign_token_conf_t *token, ngx_str_t *message)
{
    int            size, type, result;
    ngx_int_t      rc;
    ngx_str_t      value, signature;
    const EVP_MD  *md;
    EVP_MD_CTX    *ctx;
    EVP_PKEY_CTX  *pctx;

    type = EVP_PKEY_base_id(key);

    if (type != algorithm->type
        && !(type == EVP_PKEY_RSA_PSS && algorithm->type == EVP_PKEY_RSA
             && algorithm->padding == RSA_PKCS1_PSS_PADDING))
    {
        return NGX_DECLINED;
    }

    size = EVP_PKEY_size(key);
    if (size <= 0) {
        return NGX_DECLINED;
    }

    if (ngx_http_complex_value(r, token->token, &value) != NGX_OK) {
        return NGX_ERROR;
    }

    if (value.len == 0) {
        return NGX_DECLINED;
    }

    if (token->token_digest == NGX_HTTP_SECURE_LINK_SIGN_BIN) {
        if (value.len > (size_t) size) {
            return NGX_DECLINED;
        }

        signature = value;

    } else {
        if (value.len > (size_t) size * 2) {
            return NGX_DECLINED;
        }

        signature.len = size;
        signature.data = ngx_pnalloc(r->pool, size);
        if (signature.data == NULL) {
            return NGX_ERROR;
        }

        if (token->token_digest == NGX_HTTP_SECURE_LINK_SIGN_HEX) {
            rc = ngx_http_secure_link_sign_hex_decode(&signature, &value);

        } else {
            rc = ngx_http_secure_link_sign_decode_base64(&signature, &value,
                   token->token_digest == NGX_HTTP_SECURE_LINK_SIGN_BASE64URL);
        }

        if (rc != NGX_OK) {
            return NGX_DECLINED;
        }
    }

    if (algorithm->p1363) {
        rc = ngx_http_secure_link_sign_p1363(r, key, &signature);
        if (rc != NGX_OK) {
            return rc;
        }
    }

    ctx = EVP_MD_CTX_new();
    if (ctx == NULL) {
        return NGX_ERROR;
    }

    rc = NGX_DECLINED;
    md = algorithm->digest ? algorithm->digest() : NULL;

    if (EVP_DigestVerifyInit(ctx, &pctx, md, NULL, key) != 1) {
        goto done;
    }

    if (algorithm->type == EVP_PKEY_RSA) {
        if (EVP_PKEY_CTX_set_rsa_padding(pctx, algorithm->padding) <= 0) {
            goto done;
        }

        if (algorithm->padding == RSA_PKCS1_PSS_PADDING
            && (EVP_PKEY_CTX_set_rsa_pss_saltlen(pctx,
                                               RSA_PSS_SALTLEN_DIGEST) <= 0
                || EVP_PKEY_CTX_set_rsa_mgf1_md(pctx, md) <= 0))
        {
            goto done;
        }
    }

    result = EVP_DigestVerify(ctx, signature.data, signature.len,
                             message->data, message->len);
    if (result == 1) {
        rc = NGX_OK;
    }

done:

    EVP_MD_CTX_free(ctx);
    ERR_clear_error();

    return rc;
}
