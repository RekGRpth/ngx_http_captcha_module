#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_md5.h>
#include <gd.h>

#define M_PI 3.14159265358979323846
#define CAPTCHA_CHARSET "abcdefghkmnprstuvwxyzABCDEFGHKMNPRSTUVWXYZ23456789"
#define CAPTCHA_LENGTH 4
#define CAPTCHA_FONT "/usr/share/fonts/ttf-liberation/LiberationSans-Regular.ttf"
#define CAPTCHA_HASH "captcha_hash"
#define CAPTCHA_HEIGHT 30
#define CAPTCHA_SALT "captcha_salt"
#define CAPTCHA_SECRET "captcha_secret"
#define CAPTCHA_SIZE 20
#define CAPTCHA_WIDTH 130
#define CAPTCHA_LINE 6
#define CAPTCHA_STAR 100
#define MD5_BHASH_LEN 16
#define MD5_HASH_LEN (MD5_BHASH_LEN * 2)

typedef struct {
    ngx_uint_t height;
    ngx_uint_t length;
    ngx_uint_t size;
    ngx_uint_t width;
    ngx_str_t charset;
    ngx_str_t font;
    ngx_str_t hash;
    ngx_str_t salt;
    ngx_str_t secret;
} ngx_http_captcha_loc_conf_t;

static char *ngx_http_captcha_conf(ngx_conf_t *, ngx_command_t *, void *);
static void *ngx_http_captcha_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_captcha_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child);

static ngx_command_t ngx_http_captcha_commands[] = {{
    ngx_string("captcha"),
    NGX_HTTP_LOC_CONF | NGX_CONF_NOARGS,
    ngx_http_captcha_conf,
    NGX_HTTP_LOC_CONF_OFFSET,
    0,
    NULL
}, {
    ngx_string("captcha_height"),
    NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
    ngx_conf_set_num_slot,
    NGX_HTTP_LOC_CONF_OFFSET,
    offsetof(ngx_http_captcha_loc_conf_t, height),
    NULL
}, {
    ngx_string("captcha_length"),
    NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
    ngx_conf_set_num_slot,
    NGX_HTTP_LOC_CONF_OFFSET,
    offsetof(ngx_http_captcha_loc_conf_t, length),
    NULL
}, {
    ngx_string("captcha_size"),
    NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
    ngx_conf_set_num_slot,
    NGX_HTTP_LOC_CONF_OFFSET,
    offsetof(ngx_http_captcha_loc_conf_t, size),
    NULL
}, {
    ngx_string("captcha_width"),
    NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
    ngx_conf_set_num_slot,
    NGX_HTTP_LOC_CONF_OFFSET,
    offsetof(ngx_http_captcha_loc_conf_t, width),
    NULL
}, {
    ngx_string("captcha_charset"),
    NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
    ngx_conf_set_str_slot,
    NGX_HTTP_LOC_CONF_OFFSET,
    offsetof(ngx_http_captcha_loc_conf_t, charset),
    NULL
}, {
    ngx_string("captcha_font"),
    NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
    ngx_conf_set_str_slot,
    NGX_HTTP_LOC_CONF_OFFSET,
    offsetof(ngx_http_captcha_loc_conf_t, font),
    NULL
}, {
    ngx_string("captcha_hash"),
    NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
    ngx_conf_set_str_slot,
    NGX_HTTP_LOC_CONF_OFFSET,
    offsetof(ngx_http_captcha_loc_conf_t, hash),
    NULL
}, {
    ngx_string("captcha_salt"),
    NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
    ngx_conf_set_str_slot,
    NGX_HTTP_LOC_CONF_OFFSET,
    offsetof(ngx_http_captcha_loc_conf_t, salt),
    NULL
}, {
    ngx_string("captcha_secret"),
    NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
    ngx_conf_set_str_slot,
    NGX_HTTP_LOC_CONF_OFFSET,
    offsetof(ngx_http_captcha_loc_conf_t, secret),
    NULL
}, ngx_null_command};

static ngx_http_module_t ngx_http_captcha_module_ctx = {
    NULL,                             /* preconfiguration */
    NULL,                             /* postconfiguration */
    NULL,                             /* create main configuration */
    NULL,                             /* init main configuration */
    NULL,                             /* create server configuration */
    NULL,                             /* merge server configuration */
    ngx_http_captcha_create_loc_conf, /* create location configuration */
    ngx_http_captcha_merge_loc_conf   /* merge location configuration */
};

ngx_module_t ngx_http_captcha_module = {
    NGX_MODULE_V1,
    &ngx_http_captcha_module_ctx, /* module context */
    ngx_http_captcha_commands,    /* module directives */
    NGX_HTTP_MODULE,              /* module type */
    NULL,                         /* init master */
    NULL,                         /* init module */
    NULL,                         /* init process */
    NULL,                         /* init thread */
    NULL,                         /* exit thread */
    NULL,                         /* exit process */
    NULL,                         /* exit master */
    NGX_MODULE_V1_PADDING
};

static inline int mt_rand(int min, int max) {
    return (ngx_random() % (max - min + 1)) + min;
}

static inline void create_code(char *code, int code_len, char *charset, int charset_len) {
    for (int i=0; i < code_len; i++) code[i] = charset[mt_rand(0, charset_len - 1)];
    code[code_len] = '\0';
}

static inline u_char *create_captcha_png(ngx_http_request_t *r, int *size, char *code) {
    ngx_http_captcha_loc_conf_t *captcha = ngx_http_get_module_loc_conf(r, ngx_http_captcha_module);
    gdImagePtr img = gdImageCreateTrueColor(captcha->width, captcha->height);
    (void)gdImageFilledRectangle(img, 0, captcha->height, captcha->width, 0, gdImageColorAllocate(img, mt_rand(157, 255), mt_rand(157, 255), mt_rand(157, 255)));
    for (int i = 0, brect[8], x = captcha->width / captcha->length; i < (int)captcha->length; i++) {
        char str[2] = {*code++, '\0'};
        (char *)gdImageStringFT(img, brect, gdImageColorAllocate(img, mt_rand(0, 156), mt_rand(0, 156), mt_rand(0, 156)), (char *)captcha->font.data, captcha->size, mt_rand(-30, 30) * (M_PI / 180), x * i + mt_rand(1, 5), captcha->height / 1.4, str);
    }
    for (int i = 0; i < CAPTCHA_LINE; i++) {
        (void)gdImageLine(img, mt_rand(0, captcha->width), mt_rand(0, captcha->height), mt_rand(0, captcha->width), mt_rand(0, captcha->height), gdImageColorAllocate(img, mt_rand(0, 156), mt_rand(0, 156), mt_rand(0, 156)));
    }
    for (int i = 0, brect[8]; i < CAPTCHA_STAR; i++) {
        (char *)gdImageStringFT(img, brect, gdImageColorAllocate(img, mt_rand(200, 255), mt_rand(200, 255), mt_rand(200, 255)), (char *)captcha->font.data, 8, 0, mt_rand(0, captcha->width), mt_rand(0, captcha->height), "*");
    }
    u_char *out = (u_char *)gdImagePngPtrEx(img, size, -1);
    (void)gdImageDestroy(img);
    return out;
}

static inline ngx_int_t set_captcha_cookie(ngx_http_request_t *r, char *code) {
    ngx_http_captcha_loc_conf_t *captcha = ngx_http_get_module_loc_conf(r, ngx_http_captcha_module);
    ngx_md5_t md5;
    ngx_md5_init(&md5);
    ngx_md5_update(&md5, (const void *)captcha->secret.data, captcha->secret.len);
    ngx_md5_update(&md5, (const void *)code, (size_t)captcha->length);
    u_char salt_buf[32];
    size_t salt_buf_len = ngx_sprintf(salt_buf, "%d", ngx_random()) - salt_buf;
    ngx_md5_update(&md5, (const void *)salt_buf, salt_buf_len);
    u_char bhash[MD5_BHASH_LEN];
    ngx_md5_final(bhash, &md5);
    u_char hash[MD5_HASH_LEN];
    ngx_hex_dump(hash, bhash, MD5_BHASH_LEN);
    ngx_table_elt_t *set_cookie_hash = ngx_list_push(&r->headers_out.headers);
    ngx_table_elt_t *set_cookie_salt = ngx_list_push(&r->headers_out.headers);
    if (set_cookie_hash == NULL || set_cookie_salt == NULL) return NGX_ERROR;
    /* set_cookie_hash */ {
        set_cookie_hash->hash = 1;
        ngx_str_set(&set_cookie_hash->key, "Set-Cookie");
        int cookie_buf_len = captcha->hash.len + MD5_HASH_LEN + 1;
        set_cookie_hash->value.data = ngx_palloc(r->pool, cookie_buf_len);
        if (set_cookie_hash->value.data == NULL) return NGX_ERROR;
        /*ngx_sprintf(set_cookie_hash->value.data, "%s=%s", ...);*/
        unsigned char *p = set_cookie_hash->value.data;
        p = ngx_cpymem(p, captcha->hash.data, captcha->hash.len);
        *p++ = '=';
        p = ngx_cpymem(p, hash, MD5_HASH_LEN);
        set_cookie_hash->value.len = cookie_buf_len;
    }
    /* set_cookie_salt */ {
        set_cookie_salt->hash = 1;
        ngx_str_set(&set_cookie_salt->key, "Set-Cookie");
        int cookie_buf_len = captcha->salt.len + salt_buf_len + 1;
        set_cookie_salt->value.data = ngx_palloc(r->pool, cookie_buf_len);
        if (set_cookie_salt->value.data == NULL) return NGX_ERROR;
        /*ngx_sprintf(set_cookie_salt->value.data, "%s=%s", ...);*/
        unsigned char *p = set_cookie_salt->value.data;
        p = ngx_cpymem(p, captcha->salt.data, captcha->salt.len);
        *p++ = '=';
        p = ngx_cpymem(p, salt_buf, salt_buf_len);
        set_cookie_salt->value.len = cookie_buf_len;
    }
    return NGX_OK;
}

static ngx_int_t ngx_http_captcha_handler(ngx_http_request_t *r) {
    if (!(r->method & (NGX_HTTP_GET|NGX_HTTP_HEAD))) return NGX_HTTP_NOT_ALLOWED;
    ngx_int_t rc = ngx_http_discard_request_body(r);
    if (rc != NGX_OK && rc != NGX_AGAIN) return rc;
    r->headers_out.content_type.len = sizeof("image/png") - 1;
    r->headers_out.content_type.data = (u_char *)"image/png";
    ngx_http_captcha_loc_conf_t *captcha = ngx_http_get_module_loc_conf(r, ngx_http_captcha_module);
    u_char code[CAPTCHA_LENGTH+1];// = {"\0"};
    create_code((char *)code, captcha->length, (char *)captcha->charset.data, captcha->charset.len);
    rc = set_captcha_cookie(r, (char *)code);
    if (rc != NGX_OK) return rc;
    r->headers_out.status = NGX_HTTP_OK;
    r->headers_out.content_length_n = 0;
    if (r->method == NGX_HTTP_HEAD) {
        rc = ngx_http_send_header(r);
        if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) return rc;
    }
    int size;
    u_char *img_buf = create_captcha_png(r, &size, (char *)code);
    if (img_buf == NULL) size = 0; else {
        ngx_pool_cleanup_t *cln = ngx_pool_cleanup_add(r->pool, 0);;
        cln = ngx_pool_cleanup_add(r->pool, 0);
        if (cln == NULL) {
            gdFree(img_buf);
            return NGX_ERROR;
        }
        cln->handler = gdFree;
        cln->data = img_buf;
    }
    ngx_buf_t b = {.pos = (u_char *)img_buf, .last = (u_char *)img_buf + size, .memory = 1, .last_buf = 1};
    ngx_chain_t out = {.buf = &b, .next = NULL};
    r->headers_out.content_length_n = size;
    rc = ngx_http_send_header(r);
    if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) return rc;
    return ngx_http_output_filter(r, &out);
}

static char *ngx_http_captcha_conf(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {
    ngx_http_core_loc_conf_t *clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
    clcf->handler = ngx_http_captcha_handler;
    ngx_conf_set_num_slot(cf, cmd, conf);
    return NGX_CONF_OK;
}

static void *ngx_http_captcha_create_loc_conf(ngx_conf_t *cf) {
    ngx_http_captcha_loc_conf_t *conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_captcha_loc_conf_t));
    if (conf == NULL) return NGX_CONF_ERROR;
    conf->width = NGX_CONF_UNSET_UINT;
    conf->height = NGX_CONF_UNSET_UINT;
    conf->length = NGX_CONF_UNSET_UINT;
    conf->size = NGX_CONF_UNSET_UINT;
    conf->font.data = NULL;
    conf->font.len = 0;
    conf->charset.data = NULL;
    conf->charset.len = 0;
    conf->hash.data = NULL;
    conf->hash.len = 0;
    conf->salt.data = NULL;
    conf->salt.len = 0;
    conf->secret.data = NULL;
    conf->secret.len = 0;
    return conf;
}

static char *ngx_http_captcha_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child) {
    ngx_http_captcha_loc_conf_t *prev = parent;
    ngx_http_captcha_loc_conf_t *conf = child;
    ngx_conf_merge_uint_value(conf->height, prev->height, CAPTCHA_HEIGHT);
    ngx_conf_merge_uint_value(conf->length, prev->length, CAPTCHA_LENGTH);
    ngx_conf_merge_uint_value(conf->size, prev->size, CAPTCHA_SIZE);
    ngx_conf_merge_uint_value(conf->width, prev->width, CAPTCHA_WIDTH);
    ngx_conf_merge_str_value(conf->charset, prev->charset, CAPTCHA_CHARSET);
    ngx_conf_merge_str_value(conf->font, prev->font, CAPTCHA_FONT);
    ngx_conf_merge_str_value(conf->hash, prev->hash, CAPTCHA_HASH);
    ngx_conf_merge_str_value(conf->salt, prev->salt, CAPTCHA_SALT);
    ngx_conf_merge_str_value(conf->secret, prev->secret, CAPTCHA_SECRET);
    if (conf->size > conf->height) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "size is too large");
        return NGX_CONF_ERROR;
    }
    if (conf->hash.len == 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "hash cannot be empty");
        return NGX_CONF_ERROR;
    }
    if (conf->salt.len == 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "salt cannot be empty");
        return NGX_CONF_ERROR;
    }
    if (conf->secret.len == 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "secret cannot be empty");
        return NGX_CONF_ERROR;
    }
    if (conf->font.len == 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "font cannot be empty");
        return NGX_CONF_ERROR;
    }
    if (conf->charset.len == 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "charset cannot be empty");
        return NGX_CONF_ERROR;
    }
    return NGX_CONF_OK;
}
