#include <ngx_http.h>
#include <ngx_md5.h>
#include <gd.h>

#define M_PI 3.14159265358979323846
#define CAPTCHA_LINE 6
#define CAPTCHA_STAR 100
#define MD5_BHASH_LEN 16
#define MD5_HASH_LEN (MD5_BHASH_LEN * 2)

typedef struct {
    ngx_flag_t icase;
    ngx_str_t charset;
    ngx_str_t csrf;
    ngx_str_t font;
    ngx_str_t name;
    ngx_str_t secret;
    ngx_uint_t expire;
    ngx_uint_t height;
    ngx_uint_t length;
    ngx_uint_t size;
    ngx_uint_t width;
} ngx_http_captcha_loc_conf_t;

ngx_module_t ngx_http_captcha_module;

static int mt_rand(int min, int max) {
    return (ngx_random() % (max - min + 1)) + min;
}

static u_char *create_code(ngx_http_request_t *r) {
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "captcha: %s", __func__);
    ngx_http_captcha_loc_conf_t *conf = ngx_http_get_module_loc_conf(r, ngx_http_captcha_module);
    u_char *code = ngx_pnalloc(r->pool, conf->length + 1);
    if (!code) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "captcha: %s:%d", __FILE__, __LINE__); return NULL; }
    for (size_t i = 0; i < conf->length; i++) code[i] = conf->charset.data[mt_rand(0, conf->charset.len - 1)];
    code[conf->length] = '\0';
    return code;
}

static u_char *create_captcha_png(ngx_http_request_t *r, int *size, u_char *code) {
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "captcha: %s", __func__);
    ngx_http_captcha_loc_conf_t *conf = ngx_http_get_module_loc_conf(r, ngx_http_captcha_module);
    gdFTUseFontConfig(1);
    gdImagePtr img = gdImageCreateTrueColor(conf->width, conf->height);
    (void)gdImageFilledRectangle(img, 0, conf->height, conf->width, 0, gdImageColorAllocate(img, mt_rand(157, 255), mt_rand(157, 255), mt_rand(157, 255)));
    for (int i = 0, brect[8], x = conf->width / conf->length; i < (int)conf->length; i++) {
        char str[2] = {*code++, '\0'};
        (char *)gdImageStringFT(img, brect, gdImageColorAllocate(img, mt_rand(0, 156), mt_rand(0, 156), mt_rand(0, 156)), (char *)conf->font.data, conf->size, mt_rand(-30, 30) * (M_PI / 180), x * i + mt_rand(1, 5), conf->height / 1.4, str);
    }
    for (int i = 0; i < CAPTCHA_LINE; i++) {
        (void)gdImageLine(img, mt_rand(0, conf->width), mt_rand(0, conf->height), mt_rand(0, conf->width), mt_rand(0, conf->height), gdImageColorAllocate(img, mt_rand(0, 156), mt_rand(0, 156), mt_rand(0, 156)));
    }
    for (int i = 0, brect[8]; i < CAPTCHA_STAR; i++) {
        (char *)gdImageStringFT(img, brect, gdImageColorAllocate(img, mt_rand(200, 255), mt_rand(200, 255), mt_rand(200, 255)), (char *)conf->font.data, 8, 0, mt_rand(0, conf->width), mt_rand(0, conf->height), "*");
    }
    u_char *out = (u_char *)gdImagePngPtrEx(img, size, -1);
    (void)gdImageDestroy(img);
    return out;
}

static ngx_int_t set_captcha_cookie(ngx_http_request_t *r, u_char *code) {
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "captcha: %s", __func__);
    ngx_http_captcha_loc_conf_t *conf = ngx_http_get_module_loc_conf(r, ngx_http_captcha_module);
    ngx_str_t csrf_var;
/*    csrf_var.len = conf->csrf.len + sizeof("cookie_%V") - 1 - 2;
    if (!(csrf_var.data = ngx_pnalloc(r->pool, csrf_var.len))) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "captcha: %s:%d", __FILE__, __LINE__); return NGX_ERROR; }
    if (ngx_snprintf(csrf_var.data, csrf_var.len, "cookie_%V", &conf->csrf) != csrf_var.data + csrf_var.len) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "captcha: %s:%d", __FILE__, __LINE__); return NGX_ERROR; }
    ngx_http_variable_value_t *csrf = ngx_http_get_variable(r, &csrf_var, ngx_hash_key(csrf_var.data, csrf_var.len));
    if (!csrf || !csrf->data || !csrf->len) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "captcha: no \"%V\" cookie specified, trying arg", &conf->csrf);*/
        csrf_var.len = conf->csrf.len + sizeof("arg_%V") - 1 - 2;
        if (!(csrf_var.data = ngx_pnalloc(r->pool, csrf_var.len))) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "captcha: %s:%d", __FILE__, __LINE__); return NGX_ERROR; }
        if (ngx_snprintf(csrf_var.data, csrf_var.len, "arg_%V", &conf->csrf) != csrf_var.data + csrf_var.len) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "captcha: %s:%d", __FILE__, __LINE__); return NGX_ERROR; }
/*        csrf_var.data += 3;
        csrf_var.len -= 3;
        csrf_var.data[0] = 'a';
        csrf_var.data[1] = 'r';
        csrf_var.data[2] = 'g';*/
        ngx_http_variable_value_t *csrf = ngx_http_get_variable(r, &csrf_var, ngx_hash_key(csrf_var.data, csrf_var.len));
        if (!csrf || !csrf->data || !csrf->len) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "captcha: no \"%V\" arg specified", &conf->csrf); return NGX_ERROR; }
//    }
    if (conf->icase) {
        u_char *icode = ngx_pnalloc(r->pool, conf->length);
        if (!icode) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "captcha: %s:%d", __FILE__, __LINE__); return NGX_ERROR; }
        (void)ngx_strlow(icode, code, conf->length);
        code = icode;
    }
    ngx_md5_t md5;
    (void)ngx_md5_init(&md5);
    (void)ngx_md5_update(&md5, (const void *)conf->secret.data, conf->secret.len);
    (void)ngx_md5_update(&md5, (const void *)code, (size_t)conf->length);
    (void)ngx_md5_update(&md5, (const void *)csrf->data, csrf->len);
    u_char bhash[MD5_BHASH_LEN];
    (void)ngx_md5_final(bhash, &md5);
    u_char hash[MD5_HASH_LEN + 1];
    (u_char *)ngx_hex_dump(hash, bhash, MD5_BHASH_LEN);
    hash[MD5_HASH_LEN] = '\0';
    ngx_table_elt_t *set_cookie_name = ngx_list_push(&r->headers_out.headers);
    if (!set_cookie_name) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "captcha: %s:%d", __FILE__, __LINE__); return NGX_ERROR; }
    set_cookie_name->hash = 1;
    ngx_str_set(&set_cookie_name->key, "Set-Cookie");
    set_cookie_name->value.len = conf->name.len + MD5_HASH_LEN + sizeof("%V=%s; Max-Age=%d") - 1 - 6;
    for (ngx_uint_t number = conf->expire; number /= 10; set_cookie_name->value.len++);
    set_cookie_name->value.len++;
    if (!(set_cookie_name->value.data = ngx_pnalloc(r->pool, set_cookie_name->value.len))) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "captcha: %s:%d", __FILE__, __LINE__); return NGX_ERROR; }
    if (ngx_snprintf(set_cookie_name->value.data, set_cookie_name->value.len, "%V=%s; Max-Age=%d", &conf->name, hash, conf->expire) != set_cookie_name->value.data + set_cookie_name->value.len) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "captcha: %s:%d", __FILE__, __LINE__); return NGX_ERROR; }
    return NGX_OK;
}

static ngx_int_t ngx_http_captcha_handler(ngx_http_request_t *r) {
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "captcha: %s", __func__);
    if (!(r->method & (NGX_HTTP_GET|NGX_HTTP_HEAD))) return NGX_HTTP_NOT_ALLOWED;
    ngx_int_t rc = ngx_http_discard_request_body(r);
    if (rc != NGX_OK && rc != NGX_AGAIN) return rc;
    u_char *code = create_code(r);
    if (!code) return NGX_HTTP_INTERNAL_SERVER_ERROR;
    if (set_captcha_cookie(r, code) != NGX_OK) return NGX_HTTP_INTERNAL_SERVER_ERROR;
    ngx_str_set(&r->headers_out.content_type, "image/png");
    r->headers_out.status = NGX_HTTP_OK;
    r->headers_out.content_length_n = 0;
    if (r->method == NGX_HTTP_HEAD) {
        rc = ngx_http_send_header(r);
        if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) return rc;
    }
    int size;
    u_char *img_buf = create_captcha_png(r, &size, code);
    if (!img_buf) size = 0; else {
        ngx_pool_cleanup_t *cln = ngx_pool_cleanup_add(r->pool, 0);
        if (!cln) { (void)gdFree(img_buf); return NGX_HTTP_INTERNAL_SERVER_ERROR; }
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
    return NGX_CONF_OK;
}

static ngx_command_t ngx_http_captcha_commands[] = {
  { .name = ngx_string("captcha"),
    .type = NGX_HTTP_LOC_CONF|NGX_CONF_NOARGS,
    .set = ngx_http_captcha_conf,
    .conf = NGX_HTTP_LOC_CONF_OFFSET,
    .offset = 0,
    .post = NULL },
  { .name = ngx_string("captcha_case"),
    .type = NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
    .set = ngx_conf_set_flag_slot,
    .conf = NGX_HTTP_LOC_CONF_OFFSET,
    .offset = offsetof(ngx_http_captcha_loc_conf_t, icase),
    .post = NULL },
  { .name = ngx_string("captcha_expire"),
    .type = NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
    .set = ngx_conf_set_num_slot,
    .conf = NGX_HTTP_LOC_CONF_OFFSET,
    .offset = offsetof(ngx_http_captcha_loc_conf_t, expire),
    .post = NULL },
  { .name = ngx_string("captcha_height"),
    .type = NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
    .set = ngx_conf_set_num_slot,
    .conf = NGX_HTTP_LOC_CONF_OFFSET,
    .offset = offsetof(ngx_http_captcha_loc_conf_t, height),
    .post = NULL },
  { .name = ngx_string("captcha_length"),
    .type = NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
    .set = ngx_conf_set_num_slot,
    .conf = NGX_HTTP_LOC_CONF_OFFSET,
    .offset = offsetof(ngx_http_captcha_loc_conf_t, length),
    .post = NULL },
  { .name = ngx_string("captcha_size"),
    .type = NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
    .set = ngx_conf_set_num_slot,
    .conf = NGX_HTTP_LOC_CONF_OFFSET,
    .offset = offsetof(ngx_http_captcha_loc_conf_t, size),
    .post = NULL },
  { .name = ngx_string("captcha_width"),
    .type = NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
    .set = ngx_conf_set_num_slot,
    .conf = NGX_HTTP_LOC_CONF_OFFSET,
    .offset = offsetof(ngx_http_captcha_loc_conf_t, width),
    .post = NULL },
  { .name = ngx_string("captcha_charset"),
    .type = NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
    .set = ngx_conf_set_str_slot,
    .conf = NGX_HTTP_LOC_CONF_OFFSET,
    .offset = offsetof(ngx_http_captcha_loc_conf_t, charset),
    .post = NULL },
  { .name = ngx_string("captcha_csrf"),
    .type = NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
    .set = ngx_conf_set_str_slot,
    .conf = NGX_HTTP_LOC_CONF_OFFSET,
    .offset = offsetof(ngx_http_captcha_loc_conf_t, csrf),
    .post = NULL },
  { .name = ngx_string("captcha_font"),
    .type = NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
    .set = ngx_conf_set_str_slot,
    .conf = NGX_HTTP_LOC_CONF_OFFSET,
    .offset = offsetof(ngx_http_captcha_loc_conf_t, font),
    .post = NULL },
  { .name = ngx_string("captcha_name"),
    .type = NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
    .set = ngx_conf_set_str_slot,
    .conf = NGX_HTTP_LOC_CONF_OFFSET,
    .offset = offsetof(ngx_http_captcha_loc_conf_t, name),
    .post = NULL },
  { .name = ngx_string("captcha_secret"),
    .type = NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
    .set = ngx_conf_set_str_slot,
    .conf = NGX_HTTP_LOC_CONF_OFFSET,
    .offset = offsetof(ngx_http_captcha_loc_conf_t, secret),
    .post = NULL },
    ngx_null_command
};

static void *ngx_http_captcha_create_loc_conf(ngx_conf_t *cf) {
    ngx_http_captcha_loc_conf_t *conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_captcha_loc_conf_t));
    if (!conf) return NGX_CONF_ERROR;
    conf->icase = NGX_CONF_UNSET;
    conf->expire = NGX_CONF_UNSET_UINT;
    conf->height = NGX_CONF_UNSET_UINT;
    conf->length = NGX_CONF_UNSET_UINT;
    conf->size = NGX_CONF_UNSET_UINT;
    conf->width = NGX_CONF_UNSET_UINT;
    return conf;
}

static char *ngx_http_captcha_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child) {
    ngx_http_captcha_loc_conf_t *prev = parent;
    ngx_http_captcha_loc_conf_t *conf = child;
    ngx_conf_merge_value(conf->icase, prev->icase, 0);
    ngx_conf_merge_uint_value(conf->expire, prev->expire, 300);
    ngx_conf_merge_uint_value(conf->height, prev->height, 30);
    ngx_conf_merge_uint_value(conf->length, prev->length, 4);
    ngx_conf_merge_uint_value(conf->size, prev->size, 20);
    ngx_conf_merge_uint_value(conf->width, prev->width, 130);
    ngx_conf_merge_str_value(conf->charset, prev->charset, "abcdefghkmnprstuvwxyzABCDEFGHKMNPRSTUVWXYZ23456789");
    ngx_conf_merge_str_value(conf->csrf, prev->csrf, "csrf");
    ngx_conf_merge_str_value(conf->font, prev->font, "/usr/local/share/fonts/NimbusSans-Regular.ttf");
    ngx_conf_merge_str_value(conf->name, prev->name, "Captcha");
    ngx_conf_merge_str_value(conf->secret, prev->secret, "secret");
    if (conf->size > conf->height) { ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "captcha size is too large"); return NGX_CONF_ERROR; }
    if (!conf->name.len) { ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "captcha name cannot be empty"); return NGX_CONF_ERROR; }
    if (!conf->secret.len) { ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "captcha secret cannot be empty"); return NGX_CONF_ERROR; }
    if (!conf->font.len) { ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "captcha font cannot be empty"); return NGX_CONF_ERROR; }
    if (!conf->charset.len) { ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "captcha charset cannot be empty"); return NGX_CONF_ERROR; }
    if (!conf->csrf.len) { ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "captcha csrf cannot be empty"); return NGX_CONF_ERROR; }
    return NGX_CONF_OK;
}

static ngx_http_module_t ngx_http_captcha_module_ctx = {
    .preconfiguration = NULL,
    .postconfiguration = NULL,
    .create_main_conf = NULL,
    .init_main_conf = NULL,
    .create_srv_conf = NULL,
    .merge_srv_conf = NULL,
    .create_loc_conf = ngx_http_captcha_create_loc_conf,
    .merge_loc_conf = ngx_http_captcha_merge_loc_conf
};

ngx_module_t ngx_http_captcha_module = {
    NGX_MODULE_V1,
    .ctx = &ngx_http_captcha_module_ctx,
    .commands = ngx_http_captcha_commands,
    .type = NGX_HTTP_MODULE,
    .init_master = NULL,
    .init_module = NULL,
    .init_process = NULL,
    .init_thread = NULL,
    .exit_thread = NULL,
    .exit_process = NULL,
    .exit_master = NULL,
    NGX_MODULE_V1_PADDING
};
