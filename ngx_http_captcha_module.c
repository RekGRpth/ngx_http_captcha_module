#include <ngx_http.h>
#include <ngx_md5.h>
#include <gd.h>

#define M_PI 3.14159265358979323846
#define MD5_BHASH_LEN 16
#define MD5_HASH_LEN (MD5_BHASH_LEN * 2)

typedef struct {
    ngx_flag_t icase;
    ngx_int_t level;
    ngx_str_t charset;
    ngx_str_t csrf;
    ngx_str_t font;
    ngx_str_t name;
    ngx_str_t secret;
    ngx_uint_t arg;
    ngx_uint_t cookie;
    ngx_uint_t expire;
    ngx_uint_t height;
    ngx_uint_t length;
    ngx_uint_t line;
    ngx_uint_t size;
    ngx_uint_t star;
    ngx_uint_t width;
} ngx_http_captcha_location_conf_t;

ngx_module_t ngx_http_captcha_module;

static int mt_rand(int min, int max) {
    return (ngx_random() % (max - min + 1)) + min;
}

static ngx_int_t ngx_http_captcha_handler(ngx_http_request_t *r) {
    if (!(r->method & (NGX_HTTP_GET|NGX_HTTP_HEAD))) return NGX_HTTP_NOT_ALLOWED;
    ngx_int_t rc = ngx_http_discard_request_body(r);
    if (rc != NGX_OK && rc != NGX_AGAIN) return rc;
    ngx_http_captcha_location_conf_t *location_conf = ngx_http_get_module_loc_conf(r, ngx_http_captcha_module);
    u_char *code = ngx_pnalloc(r->pool, location_conf->length + 1);
    if (!code) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "captcha: %s:%d", __FILE__, __LINE__); return NGX_HTTP_INTERNAL_SERVER_ERROR; }
    for (size_t i = 0; i < location_conf->length; i++) code[i] = location_conf->charset.data[mt_rand(0, location_conf->charset.len - 1)];
    code[location_conf->length] = '\0';
    ngx_http_variable_value_t *csrf = ngx_http_get_indexed_variable(r, location_conf->cookie);
    if (!csrf || !csrf->data || !csrf->len) {
        ngx_log_error(NGX_LOG_WARN, r->connection->log, 0, "captcha: no \"%V\" cookie specified, trying arg...", &location_conf->csrf);
        csrf = ngx_http_get_indexed_variable(r, location_conf->arg);
        if (!csrf || !csrf->data || !csrf->len) { ngx_log_error(NGX_LOG_WARN, r->connection->log, 0, "captcha: no \"%V\" arg specified", &location_conf->csrf); return NGX_HTTP_NOT_FOUND; }
    }
    if (location_conf->icase) {
        u_char *icode = ngx_pnalloc(r->pool, location_conf->length);
        if (!icode) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "captcha: %s:%d", __FILE__, __LINE__); return NGX_HTTP_INTERNAL_SERVER_ERROR; }
        (void)ngx_strlow(icode, code, location_conf->length);
        code = icode;
    }
    ngx_md5_t md5;
    (void)ngx_md5_init(&md5);
    (void)ngx_md5_update(&md5, (const void *)location_conf->secret.data, location_conf->secret.len);
    (void)ngx_md5_update(&md5, (const void *)code, (size_t)location_conf->length);
    (void)ngx_md5_update(&md5, (const void *)csrf->data, csrf->len);
    u_char bhash[MD5_BHASH_LEN];
    (void)ngx_md5_final(bhash, &md5);
    u_char hash[MD5_HASH_LEN + 1];
    (u_char *)ngx_hex_dump(hash, bhash, MD5_BHASH_LEN);
    hash[MD5_HASH_LEN] = '\0';
    ngx_table_elt_t *set_cookie_name = ngx_list_push(&r->headers_out.headers);
    if (!set_cookie_name) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "captcha: %s:%d", __FILE__, __LINE__); return NGX_HTTP_INTERNAL_SERVER_ERROR; }
    set_cookie_name->hash = 1;
    ngx_str_set(&set_cookie_name->key, "Set-Cookie");
    set_cookie_name->value.len = location_conf->name.len + MD5_HASH_LEN + sizeof("%V=%s; Max-Age=%d") - 1 - 6;
    for (ngx_uint_t number = location_conf->expire; number /= 10; set_cookie_name->value.len++);
    set_cookie_name->value.len++;
    if (!(set_cookie_name->value.data = ngx_pnalloc(r->pool, set_cookie_name->value.len))) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "captcha: %s:%d", __FILE__, __LINE__); return NGX_HTTP_INTERNAL_SERVER_ERROR; }
    if (ngx_snprintf(set_cookie_name->value.data, set_cookie_name->value.len, "%V=%s; Max-Age=%d", &location_conf->name, hash, location_conf->expire) != set_cookie_name->value.data + set_cookie_name->value.len) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "captcha: %s:%d", __FILE__, __LINE__); return NGX_HTTP_INTERNAL_SERVER_ERROR; }
    ngx_str_set(&r->headers_out.content_type, "image/png");
    r->headers_out.status = NGX_HTTP_OK;
    r->headers_out.content_length_n = 0;
    if (r->method == NGX_HTTP_HEAD) {
        rc = ngx_http_send_header(r);
        if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) return rc;
    }
    int size;
    gdFTUseFontConfig(1);
    gdImagePtr img = gdImageCreateTrueColor(location_conf->width, location_conf->height);
    (void)gdImageFilledRectangle(img, 0, location_conf->height, location_conf->width, 0, gdImageColorAllocate(img, mt_rand(157, 255), mt_rand(157, 255), mt_rand(157, 255)));
    for (ngx_uint_t i = 0, brect[8], x = location_conf->width / location_conf->length; i < location_conf->length; i++) (char *)gdImageStringFT(img, (int *)brect, gdImageColorAllocate(img, mt_rand(0, 156), mt_rand(0, 156), mt_rand(0, 156)), (char *)location_conf->font.data, location_conf->size, mt_rand(-30, 30) * (M_PI / 180), x * i + mt_rand(1, 5), location_conf->height / 1.4, (char *)(u_char [2]){*code++, '\0'});
    for (ngx_uint_t i = 0; i < location_conf->line; i++) (void)gdImageLine(img, mt_rand(0, location_conf->width), mt_rand(0, location_conf->height), mt_rand(0, location_conf->width), mt_rand(0, location_conf->height), gdImageColorAllocate(img, mt_rand(0, 156), mt_rand(0, 156), mt_rand(0, 156)));
    for (ngx_uint_t i = 0, brect[8]; i < location_conf->star; i++) (char *)gdImageStringFT(img, (int *)brect, gdImageColorAllocate(img, mt_rand(200, 255), mt_rand(200, 255), mt_rand(200, 255)), (char *)location_conf->font.data, 8, 0, mt_rand(0, location_conf->width), mt_rand(0, location_conf->height), "*");
    u_char *img_buf = (u_char *)gdImagePngPtrEx(img, &size, location_conf->level);
    (void)gdImageDestroy(img);
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
    .offset = offsetof(ngx_http_captcha_location_conf_t, icase),
    .post = NULL },
  { .name = ngx_string("captcha_expire"),
    .type = NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
    .set = ngx_conf_set_num_slot,
    .conf = NGX_HTTP_LOC_CONF_OFFSET,
    .offset = offsetof(ngx_http_captcha_location_conf_t, expire),
    .post = NULL },
  { .name = ngx_string("captcha_height"),
    .type = NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
    .set = ngx_conf_set_num_slot,
    .conf = NGX_HTTP_LOC_CONF_OFFSET,
    .offset = offsetof(ngx_http_captcha_location_conf_t, height),
    .post = NULL },
  { .name = ngx_string("captcha_length"),
    .type = NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
    .set = ngx_conf_set_num_slot,
    .conf = NGX_HTTP_LOC_CONF_OFFSET,
    .offset = offsetof(ngx_http_captcha_location_conf_t, length),
    .post = NULL },
  { .name = ngx_string("captcha_size"),
    .type = NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
    .set = ngx_conf_set_num_slot,
    .conf = NGX_HTTP_LOC_CONF_OFFSET,
    .offset = offsetof(ngx_http_captcha_location_conf_t, size),
    .post = NULL },
  { .name = ngx_string("captcha_width"),
    .type = NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
    .set = ngx_conf_set_num_slot,
    .conf = NGX_HTTP_LOC_CONF_OFFSET,
    .offset = offsetof(ngx_http_captcha_location_conf_t, width),
    .post = NULL },
  { .name = ngx_string("captcha_line"),
    .type = NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
    .set = ngx_conf_set_num_slot,
    .conf = NGX_HTTP_LOC_CONF_OFFSET,
    .offset = offsetof(ngx_http_captcha_location_conf_t, line),
    .post = NULL },
  { .name = ngx_string("captcha_star"),
    .type = NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
    .set = ngx_conf_set_num_slot,
    .conf = NGX_HTTP_LOC_CONF_OFFSET,
    .offset = offsetof(ngx_http_captcha_location_conf_t, star),
    .post = NULL },
  { .name = ngx_string("captcha_level"),
    .type = NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
    .set = ngx_conf_set_num_slot,
    .conf = NGX_HTTP_LOC_CONF_OFFSET,
    .offset = offsetof(ngx_http_captcha_location_conf_t, level),
    .post = NULL },
  { .name = ngx_string("captcha_charset"),
    .type = NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
    .set = ngx_conf_set_str_slot,
    .conf = NGX_HTTP_LOC_CONF_OFFSET,
    .offset = offsetof(ngx_http_captcha_location_conf_t, charset),
    .post = NULL },
  { .name = ngx_string("captcha_csrf"),
    .type = NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
    .set = ngx_conf_set_str_slot,
    .conf = NGX_HTTP_LOC_CONF_OFFSET,
    .offset = offsetof(ngx_http_captcha_location_conf_t, csrf),
    .post = NULL },
  { .name = ngx_string("captcha_font"),
    .type = NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
    .set = ngx_conf_set_str_slot,
    .conf = NGX_HTTP_LOC_CONF_OFFSET,
    .offset = offsetof(ngx_http_captcha_location_conf_t, font),
    .post = NULL },
  { .name = ngx_string("captcha_name"),
    .type = NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
    .set = ngx_conf_set_str_slot,
    .conf = NGX_HTTP_LOC_CONF_OFFSET,
    .offset = offsetof(ngx_http_captcha_location_conf_t, name),
    .post = NULL },
  { .name = ngx_string("captcha_secret"),
    .type = NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
    .set = ngx_conf_set_str_slot,
    .conf = NGX_HTTP_LOC_CONF_OFFSET,
    .offset = offsetof(ngx_http_captcha_location_conf_t, secret),
    .post = NULL },
    ngx_null_command
};

static void *ngx_http_captcha_create_loc_conf(ngx_conf_t *cf) {
    ngx_http_captcha_location_conf_t *location_conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_captcha_location_conf_t));
    if (!location_conf) return NGX_CONF_ERROR;
    location_conf->icase = NGX_CONF_UNSET;
    location_conf->expire = NGX_CONF_UNSET_UINT;
    location_conf->height = NGX_CONF_UNSET_UINT;
    location_conf->length = NGX_CONF_UNSET_UINT;
    location_conf->size = NGX_CONF_UNSET_UINT;
    location_conf->width = NGX_CONF_UNSET_UINT;
    location_conf->line = NGX_CONF_UNSET_UINT;
    location_conf->star = NGX_CONF_UNSET_UINT;
    location_conf->level = NGX_CONF_UNSET;
    return location_conf;
}

static char *ngx_http_captcha_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child) {
    ngx_http_captcha_location_conf_t *prev = parent;
    ngx_http_captcha_location_conf_t *conf = child;
    ngx_conf_merge_value(conf->icase, prev->icase, 0);
    ngx_conf_merge_uint_value(conf->expire, prev->expire, 300);
    ngx_conf_merge_uint_value(conf->height, prev->height, 30);
    ngx_conf_merge_uint_value(conf->length, prev->length, 4);
    ngx_conf_merge_uint_value(conf->size, prev->size, 20);
    ngx_conf_merge_uint_value(conf->width, prev->width, 130);
    ngx_conf_merge_uint_value(conf->line, prev->line, 10);
    ngx_conf_merge_uint_value(conf->star, prev->star, 100);
    ngx_conf_merge_value(conf->level, prev->level, -1);
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
    if (prev->cookie && prev->arg) {
        conf->cookie = prev->cookie;
        conf->arg = prev->arg;
    } else {
        ngx_str_t name;
        name.len = conf->csrf.len + sizeof("cookie_%V") - 1 - 2;
        if (!(name.data = ngx_pnalloc(cf->pool, name.len))) { ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "captcha: %s:%d", __FILE__, __LINE__); return NGX_CONF_ERROR; }
        if (ngx_snprintf(name.data, name.len, "cookie_%V", &conf->csrf) != name.data + name.len) { ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "captcha: %s:%d", __FILE__, __LINE__); return NGX_CONF_ERROR; }
        ngx_int_t index = ngx_http_get_variable_index(cf, &name);
        if (index == NGX_ERROR) { ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "captcha: invalid cookie \"%V\"", &name); return NGX_CONF_ERROR; }
        conf->cookie = (ngx_uint_t) index;
        name.data += 3;
        name.len -= 3;
        name.data[0] = 'a';
        name.data[1] = 'r';
        name.data[2] = 'g';
        index = ngx_http_get_variable_index(cf, &name);
        if (index == NGX_ERROR) { ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "captcha: invalid arg \"%V\"", &name); return NGX_CONF_ERROR; }
        conf->arg = (ngx_uint_t) index;
//        if (ngx_pfree(cf->pool, name.data - 3) != NGX_OK) { ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "captcha: %s:%d", __FILE__, __LINE__); return NGX_CONF_ERROR; }
    }
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
