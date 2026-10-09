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
    ngx_http_complex_value_t *answer;
    ngx_http_complex_value_t *flags;
    ngx_http_complex_value_t *secret;
    ngx_uint_t arg;
    ngx_uint_t captcha;
    ngx_uint_t cookie;
    ngx_uint_t expire;
    ngx_uint_t height;
    ngx_uint_t length;
    ngx_uint_t line;
    ngx_uint_t size;
    ngx_uint_t star;
    ngx_uint_t width;
} ngx_http_captcha_location_t;

ngx_module_t ngx_http_captcha_module;

static int mt_rand(int min, int max) {
    return (ngx_random() % (max - min + 1)) + min;
}

static ngx_flag_t ngx_http_captcha_ft_inited = 0;

static ngx_http_variable_value_t *ngx_http_captcha_csrf(ngx_http_request_t *r, ngx_http_captcha_location_t *location) {
    ngx_http_variable_value_t *csrf = ngx_http_get_indexed_variable(r, location->cookie);
    if (csrf && csrf->data && csrf->len) return csrf;
    ngx_log_error(NGX_LOG_WARN, r->connection->log, 0, "captcha: no \"%V\" cookie specified, trying arg...", &location->csrf);
    csrf = ngx_http_get_indexed_variable(r, location->arg);
    if (csrf && csrf->data && csrf->len) return csrf;
    ngx_log_error(NGX_LOG_WARN, r->connection->log, 0, "captcha: no \"%V\" arg specified", &location->csrf);
    return NULL;
}

// hash = md5(secret + expires + "." + code + csrf), where expires includes the trailing "."
// expires goes right after secret so that md5 length extension cannot change it
static ngx_int_t ngx_http_captcha_hash(ngx_http_request_t *r, ngx_http_captcha_location_t *location, u_char *expires, size_t expires_len, u_char *code, size_t code_len, ngx_http_variable_value_t *csrf, u_char *hash) {
    if (location->icase) {
        u_char *low = ngx_pnalloc(r->pool, code_len);
        if (!low) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!ngx_pnalloc"); return NGX_ERROR; }
        (void)ngx_strlow(low, code, code_len);
        code = low;
    }
    ngx_str_t secret;
    if (ngx_http_complex_value(r, location->secret, &secret) != NGX_OK) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "ngx_http_complex_value != NGX_OK"); return NGX_ERROR; }
    ngx_md5_t md5;
    (void)ngx_md5_init(&md5);
    (void)ngx_md5_update(&md5, (const void *)secret.data, secret.len);
    (void)ngx_md5_update(&md5, (const void *)expires, expires_len);
    (void)ngx_md5_update(&md5, (const void *)code, code_len);
    (void)ngx_md5_update(&md5, (const void *)csrf->data, csrf->len);
    u_char bhash[MD5_BHASH_LEN];
    (void)ngx_md5_final(bhash, &md5);
    (void)ngx_hex_dump(hash, bhash, MD5_BHASH_LEN);
    return NGX_OK;
}

static ngx_int_t ngx_http_captcha_handler(ngx_http_request_t *r) {
    if (r->method != NGX_HTTP_GET) return NGX_HTTP_NOT_ALLOWED;
    ngx_int_t rc = ngx_http_discard_request_body(r);
    if (rc != NGX_OK && rc != NGX_AGAIN) return rc;
    ngx_http_captcha_location_t *location = ngx_http_get_module_loc_conf(r, ngx_http_captcha_module);
    if (!location->secret)  { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!location->secret"); return NGX_HTTP_INTERNAL_SERVER_ERROR; }
    u_char *code = ngx_pnalloc(r->pool, location->length + 1);
    if (!code) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!ngx_pnalloc"); return NGX_HTTP_INTERNAL_SERVER_ERROR; }
    for (size_t i = 0; i < location->length; i++) code[i] = location->charset.data[mt_rand(0, location->charset.len - 1)];
    code[location->length] = '\0';
    ngx_http_variable_value_t *csrf = ngx_http_captcha_csrf(r, location);
    if (!csrf) return NGX_HTTP_NOT_FOUND;
    ngx_table_elt_t *set_cookie_name = ngx_list_push(&r->headers_out.headers);
    if (!set_cookie_name) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!ngx_list_push"); return NGX_HTTP_INTERNAL_SERVER_ERROR; }
    set_cookie_name->hash = 1;
    ngx_str_set(&set_cookie_name->key, "Set-Cookie");
    ngx_str_t flags = ngx_string("Path=/; HttpOnly; SameSite=Lax");
    if (location->flags && ngx_http_complex_value(r, location->flags, &flags) != NGX_OK) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "ngx_http_complex_value != NGX_OK"); return NGX_HTTP_INTERNAL_SERVER_ERROR; }
    u_char *value = ngx_pnalloc(r->pool, location->name.len + sizeof("=.; Max-Age=; ") - 1 + NGX_TIME_T_LEN + MD5_HASH_LEN + NGX_INT_T_LEN + flags.len);
    if (!value) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!ngx_pnalloc"); return NGX_HTTP_INTERNAL_SERVER_ERROR; }
    u_char *expires = ngx_sprintf(value, "%V=", &location->name);
    u_char *last = ngx_sprintf(expires, "%T.", ngx_time() + (time_t)location->expire);
    if (ngx_http_captcha_hash(r, location, expires, last - expires, code, location->length, csrf, last) != NGX_OK) return NGX_HTTP_INTERNAL_SERVER_ERROR;
    last = ngx_sprintf(last + MD5_HASH_LEN, "; Max-Age=%ui", location->expire);
    if (flags.len) last = ngx_sprintf(last, "; %V", &flags);
    set_cookie_name->value.data = value;
    set_cookie_name->value.len = last - value;
    ngx_str_set(&r->headers_out.content_type, "image/png");
    r->headers_out.status = NGX_HTTP_OK;
    if (!ngx_http_captcha_ft_inited) {
        ngx_http_captcha_ft_inited = 1;
        if (!gdFTUseFontConfig(1)) { ngx_log_error(NGX_LOG_WARN, r->connection->log, 0, "captcha: gd was built without fontconfig support, captcha_font must be a literal font file path"); }
    }
    gdImagePtr img = gdImageCreateTrueColor(location->width, location->height);
    if (!img) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!gdImageCreateTrueColor"); return NGX_HTTP_INTERNAL_SERVER_ERROR; }
    (void)gdImageFilledRectangle(img, 0, location->height, location->width, 0, gdImageColorAllocate(img, mt_rand(157, 255), mt_rand(157, 255), mt_rand(157, 255)));
    char *gd_err;
    ngx_uint_t gd_err_logged = 0;
    for (ngx_uint_t i = 0, brect[8], x = location->width / location->length; i < location->length; i++) {
        gd_err = gdImageStringFT(img, (int *)brect, gdImageColorAllocate(img, mt_rand(0, 156), mt_rand(0, 156), mt_rand(0, 156)), (char *)location->font.data, location->size, mt_rand(-30, 30) * (M_PI / 180), x * i + mt_rand(1, 5), location->height / 1.4, (char *)(u_char [2]){*code++, '\0'});
        if (gd_err && !gd_err_logged) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "gdImageStringFT: %s", gd_err); gd_err_logged = 1; }
    }
    for (ngx_uint_t i = 0; i < location->line; i++) (void)gdImageLine(img, mt_rand(0, location->width), mt_rand(0, location->height), mt_rand(0, location->width), mt_rand(0, location->height), gdImageColorAllocate(img, mt_rand(0, 156), mt_rand(0, 156), mt_rand(0, 156)));
    for (ngx_uint_t i = 0, brect[8]; i < location->star; i++) {
        gd_err = gdImageStringFT(img, (int *)brect, gdImageColorAllocate(img, mt_rand(200, 255), mt_rand(200, 255), mt_rand(200, 255)), (char *)location->font.data, 8, 0, mt_rand(0, location->width), mt_rand(0, location->height), "*");
        if (gd_err && !gd_err_logged) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "gdImageStringFT: %s", gd_err); gd_err_logged = 1; }
    }
    int size;
    u_char *img_buf = (u_char *)gdImagePngPtrEx(img, &size, location->level);
    (void)gdImageDestroy(img);
    if (!img_buf) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!gdImagePngPtrEx"); return NGX_HTTP_INTERNAL_SERVER_ERROR; }
    ngx_buf_t *b = ngx_create_temp_buf(r->pool, size);
    if (!b) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!ngx_create_temp_buf"); gdFree(img_buf); return NGX_HTTP_INTERNAL_SERVER_ERROR; }
    b->memory = 1;
    b->last_buf = 1;
    b->last = ngx_copy(b->last, img_buf, size);
    gdFree(img_buf);
    if (b->last != b->end) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "b->last != b->end"); return NGX_HTTP_INTERNAL_SERVER_ERROR; }
    r->headers_out.content_length_n = size;
    rc = ngx_http_send_header(r);
    if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) return rc;
    ngx_chain_t cl = {.buf = b, .next = NULL};
    return ngx_http_output_filter(r, &cl);
}

static ngx_int_t ngx_http_captcha_valid_variable(ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data) {
    v->valid = 1;
    v->no_cacheable = 1;
    v->not_found = 0;
    v->len = 1;
    v->data = (u_char *)"0";
    ngx_http_captcha_location_t *location = ngx_http_get_module_loc_conf(r, ngx_http_captcha_module);
    if (!location->secret) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!location->secret"); return NGX_OK; }
    if (!location->answer) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!location->answer"); return NGX_OK; }
    ngx_http_variable_value_t *cookie = ngx_http_get_indexed_variable(r, location->captcha);
    if (!cookie || !cookie->data || !cookie->len) { ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "captcha: no \"%V\" cookie specified", &location->name); return NGX_OK; }
    u_char *dot = ngx_strlchr(cookie->data, cookie->data + cookie->len, '.');
    if (!dot || cookie->data + cookie->len - dot - 1 != MD5_HASH_LEN) { ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "captcha: invalid \"%V\" cookie", &location->name); return NGX_OK; }
    time_t expires = ngx_atotm(cookie->data, dot - cookie->data);
    if (expires == NGX_ERROR) { ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "captcha: invalid \"%V\" cookie", &location->name); return NGX_OK; }
    if (expires < ngx_time()) { ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "captcha: \"%V\" cookie expired", &location->name); return NGX_OK; }
    ngx_http_variable_value_t *csrf = ngx_http_captcha_csrf(r, location);
    if (!csrf) return NGX_OK;
    ngx_str_t answer;
    if (ngx_http_complex_value(r, location->answer, &answer) != NGX_OK) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "ngx_http_complex_value != NGX_OK"); return NGX_ERROR; }
    if (!answer.len) { ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "captcha: empty answer"); return NGX_OK; }
    u_char hash[MD5_HASH_LEN];
    if (ngx_http_captcha_hash(r, location, cookie->data, dot - cookie->data + 1, answer.data, answer.len, csrf, hash) != NGX_OK) return NGX_ERROR;
    u_char diff = 0;
    for (size_t i = 0; i < MD5_HASH_LEN; i++) diff |= hash[i] ^ dot[1 + i];
    if (!diff) v->data = (u_char *)"1";
    return NGX_OK;
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
  { .name = ngx_string("captcha_answer"),
    .type = NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
    .set = ngx_http_set_complex_value_slot,
    .conf = NGX_HTTP_LOC_CONF_OFFSET,
    .offset = offsetof(ngx_http_captcha_location_t, answer),
    .post = NULL },
  { .name = ngx_string("captcha_case"),
    .type = NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
    .set = ngx_conf_set_flag_slot,
    .conf = NGX_HTTP_LOC_CONF_OFFSET,
    .offset = offsetof(ngx_http_captcha_location_t, icase),
    .post = NULL },
  { .name = ngx_string("captcha_expire"),
    .type = NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
    .set = ngx_conf_set_num_slot,
    .conf = NGX_HTTP_LOC_CONF_OFFSET,
    .offset = offsetof(ngx_http_captcha_location_t, expire),
    .post = NULL },
  { .name = ngx_string("captcha_height"),
    .type = NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
    .set = ngx_conf_set_num_slot,
    .conf = NGX_HTTP_LOC_CONF_OFFSET,
    .offset = offsetof(ngx_http_captcha_location_t, height),
    .post = NULL },
  { .name = ngx_string("captcha_length"),
    .type = NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
    .set = ngx_conf_set_num_slot,
    .conf = NGX_HTTP_LOC_CONF_OFFSET,
    .offset = offsetof(ngx_http_captcha_location_t, length),
    .post = NULL },
  { .name = ngx_string("captcha_size"),
    .type = NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
    .set = ngx_conf_set_num_slot,
    .conf = NGX_HTTP_LOC_CONF_OFFSET,
    .offset = offsetof(ngx_http_captcha_location_t, size),
    .post = NULL },
  { .name = ngx_string("captcha_width"),
    .type = NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
    .set = ngx_conf_set_num_slot,
    .conf = NGX_HTTP_LOC_CONF_OFFSET,
    .offset = offsetof(ngx_http_captcha_location_t, width),
    .post = NULL },
  { .name = ngx_string("captcha_line"),
    .type = NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
    .set = ngx_conf_set_num_slot,
    .conf = NGX_HTTP_LOC_CONF_OFFSET,
    .offset = offsetof(ngx_http_captcha_location_t, line),
    .post = NULL },
  { .name = ngx_string("captcha_star"),
    .type = NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
    .set = ngx_conf_set_num_slot,
    .conf = NGX_HTTP_LOC_CONF_OFFSET,
    .offset = offsetof(ngx_http_captcha_location_t, star),
    .post = NULL },
  { .name = ngx_string("captcha_level"),
    .type = NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
    .set = ngx_conf_set_num_slot,
    .conf = NGX_HTTP_LOC_CONF_OFFSET,
    .offset = offsetof(ngx_http_captcha_location_t, level),
    .post = NULL },
  { .name = ngx_string("captcha_charset"),
    .type = NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
    .set = ngx_conf_set_str_slot,
    .conf = NGX_HTTP_LOC_CONF_OFFSET,
    .offset = offsetof(ngx_http_captcha_location_t, charset),
    .post = NULL },
  { .name = ngx_string("captcha_csrf"),
    .type = NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
    .set = ngx_conf_set_str_slot,
    .conf = NGX_HTTP_LOC_CONF_OFFSET,
    .offset = offsetof(ngx_http_captcha_location_t, csrf),
    .post = NULL },
  { .name = ngx_string("captcha_flags"),
    .type = NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
    .set = ngx_http_set_complex_value_slot,
    .conf = NGX_HTTP_LOC_CONF_OFFSET,
    .offset = offsetof(ngx_http_captcha_location_t, flags),
    .post = NULL },
  { .name = ngx_string("captcha_font"),
    .type = NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
    .set = ngx_conf_set_str_slot,
    .conf = NGX_HTTP_LOC_CONF_OFFSET,
    .offset = offsetof(ngx_http_captcha_location_t, font),
    .post = NULL },
  { .name = ngx_string("captcha_name"),
    .type = NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
    .set = ngx_conf_set_str_slot,
    .conf = NGX_HTTP_LOC_CONF_OFFSET,
    .offset = offsetof(ngx_http_captcha_location_t, name),
    .post = NULL },
  { .name = ngx_string("captcha_secret"),
    .type = NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
    .set = ngx_http_set_complex_value_slot,
    .conf = NGX_HTTP_LOC_CONF_OFFSET,
    .offset = offsetof(ngx_http_captcha_location_t, secret),
    .post = NULL },
    ngx_null_command
};

static void *ngx_http_captcha_create_loc_conf(ngx_conf_t *cf) {
    ngx_http_captcha_location_t *location = ngx_pcalloc(cf->pool, sizeof(*location));
    if (!location) return NULL;
    location->icase = NGX_CONF_UNSET;
    location->expire = NGX_CONF_UNSET_UINT;
    location->height = NGX_CONF_UNSET_UINT;
    location->length = NGX_CONF_UNSET_UINT;
    location->size = NGX_CONF_UNSET_UINT;
    location->width = NGX_CONF_UNSET_UINT;
    location->line = NGX_CONF_UNSET_UINT;
    location->star = NGX_CONF_UNSET_UINT;
    location->level = NGX_CONF_UNSET;
    return location;
}

static char *ngx_http_captcha_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child) {
    ngx_http_captcha_location_t *prev = parent;
    ngx_http_captcha_location_t *conf = child;
    ngx_conf_merge_value(conf->icase, prev->icase, 1);
    ngx_conf_merge_uint_value(conf->expire, prev->expire, 300);
    ngx_conf_merge_uint_value(conf->height, prev->height, 30);
    ngx_conf_merge_uint_value(conf->length, prev->length, 4);
    ngx_conf_merge_uint_value(conf->size, prev->size, 20);
    ngx_conf_merge_uint_value(conf->width, prev->width, 130);
    ngx_conf_merge_uint_value(conf->line, prev->line, 10);
    ngx_conf_merge_uint_value(conf->star, prev->star, 100);
    ngx_conf_merge_value(conf->level, prev->level, -1);
    if (conf->level > 9) conf->level = 9; else if (conf->level < -1) conf->level = -1;
    ngx_conf_merge_str_value(conf->charset, prev->charset, "abcdefghkmnprstuvwxyzABCDEFGHKMNPRSTUVWXYZ23456789");
    ngx_conf_merge_str_value(conf->csrf, prev->csrf, "csrf");
    ngx_conf_merge_str_value(conf->font, prev->font, "/usr/local/share/fonts/NimbusSans-Regular.ttf");
    ngx_conf_merge_str_value(conf->name, prev->name, "Captcha");
    if (!conf->answer) conf->answer = prev->answer;
    if (!conf->flags) conf->flags = prev->flags;
    if (!conf->secret) conf->secret = prev->secret;
    if (conf->size > conf->height) return "captcha size is too large";
    if (!conf->length) return "captcha length cannot be zero";
    if (!conf->name.len) return "captcha name cannot be empty";
//    if (!conf->secret) return "captcha secret cannot be empty";
    if (!conf->font.len) return "captcha font cannot be empty";
    if (!conf->charset.len) return "captcha charset cannot be empty";
    if (!conf->csrf.len) return "captcha csrf cannot be empty";
    if (prev->cookie && prev->arg && conf->csrf.len == prev->csrf.len && !ngx_strncmp(conf->csrf.data, prev->csrf.data, conf->csrf.len)) {
        conf->cookie = prev->cookie;
        conf->arg = prev->arg;
    } else {
        ngx_str_t name;
        name.len = conf->csrf.len + sizeof("cookie_%V") - 1 - 2;
        if (!(name.data = ngx_pnalloc(cf->pool, name.len))) return "!ngx_pnalloc";
        if (ngx_snprintf(name.data, name.len, "cookie_%V", &conf->csrf) != name.data + name.len) return "ngx_snprintf";
        ngx_int_t index = ngx_http_get_variable_index(cf, &name);
        if (index == NGX_ERROR) return "ngx_http_get_variable_index == NGX_ERROR";
        conf->cookie = (ngx_uint_t) index;
        name.data += 3;
        name.len -= 3;
        name.data[0] = 'a';
        name.data[1] = 'r';
        name.data[2] = 'g';
        index = ngx_http_get_variable_index(cf, &name);
        if (index == NGX_ERROR) return "ngx_http_get_variable_index == NGX_ERROR";
        conf->arg = (ngx_uint_t) index;
    }
    ngx_str_t cookie;
    cookie.len = conf->name.len + sizeof("cookie_%V") - 1 - 2;
    if (!(cookie.data = ngx_pnalloc(cf->pool, cookie.len))) return "!ngx_pnalloc";
    if (ngx_snprintf(cookie.data, cookie.len, "cookie_%V", &conf->name) != cookie.data + cookie.len) return "ngx_snprintf";
    ngx_int_t index = ngx_http_get_variable_index(cf, &cookie);
    if (index == NGX_ERROR) return "ngx_http_get_variable_index == NGX_ERROR";
    conf->captcha = (ngx_uint_t) index;
    return NGX_CONF_OK;
}

static ngx_int_t ngx_http_captcha_preconfiguration(ngx_conf_t *cf) {
    ngx_str_t name = ngx_string("captcha_valid");
    ngx_http_variable_t *var = ngx_http_add_variable(cf, &name, NGX_HTTP_VAR_NOCACHEABLE);
    if (!var) return NGX_ERROR;
    var->get_handler = ngx_http_captcha_valid_variable;
    return NGX_OK;
}

static ngx_http_module_t ngx_http_captcha_ctx = {
    .preconfiguration = ngx_http_captcha_preconfiguration,
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
    .ctx = &ngx_http_captcha_ctx,
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
