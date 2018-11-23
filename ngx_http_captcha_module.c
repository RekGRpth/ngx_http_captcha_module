#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_md5.h>
#include <time.h>
#include <gd.h>

#define M_PI 3.14159265358979323846
#define CAPTCHA_CHARSET "abcdefghkmnprstuvwxyzABCDEFGHKMNPRSTUVWXYZ23456789"
#define CAPTCHA_LENGTH 4
#define CAPTCHA_EXPIRE 3600
#define CAPTCHA_FONT "/usr/share/fonts/ttf-dejavu/DejaVuSans.ttf"
#define CAPTCHA_HASH "captcha_hash"
#define CAPTCHA_HEIGHT 30
#define CAPTCHA_SALT "captcha_salt"
#define CAPTCHA_SECRET "captcha_secret"
#define CAPTCHA_SIZE 20
#define CAPTCHA_WIDTH 130
#define HASHLEN 16 // 0 - 32

unsigned seed;

typedef struct {
    ngx_flag_t enable;
    ngx_uint_t expire;
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

typedef struct {
    char *buffer;
    size_t size;
    ngx_pool_t *pool;
} png_stream_buffer;

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
    ngx_string("captcha_expire"),
    NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
    ngx_conf_set_num_slot,
    NGX_HTTP_LOC_CONF_OFFSET,
    offsetof(ngx_http_captcha_loc_conf_t, expire),
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

static inline void md5_make_digest(char *md5str, const unsigned char *digest, int len) {
    static const char hexits[17] = "0123456789abcdef";
    for (int i = 0; i < len; i++) {
        md5str[i * 2]       = hexits[digest[i] >> 4];
        md5str[(i * 2) + 1] = hexits[digest[i] & 0x0F];
    }
}

static inline void *ngx_prealloc(ngx_pool_t *pool, void *p, size_t old_size, size_t new_size) {
    void *new;
    if (p == NULL) {
        return ngx_palloc(pool, new_size);
    }
    if (new_size == 0) {
        if ((u_char *) p + old_size == pool->d.last) {
           pool->d.last = p;
        } else {
           ngx_pfree(pool, p);
        }
        return NULL;
    }
    if ((u_char *) p + old_size == pool->d.last && (u_char *) p + new_size <= pool->d.end) {
        pool->d.last = (u_char *) p + new_size;
        return p;
    }
    new = ngx_palloc(pool, new_size);
    if (new == NULL) {
        return NULL;
    }
    ngx_memcpy(new, p, old_size);
    ngx_pfree(pool, p);
    return new;
}

static inline int mt_rand(int min, int max) {
    srand(seed++);
    return (rand() % (max - min + 1)) + min;
}

static inline void create_code(char *code, int code_len, char *charset, int charset_len) {
    for (int i=0; i < code_len; i++) code[i] = charset[mt_rand(0, charset_len - 1)];
}

static inline gdImagePtr create_bg(int width, int height) {
    gdImagePtr img;
    int color;
    img = gdImageCreateTrueColor(width, height);
    color = gdImageColorAllocate(img, mt_rand(157, 255), mt_rand(157, 255), mt_rand(157, 255));
    gdImageFilledRectangle(img,0,height,width,0,color);
    return img;
}

static inline void gd_image_TTF_text(gdImagePtr img,int font_size, int angle, long x, long y, long font_color, const char *font, char *str) {
    int brect[8];
    gdImageStringFT(img, brect, font_color, (char *)font, font_size, angle * (M_PI/180), x, y, str);
}

static inline void create_font(gdImagePtr img, char *code, int len, int width, int height, char *font, int size) {
    int x = width / len;
    int i = 0;
    int font_color = 0;
    char str[2] = "\0";
    for (i=0; i<len; i++)     {
        memcpy(str, code++, 1);
        font_color = gdImageColorAllocate(img,mt_rand(0, 156),mt_rand(0, 156),mt_rand(0, 156));
        gd_image_TTF_text(img,size,mt_rand(-30, 30),x*i+mt_rand(1,5),height/1.4,font_color,font,str);
    }
}

static inline void create_line(gdImagePtr img, int width, int height, char *font) {
    int i, brect[8];
    int color = 0;
    const char *str = "*";
    int font_size = 8;
    int angle = 0;
    for (i=0;i<6;i++) {
        color = gdImageColorAllocate(img,mt_rand(0,156),mt_rand(0,156),mt_rand(0,156));
        gdImageLine(img,mt_rand(0,width),mt_rand(0,height),mt_rand(0,width),mt_rand(0,height),color);
    }
    for (i=0;i<100;i++) {
        color = gdImageColorAllocate(img,mt_rand(200,255),mt_rand(200,255),mt_rand(200,255));
        gdImageStringFT(img, brect, color, font, font_size, angle, mt_rand(0,width), mt_rand(0,height), (char *)str);
    }
}

static inline void _image_output_putc(struct gdIOCtx *ctx, int c) { }

static inline int _image_output_putbuf(struct gdIOCtx *ctx, const void* buf, int len) {
    png_stream_buffer *p = (png_stream_buffer *)ctx->data;
    size_t nsize = p->size + len;
    if (p->buffer) {
        p->buffer = ngx_prealloc(p->pool, p->buffer, p->size, nsize);
    } else {
        p->buffer = ngx_pcalloc(p->pool, nsize);//alloc 1
    }
    if (!p->buffer) {
        return -1;
    }
    memcpy(p->buffer + p->size, buf, len);
    p->size += len;
    return 0;
}

static inline void _image_output_ctxfree(struct gdIOCtx *ctx) { }

static inline void freeCtx(ngx_pool_t *pool, gdIOCtx *ctx) {
    png_stream_buffer *p = (png_stream_buffer *)ctx->data;
    ngx_pfree(pool, p->buffer);//free 3
    ngx_pfree(pool, ctx->data);//free 1
    //ctx->gd_free(ctx);
    ngx_pfree(pool, ctx);//free 2
}

static inline void get_png_stream_buffer(ngx_pool_t *pool, gdImagePtr img, char *buf, int *len) {
    int q = -1;
    gdIOCtx *ctx;
    png_stream_buffer *p;
    ctx = (gdIOCtx *)ngx_pcalloc(pool, sizeof(gdIOCtx));//alloc 2
    ctx->putC = _image_output_putc;
    ctx->putBuf = _image_output_putbuf;
    ctx->gd_free = _image_output_ctxfree;
    p = (png_stream_buffer *)ngx_pcalloc(pool, sizeof(png_stream_buffer));//alloc 3
    p->pool = pool;
    ctx->data = p;
    gdImagePngCtxEx(img, ctx, q);
    p = (png_stream_buffer *)ctx->data;
    buf = memcpy(buf, p->buffer, p->size);
    *len = p->size;
    freeCtx(pool, ctx);
}

static inline void create_captcha_png(ngx_http_request_t *r, char *buf, int *len, char *code) {
    ngx_http_captcha_loc_conf_t *captcha = ngx_http_get_module_loc_conf(r, ngx_http_captcha_module);
    gdImagePtr img;
    seed = (unsigned int)time(NULL);
    img = create_bg(captcha->width, captcha->height);
    create_font(img, code, captcha->length, captcha->width, captcha->height, (char *)captcha->font.data, captcha->size);
    create_line(img, captcha->width, captcha->height, (char *)captcha->font.data);
    get_png_stream_buffer(r->pool, img, buf, len);
    gdImageDestroy(img);
}

static inline ngx_int_t set_captcha_cookie(ngx_http_request_t *r, char *code) {
    ngx_http_captcha_loc_conf_t *captcha = ngx_http_get_module_loc_conf(r, ngx_http_captcha_module);
    ngx_md5_t md5;
    ngx_md5_init(&md5);
    ngx_md5_update(&md5, captcha->secret.data, captcha->secret.len);
    ngx_md5_update(&md5, code, captcha->length);
    u_char salt_buf[32];
    size_t salt_buf_len = ngx_sprintf(salt_buf, "%d", ngx_random()) - salt_buf;
    ngx_md5_update(&md5, salt_buf, salt_buf_len);
    u_char hash[16];
    ngx_md5_final(hash, &md5);
    char hash_hex[HASHLEN];
    md5_make_digest(hash_hex, hash, HASHLEN / 2);
    ngx_table_elt_t *set_cookie_hash = ngx_list_push(&r->headers_out.headers);
    ngx_table_elt_t *set_cookie_salt = ngx_list_push(&r->headers_out.headers);
    if (set_cookie_hash == NULL || set_cookie_salt == NULL) return NGX_ERROR;
    /* set_cookie_hash */ {
        set_cookie_hash->hash = 1;
        ngx_str_set(&set_cookie_hash->key, "Set-Cookie");
        int cookie_buf_len = captcha->hash.len + HASHLEN + 1;
        set_cookie_hash->value.data = ngx_palloc(r->pool, cookie_buf_len);
        if (set_cookie_hash->value.data == NULL) return NGX_ERROR;
        /*ngx_sprintf(set_cookie_hash->value.data, "%s=%s", ...);*/
        unsigned char *p = set_cookie_hash->value.data;
        p = ngx_cpymem(p, captcha->hash.data, captcha->hash.len);
        *p++ = '=';
        p = ngx_cpymem(p, hash_hex, HASHLEN);
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
    u_char code[CAPTCHA_LENGTH] = {"\0"};
    create_code((char *)code, captcha->length, (char *)captcha->charset.data, captcha->charset.len);
    rc = set_captcha_cookie(r, (char *)code);
    if (rc != NGX_OK) return rc;
    r->headers_out.status = NGX_HTTP_OK;
    r->headers_out.content_length_n = 0;
    if (r->method == NGX_HTTP_HEAD) {
        rc = ngx_http_send_header(r);
        if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) return rc;
    }
    ngx_buf_t *b = ngx_pcalloc(r->pool, sizeof(ngx_buf_t));
    if (b == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "Failed to allocate response buffer.");
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    ngx_chain_t out = {.buf = b, .next = NULL};
    int len = 0;
    u_char img_buf[6144] = {"\0"};
    create_captcha_png(r, (char *)img_buf, &len, (char *)code);
    r->headers_out.content_length_n = len;
    b->pos = (u_char *)img_buf;
    b->last = (u_char *)img_buf + len;
    b->memory = 1;
    b->last_buf = 1;
    rc = ngx_http_send_header(r);
    if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) return rc;
    return ngx_http_output_filter(r, &out);
}

static char *ngx_http_captcha_conf(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {
    ngx_http_captcha_loc_conf_t *cplcf = conf;
    ngx_http_core_loc_conf_t *clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
    clcf->handler = ngx_http_captcha_handler;
    ngx_conf_set_num_slot(cf, cmd, conf);
    cplcf->enable = 1;
    return NGX_CONF_OK;
}

static void *ngx_http_captcha_create_loc_conf(ngx_conf_t *cf) {
    ngx_http_captcha_loc_conf_t *conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_captcha_loc_conf_t));
    if (conf == NULL) return NGX_CONF_ERROR;
    conf->width = NGX_CONF_UNSET_UINT;
    conf->height = NGX_CONF_UNSET_UINT;
    conf->length = NGX_CONF_UNSET_UINT;
    conf->expire = NGX_CONF_UNSET_UINT;
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
    conf->enable = NGX_CONF_UNSET;
    return conf;
}

static char *ngx_http_captcha_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child) {
    ngx_http_captcha_loc_conf_t *prev = parent;
    ngx_http_captcha_loc_conf_t *conf = child;
    ngx_conf_merge_value(conf->enable, prev->enable, 0);
    ngx_conf_merge_uint_value(conf->expire, prev->expire, CAPTCHA_EXPIRE);
    ngx_conf_merge_uint_value(conf->height, prev->height, CAPTCHA_HEIGHT);
    ngx_conf_merge_uint_value(conf->length, prev->length, CAPTCHA_LENGTH);
    ngx_conf_merge_uint_value(conf->size, prev->size, CAPTCHA_SIZE);
    ngx_conf_merge_uint_value(conf->width, prev->width, CAPTCHA_WIDTH);
    ngx_conf_merge_str_value(conf->charset, prev->charset, CAPTCHA_CHARSET);
    ngx_conf_merge_str_value(conf->font, prev->font, CAPTCHA_FONT);
    ngx_conf_merge_str_value(conf->hash, prev->hash, CAPTCHA_HASH);
    ngx_conf_merge_str_value(conf->salt, prev->salt, CAPTCHA_SALT);
    ngx_conf_merge_str_value(conf->secret, prev->secret, CAPTCHA_SECRET);
    if (conf->width > CAPTCHA_WIDTH) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "width must be less than %d", CAPTCHA_WIDTH);
        return NGX_CONF_ERROR;
    }
    if (conf->height > CAPTCHA_HEIGHT) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "height must be less than %d", CAPTCHA_HEIGHT);
        return NGX_CONF_ERROR;
    }
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
