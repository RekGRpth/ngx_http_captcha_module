#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_md5.h>
#include <time.h>
#include <gd.h>
#include <gd_errors.h>
#include <gdfontt.h>  /* 1 Tiny font */
#include <gdfonts.h>  /* 2 Small font */
#include <gdfontmb.h> /* 3 Medium bold font */
#include <gdfontl.h>  /* 4 Large font */
#include <gdfontg.h>  /* 5 Giant font */

#define M_PI 3.14159265358979323846
#define CHARSET "abcdefghkmnprstuvwxyzABCDEFGHKMNPRSTUVWXYZ23456789"
#define FONT_SIZE 20
#define CAPTCHA_CODE_LEN 4
#define CAPTCHA_CODE_LEN_MAX 6
#define CAPTCHA_WIDTH 130
#define CAPTCHA_HEIGHT 30
#define CAPTCHA_EXPIRE 3600
#define CAPTCHA_COOKIE_NAME "captcha_code"
#define CAPTCHA_ARG_NAME CAPTCHA_COOKIE_NAME
#define CAPTCHA_SECURITY_KEY "FD^Shcv&"

unsigned seed;

typedef struct {
    ngx_flag_t enable;
    ngx_uint_t width;
    ngx_uint_t height;
    ngx_uint_t length;
    ngx_uint_t size;
    ngx_uint_t expire;
    ngx_str_t font;
    ngx_str_t hash;
    ngx_str_t salt;
    ngx_str_t secret;
    ngx_str_t charset;
} ngx_http_captcha_loc_conf_t;

typedef struct _png_stream_buffer {
    char *buffer;
    size_t size;
    ngx_pool_t *pool;
} png_stream_buffer;

typedef struct _ngx_captcha_cookie{
    ngx_str_t path;
    ngx_str_t domain;
    ngx_str_t expire;
    ngx_str_t name;
    ngx_str_t value;
} ngx_captcha_cookie;

static void *ngx_prealloc(ngx_pool_t *pool, void *p, size_t old_size, size_t new_size);
static int mt_rand(int min, int max);
static void create_code(char *code, int len, char *charset, int charset_len);
static gdImagePtr create_bg(int width, int height);
static void gd_image_TTF_text(gdImagePtr img,int font_size, int angle, long x, long y, long font_color, const char *font, char *str);
static void create_font(gdImagePtr img, char *code, int len, int width, int height, char *font, int size);
static void create_line(gdImagePtr img, int width, int height, char *font);
static void _image_output_putc(struct gdIOCtx *ctx, int c);
static int _image_output_putbuf(struct gdIOCtx *ctx, const void* buf, int len);
static void _image_output_ctxfree(struct gdIOCtx *ctx);
static void freeCtx(ngx_pool_t *pool, gdIOCtx *ctx);
static void get_png_stream_buffer(ngx_pool_t *pool, gdImagePtr img, char *buf, int *len);
static in_addr_t get_remote_ip(ngx_http_request_t *r);
static ngx_str_t get_user_agent(ngx_http_request_t *r);
static u_char *get_unique_id(ngx_http_request_t *r);
static void create_captcha_png(ngx_http_request_t *r, char *buf, int *len, char *code);
static ngx_captcha_cookie *generate_captcha_cookie(ngx_http_request_t *r);
static ngx_int_t set_captcha_cookie(ngx_http_request_t *r);
static char *ngx_http_captcha_conf(ngx_conf_t *, ngx_command_t *, void *);
static ngx_int_t ngx_http_captcha_handler(ngx_http_request_t *r);
static void* ngx_http_captcha_create_loc_conf(ngx_conf_t *cf);
static char* ngx_http_captcha_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child);

static ngx_command_t ngx_http_captcha_commands[] = {
  {
    ngx_string("captcha_charset"),
    NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
    ngx_conf_set_str_slot,
    NGX_HTTP_LOC_CONF_OFFSET,
    offsetof(ngx_http_captcha_loc_conf_t, charset),
    NULL
  },
  {
    ngx_string("captcha_font"),
    NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
    ngx_conf_set_str_slot,
    NGX_HTTP_LOC_CONF_OFFSET,
    offsetof(ngx_http_captcha_loc_conf_t, font),
    NULL
  },
  {
    ngx_string("captcha_size"),
    NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
    ngx_conf_set_num_slot,
    NGX_HTTP_LOC_CONF_OFFSET,
    offsetof(ngx_http_captcha_loc_conf_t, size),
    NULL
  },
  {
    ngx_string("captcha_width"),
    NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
    ngx_conf_set_num_slot,
    NGX_HTTP_LOC_CONF_OFFSET,
    offsetof(ngx_http_captcha_loc_conf_t, width),
    NULL
  },
  {
    ngx_string("captcha_height"),
    NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
    ngx_conf_set_num_slot,
    NGX_HTTP_LOC_CONF_OFFSET,
    offsetof(ngx_http_captcha_loc_conf_t, height),
    NULL
  },
  {
    ngx_string("captcha_length"),
    NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
    ngx_conf_set_num_slot,
    NGX_HTTP_LOC_CONF_OFFSET,
    offsetof(ngx_http_captcha_loc_conf_t, length),
    NULL
  },
  {
    ngx_string("captcha_expire"),
    NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
    ngx_conf_set_num_slot,
    NGX_HTTP_LOC_CONF_OFFSET,
    offsetof(ngx_http_captcha_loc_conf_t, expire),
    NULL
  },
  {
    ngx_string("captcha_hash"),
    NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
    ngx_conf_set_str_slot,
    NGX_HTTP_LOC_CONF_OFFSET,
    offsetof(ngx_http_captcha_loc_conf_t, hash),
    NULL
  },
  {
    ngx_string("captcha_salt"),
    NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
    ngx_conf_set_str_slot,
    NGX_HTTP_LOC_CONF_OFFSET,
    offsetof(ngx_http_captcha_loc_conf_t, salt),
    NULL
  },
  {
    ngx_string("captcha_secret"),
    NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
    ngx_conf_set_str_slot,
    NGX_HTTP_LOC_CONF_OFFSET,
    offsetof(ngx_http_captcha_loc_conf_t, secret),
    NULL
  },
  {
    ngx_string("captcha"),
    NGX_HTTP_LOC_CONF | NGX_CONF_NOARGS,
    ngx_http_captcha_conf,
    NGX_HTTP_LOC_CONF_OFFSET,
    0,
    NULL
  },
  ngx_null_command
};

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

static void *ngx_prealloc(ngx_pool_t *pool, void *p, size_t old_size, size_t new_size) {
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

static int mt_rand(int min, int max) {
    srand(seed++);
    return (rand() % (max-min+1)) + min;
}

static void create_code(char *code, int len, char *charset, int charset_len) {
    int i = 0;
    int idx = 0;
    for(i=0; i < len; i++) {
        idx = mt_rand(0, charset_len-1);
        code[i] = charset[idx];
    }
}

static gdImagePtr create_bg(int width, int height) {
    gdImagePtr img;
    int color;
    img = gdImageCreateTrueColor(width, height);
    color = gdImageColorAllocate(img, mt_rand(157,255), mt_rand(157,255), mt_rand(157,255));
    gdImageFilledRectangle(img,0,height,width,0,color);
    return img;
}

static void gd_image_TTF_text(gdImagePtr img,int font_size, int angle, long x, long y, long font_color, const char *font, char *str) {
    int brect[8];
    gdImageStringFT(img, brect, font_color, (char *)font, font_size, angle * (M_PI/180), x, y, str);
}

static void create_font(gdImagePtr img, char *code, int len, int width, int height, char *font, int size) {
    int x = width / len;
    int i = 0;
    int font_color = 0;
    char str[2] = "\0";
    for (i=0; i<len; i++)     {
        memcpy(str, code++, 1);
        font_color = gdImageColorAllocate(img,mt_rand(0,156),mt_rand(0,156),mt_rand(0,156));
        gd_image_TTF_text(img,size,mt_rand(-30,30),x*i+mt_rand(1,5),height/1.4,font_color,font,str);
    }
}

static void create_line(gdImagePtr img, int width, int height, char *font) {
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

static void _image_output_putc(struct gdIOCtx *ctx, int c) { }

static int _image_output_putbuf(struct gdIOCtx *ctx, const void* buf, int len) {
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

static void _image_output_ctxfree(struct gdIOCtx *ctx) { }

static void freeCtx(ngx_pool_t *pool, gdIOCtx *ctx) {
    png_stream_buffer *p = (png_stream_buffer *)ctx->data;
    ngx_pfree(pool, p->buffer);//free 3
    ngx_pfree(pool, ctx->data);//free 1
    //ctx->gd_free(ctx);
    ngx_pfree(pool, ctx);//free 2
}

static void get_png_stream_buffer(ngx_pool_t *pool, gdImagePtr img, char *buf, int *len) {
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

static void create_captcha_png(ngx_http_request_t *r, char *buf, int *len, char *code) {
    ngx_http_captcha_loc_conf_t *captcha = ngx_http_get_module_loc_conf(r, ngx_http_captcha_module);
    gdImagePtr img;
    seed = (unsigned int)time(NULL);
    create_code(code, captcha->length, (char *)captcha->charset.data, captcha->charset.len);
    img = create_bg(captcha->width, captcha->height);
    create_font(img, code, captcha->length, captcha->width, captcha->height, (char *)captcha->font.data, captcha->size);
    create_line(img, captcha->width, captcha->height, (char *)captcha->font.data);
    get_png_stream_buffer(r->pool, img, buf, len);
    gdImageDestroy(img);
}

static char *ngx_http_captcha_conf(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {
    ngx_http_captcha_loc_conf_t *cplcf = conf;
    ngx_http_core_loc_conf_t *clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
    clcf->handler = ngx_http_captcha_handler;
    ngx_conf_set_num_slot(cf, cmd, conf);
    cplcf->enable = 1;
    return NGX_CONF_OK;
}

static ngx_captcha_cookie *generate_captcha_cookie(ngx_http_request_t *r) {
    ngx_http_captcha_loc_conf_t *captcha = ngx_http_get_module_loc_conf(r, ngx_http_captcha_module);
    u_char *value;
    size_t value_len;
    u_char *expire, *p;
    size_t expire_len;
    size_t exp_len;
    ngx_captcha_cookie *captcha_cookie;
    captcha_cookie = (ngx_captcha_cookie *)ngx_pcalloc(r->pool, sizeof(ngx_captcha_cookie));//alloc 7
    value = get_unique_id(r);
    value_len = 16;
    exp_len = ngx_strlen("; expires=");
    expire = (u_char *)ngx_pcalloc(r->pool, exp_len+40);//alloc 8
    p = expire;
    p = ngx_copy(p, "; expires=", exp_len);
    p = ngx_http_cookie_time(p, ngx_time()+ 8*3600 + captcha->expire);
    expire_len = ngx_strlen((const char *)expire);
    captcha_cookie->name.data = (u_char *)CAPTCHA_COOKIE_NAME;
    captcha_cookie->name.len = strlen(CAPTCHA_COOKIE_NAME);
    captcha_cookie->value.data = value;
    captcha_cookie->value.len = value_len;
    captcha_cookie->expire.data = expire;
    captcha_cookie->expire.len = expire_len;
    captcha_cookie->path.data = (u_char *)"; path=/;";
    captcha_cookie->path.len = ngx_strlen("; path=/;");
    return captcha_cookie;
}

static ngx_int_t set_captcha_cookie(ngx_http_request_t *r) {
    u_char           *cookie, *p;
    size_t           len;
    ngx_table_elt_t  *set_cookie;
    ngx_captcha_cookie *captcha_cookie = generate_captcha_cookie(r);
    len = captcha_cookie->name.len+1+captcha_cookie->value.len;
    if (captcha_cookie->expire.len) {
        len += captcha_cookie->expire.len;
    }
    if (captcha_cookie->path.len) {
        len += captcha_cookie->path.len;
    }
    cookie = ngx_pnalloc(r->pool, len);//alloc 9
    if (cookie == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "cookie ngx_pnalloc error length[%d]", len);
        return NGX_ERROR;
    }
    p = ngx_copy(cookie, captcha_cookie->name.data, captcha_cookie->name.len);
    *p++ = '=';
    p = ngx_copy(p, captcha_cookie->value.data, captcha_cookie->value.len);
    if (captcha_cookie->expire.len) {
        p = ngx_copy(p, captcha_cookie->expire.data, captcha_cookie->expire.len);
    }
    if (captcha_cookie->path.len) {
        p = ngx_copy(p, captcha_cookie->path.data, captcha_cookie->path.len);
    }
    ngx_pfree(r->pool, captcha_cookie->value.data);//free 6
    ngx_pfree(r->pool, captcha_cookie->expire.data);//free 8
    ngx_pfree(r->pool, captcha_cookie);//free 7
    set_cookie = ngx_list_push(&r->headers_out.headers);
    if (set_cookie == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "set_cookie ngx_list_push error cookie[%s]", cookie);
        return NGX_ERROR;
    }
    set_cookie->hash = 1;
    ngx_str_set(&set_cookie->key, "Set-Cookie");
    set_cookie->value.len = p - cookie;
    set_cookie->value.data = cookie;
    ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "captcha cookie: \"%V\"", &set_cookie->value);
    return NGX_OK;
}

static in_addr_t get_remote_ip(ngx_http_request_t *r) {
    in_addr_t             inaddr;
    struct sockaddr_in    *sin;
    sin = (struct sockaddr_in *) r->connection->sockaddr;
    inaddr = ntohl(sin->sin_addr.s_addr);
    return inaddr;
}

static ngx_str_t get_user_agent(ngx_http_request_t *r) {
    return r->headers_in.user_agent->value;
}

static u_char *get_unique_id(ngx_http_request_t *r) {
    u_char *crc_str;
    ngx_md5_t md5;
    u_char *hash;
    ngx_str_t ua;
    in_addr_t ip;
    ip = get_remote_ip(r);
    ua = get_user_agent(r);
    hash = ngx_pcalloc(r->pool, 17*sizeof(u_char));//alloc 6
    crc_str = ngx_pcalloc(r->pool, ua.len+19);//alloc n
    ngx_sprintf(crc_str, "%ul%s%s", ip, ua.data, CAPTCHA_SECURITY_KEY);
    ngx_md5_init(&md5);
    ngx_md5_update(&md5, crc_str, ngx_strlen(crc_str));
    ngx_md5_final(hash, &md5);
    ngx_pfree(r->pool, crc_str);//free n
    return hash;
}

static ngx_int_t ngx_http_captcha_handler(ngx_http_request_t *r) {
    int len = 0;
    u_char img_buf[6144] = {"\0"};
    u_char code[CAPTCHA_CODE_LEN_MAX] = {"\0"};
    create_captcha_png(r, (char *)img_buf, &len, (char *)code);
    set_captcha_cookie(r);
    r->headers_out.status = 200;
    r->headers_out.content_length_n = len;
    ngx_str_set(&r->headers_out.content_type, "image/png");
    ngx_http_send_header(r);
    ngx_buf_t *b;
    b = ngx_pcalloc(r->pool, sizeof(ngx_buf_t));
    ngx_chain_t out;
    out.buf = b;
    out.next = NULL;
    b->pos = (u_char *)img_buf;
    b->last = (u_char *)img_buf + len;
    b->memory = 1;
    b->last_buf = 1;
    return ngx_http_output_filter(r, &out);
}

static void *ngx_http_captcha_create_loc_conf(ngx_conf_t *cf) {
    ngx_http_captcha_loc_conf_t *conf;
    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_captcha_loc_conf_t));
    if (conf == NULL) {
        return NGX_CONF_ERROR;
    }
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
    ngx_conf_merge_uint_value(conf->width, prev->width, CAPTCHA_WIDTH);
    ngx_conf_merge_uint_value(conf->height, prev->height, CAPTCHA_HEIGHT);
    ngx_conf_merge_uint_value(conf->length, prev->length, CAPTCHA_CODE_LEN);
    ngx_conf_merge_uint_value(conf->expire, prev->expire, CAPTCHA_EXPIRE);
    ngx_conf_merge_uint_value(conf->size, prev->size, FONT_SIZE);
    ngx_conf_merge_str_value(conf->font, prev->font, "simsun");
    ngx_conf_merge_str_value(conf->charset, prev->charset, CHARSET);
    ngx_conf_merge_str_value(conf->hash, prev->hash, "captcha_h");
    ngx_conf_merge_str_value(conf->salt, prev->salt, "captcha_s");
    ngx_conf_merge_str_value(conf->secret, prev->secret, "yoursecret");
    ngx_conf_merge_value(conf->enable, prev->enable, 0);
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
