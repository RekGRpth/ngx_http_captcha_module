#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_md5.h>
//#include <hiredis/hiredis.h>
#include <time.h>
#include <gd.h>
#include <gd_errors.h>
#include <gdfontt.h>  /* 1 Tiny font */
#include <gdfonts.h>  /* 2 Small font */
#include <gdfontmb.h> /* 3 Medium bold font */
#include <gdfontl.h>  /* 4 Large font */
#include <gdfontg.h>  /* 5 Giant font */


#define M_PI 3.14159265358979323846
//#define MAXPATHLEN 256
#define CHARSET "abcdefghkmnprstuvwxyzABCDEFGHKMNPRSTUVWXYZ23456789"
#define CHARSET_LEN sizeof(CHARSET)
#define FONT_SIZE 20
#define TTFTEXT_DRAW 0
#define CAPTCHA_CODE_LEN 4
#define CAPTCHA_CODE_LEN_MAX 6
#define CAPTCHA_WIDTH 130
#define CAPTCHA_HEIGHT 30
//#define CAPTCHA_REDIS_HOST "127.0.0.1"
//#define CAPTCHA_REDIS_PORT 6379
#define CAPTCHA_EXPIRE 3600
#define CAPTCHA_COOKIE_NAME "captcha_code"
#define CAPTCHA_ARG_NAME CAPTCHA_COOKIE_NAME
#define CAPTCHA_SECURITY_KEY "FD^Shcv&"
//#define AUTH_SUCCESS "{\"code\" : 0, \"data\" : [], \"message\" : \"SUCCESS\"}"
//#define AUTH_FAIL "{\"code\" : -1, \"data\" : [], \"message\" : \"FAIL\"}"

unsigned seed;

/*typedef struct _ngx_captcha_redis_conf {
    char *host;
    int port;
} ngx_captcha_redis_conf;*/

typedef struct {
    ngx_uint_t width;
    ngx_uint_t height;
    ngx_uint_t length;
    ngx_str_t font;
    ngx_uint_t size;
    char *font_cstr;
//    char * font;
    ngx_uint_t expire;
    ngx_str_t hash;
    ngx_str_t salt;
    ngx_str_t secret;
//    ngx_captcha_redis_conf * redis_conf;
    ngx_flag_t enable;
} ngx_http_captcha_loc_conf_t;

typedef struct _png_stream_buffer {
    char *buffer;
    size_t size;
    ngx_pool_t * pool;
} png_stream_buffer;


typedef struct _ngx_captcha_cookie{
    ngx_str_t path;
    ngx_str_t domain;
    ngx_str_t expire;
    ngx_str_t name;
    ngx_str_t value;
} ngx_captcha_cookie;

static void * ngx_prealloc(ngx_pool_t *pool, void *p, size_t old_size, size_t new_size); 
static int mt_rand(int min, int max);
static void create_code(char * code, int len);
static gdImagePtr create_bg(int width, int height);
static void gd_image_TTF_text(gdImagePtr img,int font_size, int angle, long x, long y, long font_color, const char * font, char *str);
static void create_font(gdImagePtr img, char *code, int len, int width, int height, char * font, int size);
static void create_line(gdImagePtr img, int width, int height, char * font);
static void _image_output_putc(struct gdIOCtx *ctx, int c);
static int _image_output_putbuf(struct gdIOCtx *ctx, const void* buf, int len);
static void _image_output_ctxfree(struct gdIOCtx *ctx);
static void freeCtx(ngx_pool_t * pool, gdIOCtx *ctx);
static void get_png_stream_buffer(ngx_pool_t * pool, gdImagePtr img, char *buf, int *len);
static in_addr_t get_remote_ip(ngx_http_request_t *r);
static ngx_str_t get_user_agent(ngx_http_request_t *r);
static u_char * get_unique_id(ngx_http_request_t *r);
//static u_char * user_crc_hash(ngx_http_request_t *r);
//static redisContext * connectRedis(char *host, int port, ngx_log_t *log);
//static ngx_int_t closeRedisConnect(redisContext *conn);
//static ngx_int_t redisSetex(redisContext *conn, char *key, int expire_time, char *val, ngx_log_t *log);
//static ngx_int_t redisGet(redisContext *conn, char *key, u_char * result, ngx_log_t *log);
//static void create_captcha_png(ngx_pool_t * pool, char *buf, int *len, char * code, ngx_http_captcha_loc_conf_t *captcha);
static void create_captcha_png(ngx_http_request_t *r, char *buf, int *len, char *code);
//static void create_captcha_img(ngx_pool_t * pool, char * img_buf, int *len, char * code, ngx_http_captcha_loc_conf_t *captcha_conf);
//static void save_captcha_code(ngx_http_request_t *r, char * code);
static ngx_captcha_cookie * generate_captcha_cookie(ngx_http_request_t *r);
static ngx_int_t set_captcha_cookie(ngx_http_request_t *r);
//static ngx_uint_t get_captcha_cookie(ngx_http_request_t *r, u_char * captcha_id);
//static ngx_uint_t get_query_param_value(ngx_http_request_t *r, const char * param_name, ngx_str_t *param_value);
//static ngx_int_t get_user_captcha_code(ngx_http_request_t *r, u_char *input_code);
//static char *set_captcha_init(ngx_conf_t *, ngx_command_t *, void *);
//static char *set_captcha_font(ngx_conf_t *, ngx_command_t *, void *);
//static char *set_captcha_width(ngx_conf_t *, ngx_command_t *, void *);
//static char *set_captcha_height(ngx_conf_t *, ngx_command_t *, void *);
//static char *set_captcha_length(ngx_conf_t *, ngx_command_t *, void *);
//static char *set_captcha_expire(ngx_conf_t *, ngx_command_t *, void *);
//static char *set_captcha_redis_conf(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char *ngx_http_captcha_conf(ngx_conf_t *, ngx_command_t *, void *);
static ngx_int_t ngx_http_captcha_handler(ngx_http_request_t *r);
//static char *set_captcha_auth_handler(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
//static ngx_int_t captcha_auth_handler(ngx_http_request_t *r);
static void* ngx_http_captcha_create_loc_conf(ngx_conf_t *cf);
static char* ngx_http_captcha_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child);

static ngx_command_t ngx_http_captcha_commands[] = {
/*  {
    ngx_string("captcha_redis_conf"),
    NGX_HTTP_LOC_CONF | NGX_CONF_TAKE2,
    set_captcha_redis_conf,
    NGX_HTTP_LOC_CONF_OFFSET,
    0,
    NULL
  },*/
/*  {
    ngx_string("captcha_init"),
    NGX_HTTP_LOC_CONF | NGX_CONF_NOARGS,
    set_captcha_init,
    NGX_HTTP_LOC_CONF_OFFSET,
    0,
    NULL
  },*/
/*  {
    ngx_string("captcha_font"),
    NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
    set_captcha_font,
    NGX_HTTP_LOC_CONF_OFFSET,
    0,
    NULL
  },*/
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
/*  {
    ngx_string("captcha_width"),
    NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
    set_captcha_width,
    NGX_HTTP_LOC_CONF_OFFSET,
    0,
    NULL
  },*/
  {
    ngx_string("captcha_width"),
    NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
    ngx_conf_set_num_slot,
    NGX_HTTP_LOC_CONF_OFFSET,
    offsetof(ngx_http_captcha_loc_conf_t, width),
    NULL
  },
/*  {
    ngx_string("captcha_height"),
    NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
    set_captcha_height,
    NGX_HTTP_LOC_CONF_OFFSET,
    0,
    NULL
  },*/
  {
    ngx_string("captcha_height"),
    NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
    ngx_conf_set_num_slot,
    NGX_HTTP_LOC_CONF_OFFSET,
    offsetof(ngx_http_captcha_loc_conf_t, height),
    NULL
  },
/*  {
    ngx_string("captcha_length"),
    NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
    set_captcha_length,
    NGX_HTTP_LOC_CONF_OFFSET,
    0,
    NULL
  },*/
  {
    ngx_string("captcha_length"),
    NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
    ngx_conf_set_num_slot,
    NGX_HTTP_LOC_CONF_OFFSET,
    offsetof(ngx_http_captcha_loc_conf_t, length),
    NULL
  },
/*  {
    ngx_string("captcha_expire"),
    NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
    set_captcha_expire,
    NGX_HTTP_LOC_CONF_OFFSET,
    0,
    NULL
  },*/
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
/*  {
    ngx_string("captcha_auth"),
    NGX_HTTP_LOC_CONF | NGX_CONF_NOARGS,
    set_captcha_auth_handler,
    NGX_HTTP_LOC_CONF_OFFSET,
    0,
    NULL
  },*/
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

//ngx_http_captcha_loc_conf_t * captcha_conf;
//ngx_captcha_redis_conf * redis_conf;

static void * ngx_prealloc(ngx_pool_t *pool, void *p, size_t old_size, size_t new_size) {  
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
   
    if ((u_char *) p + old_size == pool->d.last  
        && (u_char *) p + new_size <= pool->d.end)  
    {  
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

static void create_code(char * code, int len) {
    int i = 0;
    int idx = 0;
    for(i=0; i < len; i++) {
        idx = mt_rand(0, CHARSET_LEN-1);
        code[i] = CHARSET[idx];
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

static void gd_image_TTF_text(gdImagePtr img,int font_size, int angle, long x, long y, long font_color, const char * font, char *str) {
    int brect[8];
//    char * error = NULL;
    angle = angle * (M_PI/180);
    /*error = */gdImageStringFT(img, brect, font_color, (char *)font, font_size, angle, x, y, str);
}

static void create_font(gdImagePtr img, char *code, int len, int width, int height, char * font, int size) {
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

static void create_line(gdImagePtr img, int width, int height, char * font) {
    int i, brect[8];
    int color = 0;
    const char * str = "*";
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
    png_stream_buffer * p = (png_stream_buffer *)ctx->data;
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

static void get_png_stream_buffer(ngx_pool_t * pool, gdImagePtr img, char *buf, int *len) {
    int q = -1;
    gdIOCtx *ctx;
    png_stream_buffer * p;
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
    create_code(code, captcha->length);
    img = create_bg(captcha->width, captcha->height);
    create_font(img, code, captcha->length, captcha->width, captcha->height, captcha->font_cstr, captcha->size);
    create_line(img, captcha->width, captcha->height, captcha->font_cstr);
    get_png_stream_buffer(r->pool, img, buf, len);
    gdImageDestroy(img);
}

/*static void 
redis_conf_init(ngx_conf_t *cf) 
{
  redis_conf = (ngx_captcha_redis_conf *)ngx_pcalloc(cf->pool, sizeof(ngx_captcha_redis_conf));//alloc 4
  redis_conf->host = (char *)CAPTCHA_REDIS_HOST;
  redis_conf->port = CAPTCHA_REDIS_PORT;
};*/


/*static char *
set_captcha_init(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) 
{

  if(!redis_conf)
  {
    redis_conf_init(cf);
  }
  captcha_conf = (ngx_http_captcha_loc_conf_t *)ngx_pcalloc(cf->pool, sizeof(ngx_http_captcha_loc_conf_t));//alloc 5
  captcha_conf->width = CAPTCHA_WIDTH;
  captcha_conf->height = CAPTCHA_HEIGHT;
  captcha_conf->length = CAPTCHA_CODE_LEN;
  captcha_conf->font = NULL;
  captcha_conf->expire = CAPTCHA_EXPIRE;
  captcha_conf->redis_conf = redis_conf;
  return NGX_CONF_OK;
};*/

/*static char *
set_captcha_font(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {
  ngx_str_t *value;
  value = cf->args->elts;
  captcha_conf->font = (char *)value[1].data;
  return NGX_CONF_OK;
};*/

/*static char *
set_captcha_width(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {
  ngx_str_t *value;
  ngx_int_t w;
  value = cf->args->elts;
  w = ngx_atoi(value[1].data, value[1].len);
  captcha_conf->width = w < 0 ? 0 : w;
  return NGX_CONF_OK;
};*/

/*static char *
set_captcha_height(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {
  ngx_str_t *value;
  ngx_int_t h;
  value = cf->args->elts;
  h = ngx_atoi(value[1].data, value[1].len);
  captcha_conf->height = h < 0 ? 0 : h;
  return NGX_CONF_OK;
};*/

/*static char *
set_captcha_length(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {
  ngx_str_t *value;
  ngx_int_t len;
  value = cf->args->elts;
  len = ngx_atoi(value[1].data, value[1].len);
  captcha_conf->length = len > CAPTCHA_CODE_LEN_MAX ? CAPTCHA_CODE_LEN_MAX : len;
  return NGX_CONF_OK;
};*/


/*static char *
set_captcha_expire(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) 
{
  ngx_str_t *value;
  ngx_int_t exp;
  value = cf->args->elts;
  exp = ngx_atoi(value[1].data, value[1].len);
  captcha_conf->expire = exp < 0 ? 0 : exp;
  return NGX_CONF_OK;
};*/


/*static char *
set_captcha_auth_handler(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) 
{
  ngx_http_core_loc_conf_t *corecf;
  corecf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
  corecf->handler = captcha_auth_handler;
  if(!redis_conf)
  {
    redis_conf_init(cf);
  }
  return NGX_CONF_OK;
};*/

/*static char *
set_captcha_redis_conf(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) 
{
  ngx_str_t *value;
  value = cf->args->elts;
  if(!redis_conf)
  {
    redis_conf_init(cf);
  }
  redis_conf->host = (char *)value[1].data;
  redis_conf->port = ngx_atoi(value[2].data, value[2].len);

  return NGX_CONF_OK;
};*/

/*static char *
ngx_http_captcha_conf(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) 
{
  ngx_http_core_loc_conf_t *corecf;
  corecf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
  corecf->handler = ngx_http_captcha_handler;
  return NGX_CONF_OK;
};*/
static char *ngx_http_captcha_conf(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {
    ngx_http_captcha_loc_conf_t *cplcf = conf;
    ngx_http_core_loc_conf_t *clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
    clcf->handler = ngx_http_captcha_handler;
    ngx_conf_set_num_slot(cf, cmd, conf);
    cplcf->enable = 1;
    return NGX_CONF_OK;
}

/*static u_char *
get_unique_id(ngx_http_request_t *r)
{
    return user_crc_hash(r);
}*/

/*static redisContext *
connectRedis(char *host, int port, ngx_log_t *log)
{
    redisContext *conn = redisConnect(host, port);
    if (conn != NULL && conn->err) {
        ngx_log_error(NGX_LOG_ERR, log, 0,
                      "can't connect to redis by host[%s] port[%d]",
                      host,port);
        return conn;
    }

    ngx_log_debug(NGX_LOG_DEBUG_HTTP, log, 0,
                      "connect to redis by host[%s] port[%d]",
                      host,port);
    return conn;
}*/

/*static ngx_int_t
closeRedisConnect(redisContext *conn)
{
    redisFree(conn);
    return NGX_OK;
}*/

/*static ngx_int_t
redisSetex(redisContext *conn, char *key, int expire_time, char *val, ngx_log_t *log)
{
    redisReply *reply;
    reply = redisCommand(conn, "SETEX %s %d %s", key, expire_time, val);
    if (reply->type == REDIS_REPLY_ERROR ) { 
         ngx_log_error(NGX_LOG_ERR, log, 0,
                      "redis command[SETEX %s %d %s] result[%s]",
                      key, expire_time, val, reply->str);
         freeReplyObject(reply);
         closeRedisConnect(conn);  
         return NGX_ERROR;
    } 
    ngx_log_debug(NGX_LOG_DEBUG_HTTP, log, 0,
                      "redis command[SETEX %s %d %s] result[%s]",
                      key, expire_time, val, reply->str);
    freeReplyObject(reply);
    return NGX_OK;
}*/

/*static ngx_int_t
redisGet(redisContext *conn, char *key, u_char * result, ngx_log_t *log)
{ 
    redisReply *reply;
  
    reply = redisCommand(conn, "GET %s", key);
  
    if (reply->type == REDIS_REPLY_ERROR || reply->type == REDIS_REPLY_NIL) { 
          ngx_log_debug(NGX_LOG_DEBUG_HTTP, log, 0,
                      "redis command[GET %s] result[%d]",
                      key, reply->type);
       
    }
    else
    {
        result = ngx_copy(result, (u_char *)reply->str, ngx_strlen(reply->str));

        ngx_log_debug(NGX_LOG_DEBUG_HTTP, log, 0,
                      "redis command[GET %s] result[%s]",
                      key, reply->str);
    }

    freeReplyObject(reply);
    return NGX_OK;
}*/

/*static void 
create_captcha_img(ngx_pool_t * pool, char * img_buf, int *len, char *code, ngx_http_captcha_loc_conf_t * captcha_conf)
{
    create_captcha_png(pool, img_buf, len, code, captcha_conf);
}*/

/*static void 
save_captcha_code(ngx_http_request_t *r, char * code)
{
    u_char * unique_id = get_unique_id(r);
    redisContext * conn = connectRedis(redis_conf->host, redis_conf->port, r->connection->log);
    redisSetex(conn, (char *)unique_id, CAPTCHA_EXPIRE, code, r->connection->log);
    closeRedisConnect(conn);
    ngx_pfree(r->pool, unique_id);//free 6
}*/

static ngx_captcha_cookie *generate_captcha_cookie(ngx_http_request_t *r) {
    ngx_http_captcha_loc_conf_t *captcha = ngx_http_get_module_loc_conf(r, ngx_http_captcha_module);
    u_char * value;
    size_t value_len;
    u_char * expire, *p;
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
//    ngx_http_captcha_loc_conf_t *captcha = ngx_http_get_module_loc_conf(r, ngx_http_captcha_module);
    u_char           *cookie, *p;
    size_t           len;
    ngx_table_elt_t  *set_cookie;
    ngx_captcha_cookie * captcha_cookie = generate_captcha_cookie(r);
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


/*static ngx_uint_t 
get_captcha_cookie(ngx_http_request_t *r, u_char * captcha_id)
{
    ngx_str_t cookie_name;
    ngx_str_t cookie_value;

    cookie_name.data = (u_char *)CAPTCHA_COOKIE_NAME;
    cookie_name.len = ngx_strlen(CAPTCHA_COOKIE_NAME);

    ngx_uint_t n = ngx_http_parse_multi_header_lines(&r->headers_in.cookies, &cookie_name, &cookie_value);
    captcha_id = ngx_cpymem(captcha_id, cookie_value.data, 16);

    return n;
}*/

/*static ngx_uint_t
get_query_param_value(ngx_http_request_t *r, const char * param_name, ngx_str_t *param_value)
{
  size_t param_name_len;
  param_name_len = ngx_strlen(param_name);
  if (ngx_http_arg(r, (u_char *)param_name, param_name_len, param_value) != NGX_OK)
  {
      param_value->len = 0;
  }
  ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                      "get_query_param_value param_name[%s:%d] param_value[%s:%d]",
                      param_name,param_name_len,param_value->data,param_value->len
                      );
  return NGX_OK;
}*/

/*static ngx_int_t
get_user_captcha_code(ngx_http_request_t *r, u_char *input_code)
{
    ngx_int_t ret;
    ngx_str_t param_value;

    if(!(r->method & NGX_HTTP_GET))
    {
      ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                      "get_user_captcha_code request method error");
                      
        return NGX_ERROR;
    }

    ret = ngx_http_discard_request_body(r);

    if(NGX_OK != ret)
    {
       ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                      "get_user_captcha_code discard_request_body error");
       return NGX_ERROR;
    }

    ret = get_query_param_value(r, CAPTCHA_ARG_NAME, &param_value);

    if(ret == NGX_OK)
    {
      input_code = ngx_cpymem(input_code, param_value.data, param_value.len);

      return NGX_OK;
    }

    return NGX_ERROR;
}*/

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
    u_char * crc_str;
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
    //  save_captcha_code(r, (char *)code);
    set_captcha_cookie(r);
//    ngx_pfree(r->pool, captcha_conf);//free 5
    //  ngx_pfree(r->pool, redis_conf);//free 4
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


/*static ngx_int_t
captcha_auth_handler(ngx_http_request_t *r) 
{
  size_t len = 0;
  ngx_int_t ret;
  u_char * auth_result;
  u_char captcha_id[17] = {"\0"};
  u_char * unique_id;
  u_char input_code[CAPTCHA_CODE_LEN_MAX] = {"\0"};;
  u_char code[CAPTCHA_CODE_LEN_MAX] = {"\0"};
  redisContext * conn = NULL;

  ret = get_user_captcha_code(r, input_code);

  if(ret != NGX_OK)
  {
     ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                      "captcha_auth_handler get_user_captcha_code fail"
                      );

    goto auth_fail;
  }
  
  unique_id = get_unique_id(r);
  get_captcha_cookie(r, captcha_id);
  
  if(0 != ngx_strcasecmp(unique_id, captcha_id))
  {
    ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                      "captcha_auth_handler code is equal input_code[%s] redis_code[%s]",
                      input_code,code
                      );
    ngx_pfree(r->pool, unique_id);//free 6
    goto auth_fail;
  }

  ngx_pfree(r->pool, unique_id);//free 6
    
  conn = connectRedis(redis_conf->host, redis_conf->port, r->connection->log);
  if(!conn)
  {
    ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                      "captcha_auth_handler code is equal input_code[%s] redis_code[%s]",
                      input_code,code
                      );
    goto auth_fail;
  }
    
  redisGet(conn, (char *)captcha_id, code, r->connection->log);
  closeRedisConnect(conn);
  
  if(0 != ngx_strcasecmp(&input_code[0], code))
  {
    ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                      "captcha_auth_handler code is not equal input_code[%s] redis_code[%s]",
                      input_code,code
                      );

    goto auth_fail;
  }
  else
  {
    ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                      "captcha_auth_handler code is equal input_code[%s] redis_code[%s]",
                      input_code,code
                      );

    len = ngx_strlen(AUTH_SUCCESS);
    auth_result = (u_char *)AUTH_SUCCESS;
    goto output;
  }
  

auth_fail:
  len = ngx_strlen(AUTH_FAIL);
  auth_result = (u_char *)AUTH_FAIL;
  goto output;

output:
  ngx_pfree(r->pool, captcha_conf);//free 5
  ngx_pfree(r->pool, redis_conf);//free 4

  r->headers_out.status = 200;
  r->headers_out.content_length_n = len;
  ngx_str_set(&r->headers_out.content_type, "application/json");
  ngx_http_send_header(r);
 
  ngx_buf_t *b;
  b = ngx_pcalloc(r->pool, sizeof(ngx_buf_t));
  ngx_chain_t out;
  out.buf = b;
  out.next = NULL;
  b->pos = auth_result;
  b->last = auth_result + len;
  b->memory = 1;
  b->last_buf = 1;
 
 return ngx_http_output_filter(r, &out);
}*/

static void *ngx_http_captcha_create_loc_conf(ngx_conf_t *cf) {
    ngx_http_captcha_loc_conf_t *conf;
    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_captcha_loc_conf_t));
    if (conf == NULL) {
        return NGX_CONF_ERROR;
    }
//    conf->maxCaptcha = NGX_CONF_UNSET_UINT;
    conf->width = NGX_CONF_UNSET_UINT;
    conf->height = NGX_CONF_UNSET_UINT;
    conf->length = NGX_CONF_UNSET_UINT;
    conf->expire = NGX_CONF_UNSET_UINT;
//    conf->charSpacing = NGX_CONF_UNSET;
    conf->size = NGX_CONF_UNSET_UINT;
    conf->font.data = NULL;
    conf->font.len = 0;
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
//    ngx_conf_merge_uint_value(conf->maxCaptcha, prev->maxCaptcha, 100);
    ngx_conf_merge_uint_value(conf->width, prev->width, CAPTCHA_WIDTH);
    ngx_conf_merge_uint_value(conf->height, prev->height, CAPTCHA_HEIGHT);
    ngx_conf_merge_uint_value(conf->length, prev->length, CAPTCHA_CODE_LEN);
    ngx_conf_merge_uint_value(conf->expire, prev->expire, CAPTCHA_EXPIRE);
//    ngx_conf_merge_value(conf->charSpacing, prev->charSpacing, -4);
    ngx_conf_merge_uint_value(conf->size, prev->size, FONT_SIZE);
    ngx_conf_merge_str_value(conf->font, prev->font, "simsun");
    ngx_conf_merge_str_value(conf->hash, prev->hash, "captcha_h");
    ngx_conf_merge_str_value(conf->salt, prev->salt, "captcha_s");
    ngx_conf_merge_str_value(conf->secret, prev->secret, "yoursecret");
    ngx_conf_merge_value(conf->enable, prev->enable, 0);
/*    if (conf->maxCaptcha < 1 || conf->maxCaptcha > MAXCAPTCHA) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "max_captcha must be large than 0 and less than %d", MAXCAPTCHA);
        return NGX_CONF_ERROR;
    }*/
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
    if(conf->enable) {
        conf->font_cstr = ngx_pcalloc(cf->pool, conf->font.len + 1);
        ngx_memcpy(conf->font_cstr, conf->font.data, conf->font.len);
        conf->font_cstr[conf->font.len] = '\0';
/*        if (conf->charCount > (MAXCHAR >> 1)) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "char_count must be less than %d", MAXCHAR >> 1);
            return NGX_CONF_ERROR;
        }
        ngx_http_captcha_init(conf);*/
    }
    return NGX_CONF_OK;
}
