# vi:filetype=

use lib 'lib';
use Test::Nginx::Socket;

repeat_each(1);

plan tests => repeat_each() * 2 * blocks();

no_long_string();

run_tests();

__DATA__

=== TEST 1: captcha_size larger than captcha_height is rejected
--- main_config
    load_module /etc/nginx/modules/ngx_http_captcha_module.so;
--- config
    location = /captcha {
        captcha;
        captcha_secret secret;
        captcha_height 10;
        captcha_size 20;
    }
--- request
GET /captcha
--- must_die
--- error_log
captcha size is too large



=== TEST 2: empty captcha_charset is rejected
--- main_config
    load_module /etc/nginx/modules/ngx_http_captcha_module.so;
--- config
    location = /captcha {
        captcha;
        captcha_secret secret;
        captcha_charset "";
    }
--- request
GET /captcha
--- must_die
--- error_log
captcha charset cannot be empty



=== TEST 3: empty captcha_font is rejected
--- main_config
    load_module /etc/nginx/modules/ngx_http_captcha_module.so;
--- config
    location = /captcha {
        captcha;
        captcha_secret secret;
        captcha_font "";
    }
--- request
GET /captcha
--- must_die
--- error_log
captcha font cannot be empty



=== TEST 4: empty captcha_name is rejected
--- main_config
    load_module /etc/nginx/modules/ngx_http_captcha_module.so;
--- config
    location = /captcha {
        captcha;
        captcha_secret secret;
        captcha_name "";
    }
--- request
GET /captcha
--- must_die
--- error_log
captcha name cannot be empty



=== TEST 5: empty captcha_csrf is rejected
--- main_config
    load_module /etc/nginx/modules/ngx_http_captcha_module.so;
--- config
    location = /captcha {
        captcha;
        captcha_secret secret;
        captcha_csrf "";
    }
--- request
GET /captcha
--- must_die
--- error_log
captcha csrf cannot be empty
