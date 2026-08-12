# vi:filetype=

use lib 'lib';
use Test::Nginx::Socket;

repeat_each(1);

plan tests => repeat_each() * 2 * blocks();

no_long_string();

run_tests();

__DATA__

=== TEST 1: outer location uses its own captcha_csrf name
--- main_config
    load_module /var/cache/nginx/src/ngx_http_captcha_module/t/build/ngx_http_captcha_module.so;
--- config
    location /a {
        captcha;
        captcha_csrf outer;
        captcha_secret secret;

        location = /a/inner {
            captcha;
            captcha_csrf inner;
            captcha_secret secret;
        }
    }
--- request
GET /a?outer=token
--- error_code: 200
--- response_headers
Content-Type: image/png



=== TEST 2: nested location must use its own captcha_csrf name, not the parent's
--- main_config
    load_module /var/cache/nginx/src/ngx_http_captcha_module/t/build/ngx_http_captcha_module.so;
--- config
    location /a {
        captcha;
        captcha_csrf outer;
        captcha_secret secret;

        location = /a/inner {
            captcha;
            captcha_csrf inner;
            captcha_secret secret;
        }
    }
--- request
GET /a/inner?inner=token
--- error_code: 200
--- response_headers
Content-Type: image/png



=== TEST 3: nested location must reject the parent's csrf arg name
--- main_config
    load_module /var/cache/nginx/src/ngx_http_captcha_module/t/build/ngx_http_captcha_module.so;
--- config
    location /a {
        captcha;
        captcha_csrf outer;
        captcha_secret secret;

        location = /a/inner {
            captcha;
            captcha_csrf inner;
            captcha_secret secret;
        }
    }
--- request
GET /a/inner?outer=token
--- error_code: 404
--- no_error_log
[error]
