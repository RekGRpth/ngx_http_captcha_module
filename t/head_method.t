# vi:filetype=

use lib 'lib';
use Test::Nginx::Socket;

repeat_each(1);

plan tests => repeat_each() * 2 * blocks();

no_long_string();

run_tests();

__DATA__

=== TEST 1: HEAD is rejected instead of silently rotating the challenge
--- main_config
    load_module /var/cache/nginx/src/ngx_http_captcha_module/t/build/ngx_http_captcha_module.so;
--- config
    location = /captcha {
        captcha;
        captcha_secret secret;
    }
--- request
HEAD /captcha?csrf=token
--- error_code: 405
--- no_error_log
[error]



=== TEST 2: GET is unaffected
--- main_config
    load_module /var/cache/nginx/src/ngx_http_captcha_module/t/build/ngx_http_captcha_module.so;
--- config
    location = /captcha {
        captcha;
        captcha_secret secret;
    }
--- request
GET /captcha?csrf=token
--- error_code: 200
--- response_headers
Content-Type: image/png
