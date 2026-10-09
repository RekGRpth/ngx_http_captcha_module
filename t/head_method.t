# vi:filetype=

use lib 'lib';
use Test::Nginx::Socket;

repeat_each(1);

plan tests => repeat_each() * (2 * blocks() + 1);

no_long_string();

run_tests();

__DATA__

=== TEST 1: HEAD is rejected instead of silently rotating the challenge
--- main_config
    load_module /etc/nginx/modules/ngx_http_captcha_module.so;
--- config
    location = /captcha {
        captcha;
        captcha_secret secret;
    }
--- request
HEAD /captcha?csrf=token
--- error_code: 405
--- response_headers
Allow: GET
--- no_error_log
[error]



=== TEST 2: GET is unaffected
--- main_config
    load_module /etc/nginx/modules/ngx_http_captcha_module.so;
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



=== TEST 3: POST is rejected with Allow: GET
--- main_config
    load_module /etc/nginx/modules/ngx_http_captcha_module.so;
--- config
    location = /captcha {
        captcha;
        captcha_secret secret;
    }
--- request
POST /captcha?csrf=token
hello
--- error_code: 405
--- response_headers
Allow: GET
