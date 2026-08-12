# vi:filetype=

use lib 'lib';
use Test::Nginx::Socket;

repeat_each(1);

plan tests => repeat_each() * 3 * blocks();

no_long_string();

run_tests();

__DATA__

=== TEST 1: captcha_length 0 must be rejected at config time, not crash a worker
--- main_config
    load_module /etc/nginx/modules/ngx_http_captcha_module.so;
--- config
    location = /captcha {
        captcha;
        captcha_length 0;
        captcha_secret secret;
    }
--- request
GET /captcha
--- must_die
--- error_log
captcha length cannot be zero
--- no_error_log
[error]



=== TEST 2: a sane captcha_length still generates a normal image (no regression)
--- main_config
    load_module /etc/nginx/modules/ngx_http_captcha_module.so;
--- config
    location = /captcha {
        captcha;
        captcha_length 4;
        captcha_secret secret;
    }
--- request
GET /captcha?csrf=token
--- error_code: 200
--- response_headers
Content-Type: image/png
--- no_error_log
[error]
