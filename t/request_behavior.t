# vi:filetype=

use lib 'lib';
use Test::Nginx::Socket;

repeat_each(1);

plan tests => repeat_each() * 17;

no_long_string();

run_tests();

__DATA__

=== TEST 1: csrf accepted via Cookie header, not just arg
--- main_config
    load_module /etc/nginx/modules/ngx_http_captcha_module.so;
--- config
    location = /captcha {
        captcha;
        captcha_secret secret;
    }
--- more_headers
Cookie: csrf=token
--- request
GET /captcha
--- error_code: 200
--- response_headers
Content-Type: image/png



=== TEST 2: no csrf cookie and no csrf arg is rejected
--- main_config
    load_module /etc/nginx/modules/ngx_http_captcha_module.so;
--- config
    location = /captcha {
        captcha;
        captcha_secret secret;
    }
--- request
GET /captcha
--- error_code: 404
--- error_log
captcha: no "csrf" cookie specified, trying arg...
captcha: no "csrf" arg specified



=== TEST 3: missing captcha_secret fails the request, not the config
--- main_config
    load_module /etc/nginx/modules/ngx_http_captcha_module.so;
--- config
    location = /captcha {
        captcha;
    }
--- request
GET /captcha?csrf=token
--- error_code: 500
--- error_log
!location->secret



=== TEST 4: captcha_case off still renders normally
--- main_config
    load_module /etc/nginx/modules/ngx_http_captcha_module.so;
--- config
    location = /captcha {
        captcha;
        captcha_secret secret;
        captcha_case off;
    }
--- request
GET /captcha?csrf=token
--- error_code: 200
--- response_headers
Content-Type: image/png



=== TEST 5: Set-Cookie reflects the configured name and expire
--- main_config
    load_module /etc/nginx/modules/ngx_http_captcha_module.so;
--- config
    location = /captcha {
        captcha;
        captcha_secret secret;
        captcha_name MyCaptcha;
        captcha_expire 123;
    }
--- request
GET /captcha?csrf=token
--- error_code: 200
--- response_headers_like
Set-Cookie: MyCaptcha=\d+\.[0-9a-f]{32}; Max-Age=123; Path=/; HttpOnly; SameSite=Lax



=== TEST 6: captcha_level above range is clamped, not rejected
--- main_config
    load_module /etc/nginx/modules/ngx_http_captcha_module.so;
--- config
    location = /captcha {
        captcha;
        captcha_secret secret;
        captcha_level 99;
    }
--- request
GET /captcha?csrf=token
--- error_code: 200
--- response_headers
Content-Type: image/png






=== TEST 7: captcha_flags replaces the default cookie attributes and accepts variables
--- main_config
    load_module /etc/nginx/modules/ngx_http_captcha_module.so;
--- config
    location = /captcha {
        captcha;
        captcha_secret secret;
        captcha_flags "Path=$uri; Secure; SameSite=Strict";
    }
--- request
GET /captcha?csrf=token
--- error_code: 200
--- response_headers_like
Set-Cookie: Captcha=\d+\.[0-9a-f]{32}; Max-Age=300; Path=/captcha; Secure; SameSite=Strict



=== TEST 8: empty captcha_flags adds no cookie attributes
--- main_config
    load_module /etc/nginx/modules/ngx_http_captcha_module.so;
--- config
    location = /captcha {
        captcha;
        captcha_secret secret;
        captcha_flags "";
    }
--- request
GET /captcha?csrf=token
--- error_code: 200
--- response_headers_like
Set-Cookie: Captcha=\d+\.[0-9a-f]{32}; Max-Age=300
