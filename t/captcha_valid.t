# vi:filetype=

use lib 'lib';
use Test::Nginx::Socket;
use Digest::MD5 qw(md5_hex);

repeat_each(1);

plan tests => repeat_each() * (2 * blocks() + 2);

no_long_string();

our $future = time() + 300;
our $past = time() - 1;

sub captcha_cookie {
    my ($expires, $answer, $csrf) = @_;
    return "$expires." . md5_hex("secret$expires.$answer$csrf");
}

run_tests();

__DATA__

=== TEST 1: matching answer, csrf and unexpired cookie are valid (answer case is ignored)
--- main_config
    load_module /etc/nginx/modules/ngx_http_captcha_module.so;
--- config
    location = /login {
        captcha_secret secret;
        captcha_answer $arg_answer;
        return 200 "valid=$captcha_valid\n";
    }
--- more_headers eval
"Cookie: csrf=token; Captcha=" . main::captcha_cookie($main::future, "abcd", "token")
--- request
GET /login?answer=AbCd
--- response_body
valid=1



=== TEST 2: wrong answer is invalid
--- main_config
    load_module /etc/nginx/modules/ngx_http_captcha_module.so;
--- config
    location = /login {
        captcha_secret secret;
        captcha_answer $arg_answer;
        return 200 "valid=$captcha_valid\n";
    }
--- more_headers eval
"Cookie: csrf=token; Captcha=" . main::captcha_cookie($main::future, "abcd", "token")
--- request
GET /login?answer=abce
--- response_body
valid=0



=== TEST 3: expired cookie is invalid even with the right answer
--- main_config
    load_module /etc/nginx/modules/ngx_http_captcha_module.so;
--- config
    location = /login {
        captcha_secret secret;
        captcha_answer $arg_answer;
        return 200 "valid=$captcha_valid\n";
    }
--- more_headers eval
"Cookie: csrf=token; Captcha=" . main::captcha_cookie($main::past, "abcd", "token")
--- request
GET /login?answer=abcd
--- response_body
valid=0



=== TEST 4: extending the expiry of an expired cookie breaks the hash
--- main_config
    load_module /etc/nginx/modules/ngx_http_captcha_module.so;
--- config
    location = /login {
        captcha_secret secret;
        captcha_answer $arg_answer;
        return 200 "valid=$captcha_valid\n";
    }
--- more_headers eval
my $cookie = main::captcha_cookie($main::past, "abcd", "token");
$cookie =~ s/^\d+/$main::future/;
"Cookie: csrf=token; Captcha=$cookie"
--- request
GET /login?answer=abcd
--- response_body
valid=0



=== TEST 5: different csrf is invalid
--- main_config
    load_module /etc/nginx/modules/ngx_http_captcha_module.so;
--- config
    location = /login {
        captcha_secret secret;
        captcha_answer $arg_answer;
        return 200 "valid=$captcha_valid\n";
    }
--- more_headers eval
"Cookie: csrf=other; Captcha=" . main::captcha_cookie($main::future, "abcd", "token")
--- request
GET /login?answer=abcd
--- response_body
valid=0



=== TEST 6: missing captcha cookie is invalid
--- main_config
    load_module /etc/nginx/modules/ngx_http_captcha_module.so;
--- config
    location = /login {
        captcha_secret secret;
        captcha_answer $arg_answer;
        return 200 "valid=$captcha_valid\n";
    }
--- more_headers
Cookie: csrf=token
--- request
GET /login?answer=abcd
--- response_body
valid=0



=== TEST 7: cookie in the old format without expiry is invalid
--- main_config
    load_module /etc/nginx/modules/ngx_http_captcha_module.so;
--- config
    location = /login {
        captcha_secret secret;
        captcha_answer $arg_answer;
        return 200 "valid=$captcha_valid\n";
    }
--- more_headers eval
"Cookie: csrf=token; Captcha=" . Digest::MD5::md5_hex("secretabcdtoken")
--- request
GET /login?answer=abcd
--- response_body
valid=0



=== TEST 8: captcha_case off compares the answer case-sensitively
--- main_config
    load_module /etc/nginx/modules/ngx_http_captcha_module.so;
--- config
    location = /login {
        captcha_secret secret;
        captcha_case off;
        captcha_answer $arg_answer;
        return 200 "valid=$captcha_valid\n";
    }
--- more_headers eval
"Cookie: csrf=token; Captcha=" . main::captcha_cookie($main::future, "abcd", "token")
--- request
GET /login?answer=AbCd
--- response_body
valid=0



=== TEST 9: csrf is taken from the arg when there is no csrf cookie
--- main_config
    load_module /etc/nginx/modules/ngx_http_captcha_module.so;
--- config
    location = /login {
        captcha_secret secret;
        captcha_answer $arg_answer;
        return 200 "valid=$captcha_valid\n";
    }
--- more_headers eval
"Cookie: Captcha=" . main::captcha_cookie($main::future, "abcd", "token")
--- request
GET /login?answer=abcd&csrf=token
--- response_body
valid=1
--- error_log eval
qr/\[info\] .*captcha: no "csrf" cookie specified, trying arg/
--- no_error_log
[warn]



=== TEST 10: without captcha_answer the variable is always invalid
--- main_config
    load_module /etc/nginx/modules/ngx_http_captcha_module.so;
--- config
    location = /login {
        captcha_secret secret;
        return 200 "valid=$captcha_valid\n";
    }
--- more_headers eval
"Cookie: csrf=token; Captcha=" . main::captcha_cookie($main::future, "abcd", "token")
--- request
GET /login?answer=abcd
--- response_body
valid=0



=== TEST 11: cookie issued by the captcha location uses the same hash scheme
--- main_config
    load_module /etc/nginx/modules/ngx_http_captcha_module.so;
--- config
    location = /captcha {
        captcha;
        captcha_secret secret;
        captcha_charset a;
    }
--- request
GET /captcha?csrf=token
--- response_headers_like eval
"Set-Cookie: Captcha=(?:" . CORE::join("|", map { main::captcha_cookie($_, "aaaa", "token") } ($main::future .. $main::future + 30)) . "); Max-Age=300; Path=/; HttpOnly; SameSite=Lax"



=== TEST 12: UTF-8 charset produces whole characters, not split bytes
--- main_config
    load_module /etc/nginx/modules/ngx_http_captcha_module.so;
--- config
    location = /captcha {
        captcha;
        captcha_secret secret;
        captcha_charset ж;
    }
--- request
GET /captcha?csrf=token
--- response_headers_like eval
"Set-Cookie: Captcha=(?:" . CORE::join("|", map { main::captcha_cookie($_, "жжжж", "token") } ($main::future .. $main::future + 30)) . "); Max-Age=300; Path=/; HttpOnly; SameSite=Lax"
