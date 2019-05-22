# auth
```nginx
server {
    listen 80;
    server_name server.name.com;
    rewrite ^(.*) https://$server_name redirect;
}
server {
    listen 443 ssl;
    server_name server.name.com;
    ssl_certificate /etc/nginx/ssl/ssl.crt;
    ssl_certificate_key /etc/nginx/ssl/ssl.key;
    encrypted_session_key "abcdefghijklmnopqrstuvwxyz123456";
    auth_request /auth;
    set_escape_uri $request_uri_escape $request_uri;
    error_page 401 =303 $scheme://$server_name:$server_port/login?request_uri=$request_uri_escape;
    more_clear_input_headers Authorization;
    location / {
        alias html/$remote_user/;
    }
    location =/favicon.ico {
        auth_request off;
    }
    location =/login {
        auth_request off;
        try_files /nonexistent @login_$request_method;
    }
    location @login_GET {
        auth_request off;
        default_type "text/html; charset=utf-8";
        template login.html.ct2;
        ctpp2 on;
        set_secure_random_alphanum $csrf_random 32;
        encrypted_session_expires 3600;
        set_encrypt_session $csrf_encrypt $csrf_random;
        set_encode_base64 $csrf_encode $csrf_encrypt;
        add_header Set-Cookie "CSRF=$csrf_encode; Max-Age=3600";
        echo -n "{\"csrf\":\"$csrf_random\"}";
    }
    location @login_POST {
        auth_request off;
        set_form_input $csrf_form csrf;
        set_unescape_uri $csrf_unescape $csrf_form;
        set_decode_base64 $csrf_decode $cookie_csrf;
        set_decrypt_session $csrf_decrypt $csrf_decode;
        if ($csrf_decrypt != $csrf_unescape) {
            return 303 $request_uri;
        }
        set_form_input $captcha_form captcha;
        set_unescape_uri $captcha_unescape $captcha_form;
        set_md5 $captcha_md5 "secret${captcha_unescape}${csrf_decrypt}";
        if ($captcha_md5 != $cookie_captcha) {
            return 303 $request_uri;
        }
        set_form_input $username_form username;
        set_form_input $password_form password;
        set_unescape_uri $username_unescape $username_form;
        set_unescape_uri $password_unescape $password_form;
        encrypted_session_expires 2592000;
        set_encrypt_session $auth_encrypt "$username_unescape:$password_unescape";
        set_encode_base64 $auth_encode $auth_encrypt;
        add_header Set-Cookie "Auth=$auth_encode; Max-Age=2592000";
        set_unescape_uri $request_uri_unescape $arg_request_uri;
        return 303 $scheme://$server_name:$server_port$request_uri_unescape;
    }
    location =/auth {
        internal;
        if ($cookie_auth = "") {
            return 401 BAD;
        }
        set_decode_base64 $auth_decode $cookie_auth;
        set_decrypt_session $auth_decrypt $auth_decode;
        if ($auth_decrypt = "") {
            return 401 BAD;
        }
        set_encode_base64 $auth_encode $auth_decrypt;
        more_set_input_headers "Authorization: Basic $auth_encode";
        proxy_http_version 1.1;
        proxy_set_header Authorization "Basic $auth_encode";
        proxy_set_header X-Real-IP $remote_addr;
        proxy_cache all;
        proxy_cache_key $auth_encode;
        proxy_cache_valid 30d;
        proxy_pass http://localhost/basic?$auth_encode;
#        proxy_pass http://localhost/ldap?$auth_encode;
    }
    location =/captcha {
        auth_request off;
        captcha_case on;
        capture_response_body off;
        captcha;
    }
}
server {
    listen localhost;
    set_real_ip_from localhost;
    auth_basic_user_file html/.htaccess;
    auth_ldap_servers ad;
    more_clear_input_headers Cookie;
    location =/basic {
        auth_basic "auth";
        echo -n OK;
    }
    location =/ldap {
        auth_ldap "auth";
        echo -n OK;
    }
}
```
