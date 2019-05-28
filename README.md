# auth
```nginx
server {
    listen 80;
    server_name cas.server.com;
    rewrite ^ https://$server_name$uri redirect;
}
server {
    listen 443 ssl;
    server_name cas.server.com;
    ssl_certificate /etc/nginx/ssl/crt;
    ssl_certificate_key /etc/nginx/ssl/key;
    auth_request /auth;
    error_page 401 = @error401;
    more_clear_input_headers Authorization;
    location @error401 {
        set_escape_uri $request_uri_escape $request_uri;
        return 303 /login?request_uri=$request_uri_escape;
    }
    location / {
        alias html/cas/$remote_user/;
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
        template cas/login.html.ct2;
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
        if ($csrf_decrypt != $csrf_unescape) { return 303 $request_uri; }
        set_form_input $captcha_form captcha;
        set_unescape_uri $captcha_unescape $captcha_form;
        set_md5 $captcha_md5 "secret${captcha_unescape}${csrf_decrypt}";
        if ($captcha_md5 != $cookie_captcha) { return 303 $request_uri; }
        set_form_input $username_form username;
        set_form_input $password_form password;
        set_unescape_uri $username_unescape $username_form;
        set_unescape_uri $password_unescape $password_form;
        encrypted_session_expires 2592000;
        set_encrypt_session $auth_encrypt "$username_unescape:$password_unescape";
        set_encode_base64 $auth_encode $auth_encrypt;
        add_header Set-Cookie "Auth=$auth_encode; Max-Age=2592000";
        set_if_empty $arg_request_uri "/";
        set_unescape_uri $request_uri_unescape $arg_request_uri;
        return 303 $request_uri_unescape;
    }
    location =/logout {
        add_header Set-Cookie "Auth=; Max-Age=0";
        return 303 /login;
    }
    location =/auth {
        internal;
        set_decode_base64 $auth_decode $cookie_auth;
        set_decrypt_session $auth_decrypt $auth_decode;
        if ($auth_decrypt = "") { return 401 BAD; }
        set_encode_base64 $auth_encode $auth_decrypt;
        more_set_input_headers "Authorization: Basic $auth_encode";
        proxy_http_version 1.1;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header Host $host;
        proxy_cache all;
        proxy_cache_valid 2592000;
        proxy_pass http://localhost/basic?$auth_encode;
#        proxy_pass http://localhost/ldap?$auth_encode;
    }
    location =/captcha {
        auth_request off;
        captcha_case on;
        captcha;
    }
    location =/service {
        set_decode_base64 $auth_decode $cookie_auth;
        set_decrypt_session $auth_decrypt $auth_decode;
        if ($auth_decrypt) {
            encrypted_session_expires 3600;
            set_encrypt_session $auth_encrypt $auth_decrypt;
            set_encode_base64 $auth_encode $auth_encrypt;
            set_escape_uri $auth_escape $auth_encode;
            set_unescape_uri $service_unescape $arg_service;
            return 303 $service_unescape?auth=$auth_escape&request_uri=$arg_request_uri;
        }
    }
    location =/serviceValidate {
        auth_request off;
        set_unescape_uri $auth_unescape $arg_auth;
        set_decode_base64 $auth_decode $auth_unescape;
        set_decrypt_session $auth_decrypt $auth_decode;
        if ($auth_decrypt = "") { return 401 BAD; }
        return 200 OK;
    }
}
server {
    listen localhost;
    server_name cas.server.com;
    set_real_ip_from localhost;
    auth_basic_user_file html/cas/.htaccess;
    auth_ldap_servers ldap;
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
server {
    listen 80;
    server_name test.server.com;
    rewrite ^ https://$server_name$uri redirect;
}
server {
    listen 443 ssl;
    server_name test.server.com;
    ssl_certificate /etc/nginx/ssl/crt;
    ssl_certificate_key /etc/nginx/ssl/key;
    root html/test;
    auth_request /auth;
    error_page 401 = @error401;
    more_clear_input_headers Authorization;
    set $service $scheme://$server_name:$server_port/login;
    set $cas cas.server.com;
    location @error401 {
        set_escape_uri $request_uri_escape $request_uri;
        set_escape_uri $service_escape $service;
        return 303 https://$cas/service?service=$service_escape&request_uri=$request_uri_escape;
    }
    location / {
        alias html/test/$remote_user/;
    }
    location =/favicon.ico {
        auth_request off;
    }
    location =/login {
        auth_request off;
        set_unescape_uri $auth_unescape $arg_auth;
        add_header Set-Cookie "Auth=$auth_unescape; Max-Age=3600";
        set_if_empty $arg_request_uri "/";
        set_unescape_uri $request_uri_unescape $arg_request_uri;
        return 303 $request_uri_unescape;
    }
    location =/logout {
        add_header Set-Cookie "Auth=; Max-Age=0";
        return 303 /login;
    }
    location =/auth {
        internal;
        set_decode_base64 $auth_decode $cookie_auth;
        set_decrypt_session $auth_decrypt $auth_decode;
        if ($auth_decrypt = "") { return 401 BAD; }
        set_encode_base64 $auth_encode $auth_decrypt;
        more_set_input_headers "Authorization: Basic $auth_encode";
        set_escape_uri $auth_escape $cookie_auth;
        proxy_http_version 1.1;
        proxy_set_header Host $cas;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_cache all;
        proxy_cache_valid 3600;
        proxy_pass https://$cas/serviceValidate?auth=$auth_escape;
    }
}
```
