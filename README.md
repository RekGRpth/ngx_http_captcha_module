# auth
```conf
server {
    listen 80;
    server_name server.name.com;
    rewrite ^(.*) https://$server_name redirect;
}
server {
    listen 443 ssl;
    server_name server.name.com;
    encrypted_session_key "012345abcdefghijklmnopqrstuvwxyz";
    encrypted_session_expires 30d;
    auth_request /auth;
    set_escape_uri $request_uri_escape $request_uri;
    error_page 401 =303 $scheme://$server_name:$server_port/login?request_uri=$request_uri_escape;
    location / {
        add_header Pragma no-cache;
        alias html/$remote_user/;
    }
    location =/favicon.ico {
        auth_request off;
    }
    location =/login {
        auth_request off;
        add_header Pragma no-cache;
        capture_response_body off;
        default_type "text/html; charset=utf-8";
        template cas/login.html.ct2;
        if ($request_method = GET) {
            add_header Set-Cookie "auth='';Path=/;Max-Age=0;Secure;Discard;";
            ctpp2 on;
            set_secure_random_alphanum $csrf 32;
            encrypted_session_expires 1h;
            set_encrypt_session $csrf_encrypt $csrf;
            set_encode_base64 $csrf_encode $csrf_encrypt;
            add_header Set-Cookie "csrf=$csrf_encode;Path=/;Max-Age=3600;Secure;Discard;";
            echo -n "{\"csrf\":\"$csrf\"}";
            break;
        }
        set_form_input $captcha;
        set_unescape_uri $captcha_unescape $captcha;
        set_decode_base64 $csrf_decode $cookie_csrf;
        set_decrypt_session $csrf_decrypt $csrf_decode;
        set_md5 $captcha_md5 "secret${captcha_unescape}${csrf_decrypt}";
        if ($captcha_md5 != $cookie_captcha) {
            rewrite ^ $scheme://$server_name:$server_port$request_uri redirect;
        }
        set_form_input $username;
        set_form_input $password;
        set_unescape_uri $username_unescape $username;
        set_unescape_uri $password_unescape $password;
        set_encrypt_session $auth_encrypt "$username_unescape:$password_unescape";
        set_encode_base64 $auth_encode $auth_encrypt;
        add_header Set-Cookie "auth=$auth_encode;Path=/;Max-Age=2592000;Secure;Discard;";
        set_unescape_uri $request_uri_unescape $arg_request_uri;
        return 303 $scheme://$server_name:$server_port$request_uri_unescape;
    }
    location =/auth {
        internal;
        set_decode_base64 $auth_decode $cookie_auth;
        set_decrypt_session $auth_decrypt $auth_decode;
        set_encode_base64 $auth_encode $auth_decrypt;
        more_set_input_headers "Authorization: Basic $auth_encode";
        proxy_http_version 1.1;
        proxy_set_header Content-Length "";
        proxy_set_header X-Real-IP $remote_addr;
        proxy_pass_request_body off;
        proxy_pass http://127.0.0.1:443/basic;
#        proxy_pass http://127.0.0.1:443/ldap;
    }
    location =/captcha {
        auth_request off;
        captcha_case on;
        capture_response_body off;
        captcha;
    }
}
server {
    listen 127.0.0.1:443;
    set_real_ip_from 127.0.0.1;
    auth_basic_user_file html/cas/.htaccess;
    auth_ldap_servers ad;
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
