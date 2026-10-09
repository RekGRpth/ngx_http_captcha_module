## Pre-built Packages (Ubuntu / Debian)

Pre-built packages for this module are freely available from the GetPageSpeed repository:

```bash
# Install the repository keyring
sudo install -d -m 0755 /etc/apt/keyrings
curl -fsSL https://extras.getpagespeed.com/deb-archive-keyring.gpg \
  | sudo tee /etc/apt/keyrings/getpagespeed.gpg >/dev/null

# Add the repository (Ubuntu example - replace 'ubuntu' and 'jammy' for your distro)
echo "deb [signed-by=/etc/apt/keyrings/getpagespeed.gpg] https://extras.getpagespeed.com/ubuntu jammy main" \
  | sudo tee /etc/apt/sources.list.d/getpagespeed-extras.list

# Install nginx and the module
sudo apt-get update
sudo apt-get install nginx nginx-module-captcha
```

The module is automatically enabled after installation. Supported distributions include Debian 12/13 and Ubuntu 20.04/22.04/24.04 (both amd64 and arm64). See [the complete setup instructions](https://apt-nginx-extras.getpagespeed.com/apt-setup/).

## Module:

### Example Configuration:
```nginx
location =/captcha {
    captcha;
}
location =/login {
    set_form_input $captcha_form captcha;
    set_unescape_uri $captcha_unescape $captcha_form;
    captcha_answer $captcha_unescape;
    if ($captcha_valid != 1) {
        # captcha invalid code
    }
}
```
`captcha_secret` (and any other `captcha_*` settings) must be the same for
the captcha location and the location that checks `$captcha_valid`, so it is
simplest to set them at the `server` or `http` level.

The captcha cookie has the form `<expires>.<hash>`, where `expires` is a unix
timestamp and `hash = md5(secret + expires + "." + code + csrf)` (`code` is
lowercased when `captcha_case` is on). Because the expiry is covered by the
hash, a solved captcha stops being accepted after `captcha_expire` seconds
even if the client keeps the cookie. Within that time it can still be
reused with the same csrf value, so rotate the csrf token after each check if
a captcha must be strictly single-use.
### Directives:

    Syntax:	 captcha;
    Default: ——
    Context: location

Enables generation of captcha image. Only GET requests are accepted; any
other method, including HEAD, gets a 405 response. The image is sent with
`Cache-Control: no-store`; the `expires` directive replaces it if set.<hr>

    Syntax:	 captcha_answer string;
    Default: ——
    Context: http, server, location

Sets the user's answer to check with `$captcha_valid`. The value can contain
variables.<hr>

    Syntax:	 captcha_case on | off;
    Default: on
    Context: http, server, location

Enables/disables ignoring captcha case.<hr>

    Syntax:	 captcha_expire seconds;
    Default: 300
    Context: http, server, location

Sets seconds before expiring captcha, from 0 to 2147483647.<hr>

    Syntax:	 captcha_height pixels;
    Default: 30
    Context: http, server, location

Sets height of captcha image, from 1 to 65535.<hr>

    Syntax:	 captcha_length characters;
    Default: 4
    Context: http, server, location

Sets length of captcha text, from 1 to 65535 and not more than
`captcha_width`.<hr>

    Syntax:	 captcha_size pixels;
    Default: 20
    Context: http, server, location

Sets size of captcha font, from 1 to 65535 and not more than
`captcha_height`.<hr>

    Syntax:	 captcha_width pixels;
    Default: 130
    Context: http, server, location

Sets width of captcha image, from 1 to 65535.<hr>

    Syntax:	 captcha_line number;
    Default: 10
    Context: http, server, location

Sets number of random noise lines drawn over the captcha image.<hr>

    Syntax:	 captcha_star number;
    Default: 100
    Context: http, server, location

Sets number of random noise stars ("*") drawn over the captcha image.<hr>

    Syntax:	 captcha_level number;
    Default: -1
    Context: http, server, location

Sets the PNG compression level, from 0 (none) to 9 (best); -1 uses zlib's
default compression. Values outside -1..9 are clamped.<hr>

    Syntax:	 captcha_charset string;
    Default: abcdefghkmnprstuvwxyzABCDEFGHKMNPRSTUVWXYZ23456789
    Context: http, server, location

Sets characters used in captcha text.<hr>

    Syntax:	 captcha_csrf string;
    Default: csrf
    Context: http, server, location

Sets name of csrf var of captcha.<hr>

    Syntax:	 captcha_flags string;
    Default: Path=/; HttpOnly; SameSite=Lax
    Context: http, server, location

Sets attributes appended to the captcha cookie after `Max-Age`. The value can
contain variables. Add `Secure` when the site is served over HTTPS (including
behind a TLS-terminating proxy). An empty string adds no attributes.<hr>

    Syntax:	 captcha_font string;
    Default: /usr/local/share/fonts/NimbusSans-Regular.ttf
    Context: http, server, location

Sets font of captcha text.<hr>

    Syntax:	 captcha_name string;
    Default: Captcha
    Context: http, server, location

Sets name of captcha cookie.<hr>

    Syntax:	 captcha_secret string;
    Default: ——
    Context: http, server, location

Sets secret of captcha. Mandatory: a location that enables `captcha;`
without a `captcha_secret` set anywhere in its config hierarchy will
return a 500 for every request.

### Variables:

    $captcha_valid

`1` if the captcha cookie (named by `captcha_name`) is not expired and its hash
matches `captcha_answer`, `captcha_secret` and the csrf value, otherwise `0`.
The csrf value is taken from the cookie named by `captcha_csrf`, or from the
argument of the same name if there is no such cookie, just like when the
captcha image is generated.
