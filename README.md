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
    set_form_input $csrf_form csrf;
    set_unescape_uri $csrf_unescape $csrf_form;
    set_form_input $captcha_form captcha;
    set_unescape_uri $captcha_unescape $captcha_form;
    set_md5 $captcha_md5 "secret${captcha_unescape}${csrf_unescape}";
    if ($captcha_md5 != $cookie_captcha) {
        # captcha invalid code
    }
}
```
### Directives:

    Syntax:	 captcha;
    Default: ——
    Context: location

Enables generation of captcha image.<hr>

    Syntax:	 captcha_case on | off;
    Default: off
    Context: http, server, location

Enables/disables ignoring captcha case.<hr>

    Syntax:	 captcha_expire seconds;
    Default: 3600
    Context: http, server, location

Sets seconds before expiring captcha.<hr>

    Syntax:	 captcha_height pixels;
    Default: 30
    Context: http, server, location

Sets height of captcha image.<hr>

    Syntax:	 captcha_length characters;
    Default: 4
    Context: http, server, location

Sets length of captcha text.<hr>

    Syntax:	 captcha_size pixels;
    Default: 20
    Context: http, server, location

Sets size of captcha font.<hr>

    Syntax:	 captcha_width pixels;
    Default: 130
    Context: http, server, location

Sets width of captcha image.<hr>

    Syntax:	 captcha_charset string;
    Default: abcdefghkmnprstuvwxyzABCDEFGHKMNPRSTUVWXYZ23456789
    Context: http, server, location

Sets characters used in captcha text.<hr>

    Syntax:	 captcha_csrf string;
    Default: csrf
    Context: http, server, location

Sets name of csrf var of captcha.<hr>

    Syntax:	 captcha_font string;
    Default: /usr/share/fonts/ttf-liberation/LiberationSans-Regular.ttf
    Context: http, server, location

Sets font of captcha text.<hr>

    Syntax:	 captcha_name string;
    Default: Captcha
    Context: http, server, location

Sets name of captcha cookie.<hr>

    Syntax:	 captcha_secret string;
    Default: secret
    Context: http, server, location

Sets secret of captcha.
