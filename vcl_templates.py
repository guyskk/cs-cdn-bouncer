GOOGLE_BACKEND = """
backend google_host {{
    .between_bytes_timeout = 10s;
    .connect_timeout = 1s;
    .dynamic = true;
    .first_byte_timeout = 15s;
    .host = "www.google.com";
    .max_connections = 200;
    .port = "443";
    .share_key = "{SERVICE_ID}";
    .ssl = true;
    .ssl_cert_hostname = "www.google.com";
    .ssl_check_cert = always;
    .ssl_sni_hostname = "www.google.com";
    .probe = {{
        .dummy = true;
        .initial = 5;
        .request = "HEAD / HTTP/1.1"  "Host: www.google.com" "Connection: close";
        .threshold = 1;
        .timeout = 2s;
        .window = 5;
      }}
}}
"""

CAPTCHA_RECV_VCL = """

declare local var.captcha_token STRING;

if(req.http.origURL != req.http.origURL){{
  set req.http.origURL = req.url; 
  set req.http.origHost = req.http.host ;
}}

if (std.strlen(querystring.get(req.url, "g-recaptcha-response")) > 0){{  # This is captcha response
  set req.backend = google_host /* www.google.com */ ; 
  set var.captcha_token = querystring.get(req.url, "g-recaptcha-response"); 
  set req.url = "/recaptcha/api/siteverify" ; 
  set req.url = querystring.add(req.url, "secret", "{RECAPTCHA_SECRET}"); 
  set req.url = querystring.add(req.url, "response", var.captcha_token); 
  set req.http.host = "www.google.com" ;
  return(pass);
}}


if(!req.http.Cookie:captchaAuth){{
  error 676 ; 
}}

set req.backend = F_Host_1 ;
set req.http.host = req.http.origHost ;
"""


CAPTCHA_RENDER_VCL = """
if (obj.status == 676){{
    set obj.status = 200 ;
    set obj.response = "OK";
    set obj.http.Cache-Control = "private, no-store";
    set obj.http.Content-Type = "text/html";
  
    synthetic {{"
      <html>
        <head>
          <title>reCAPTCHA demo: Simple page</title>
          <script src="https://www.google.com/recaptcha/api.js" async defer></script>
        </head>
        <body>
          <form action="" method="GET">
            <div class="g-recaptcha" data-sitekey="{RECAPTCHA_SITE_KEY}"></div>
            <br/>
            <input type="submit" value="Submit">
          </form>
        </body>
      </html>
    "}};
    return(deliver);
  }}
"""

CAPTCHA_VALIDATOR_VCL = """

if (req.http.Host ~ "google.com"){
  if(resp.status == 200){
    set req.http.origURL =querystring.filter(req.http.origURL, "g-recaptcha-response");
    set resp.status = 307;
    set resp.response = "Temporary redirect";
    set resp.http.Set-Cookie = "captchaAuth=1; path=/; max-age=3600";
    set resp.http.Cache-Control = "private, no-store";
    set resp.http.Location = req.http.origURL ;
  }
  restart;
}
"""
