#!/usr/bin/env python
# SecretFinder - Tool for discover apikeys/accesstokens and sensitive data in js file
# based to LinkFinder - github.com/GerbenJavado
# By m4ll0k (@m4ll0k2) github.com/m4ll0k


import os, sys

if not sys.version_info.major >= 3:
    print("[ + ] Run this tool with python version 3.+")
    sys.exit(0)
os.environ["BROWSER"] = "open"

import re
import glob
import argparse
import jsbeautifier
import webbrowser
import subprocess
import base64
import requests
import string
import random
from html import escape
import urllib3
import xml.etree.ElementTree

# disable warning

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# for read local file with file:// protocol
from requests_file import FileAdapter
from lxml import html
from urllib.parse import urlparse

# regex
_regex = {
    'google_api': r'AIza[0-9A-Za-z-_]{35}',
    'firebase': r'AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}',
    'google_captcha': r'6L[0-9A-Za-z-_]{38}|^6[0-9a-zA-Z_-]{39}$',
    'google_oauth': r'ya29\.[0-9A-Za-z\-_]+',
    'amazon_aws_access_key_id': r'AKIA[0-9A-Z]{16}',
    'amazon_mws_auth_toke': r'amzn\\.mws\\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}',
    'amazon_aws_url': r's3\.amazonaws.com[/]+|[a-zA-Z0-9_-]*\.s3\.amazonaws.com',
    'amazon_aws_url2': r"(" \
                       r"[a-zA-Z0-9-\.\_]+\.s3\.amazonaws\.com" \
                       r"|s3://[a-zA-Z0-9-\.\_]+" \
                       r"|s3-[a-zA-Z0-9-\.\_\/]+" \
                       r"|s3.amazonaws.com/[a-zA-Z0-9-\.\_]+" \
                       r"|s3.console.aws.amazon.com/s3/buckets/[a-zA-Z0-9-\.\_]+)",
    'facebook_access_token': r'EAACEdEose0cBA[0-9A-Za-z]+',
    'authorization_basic': r'basic [a-zA-Z0-9=:_\+\/-]{5,100}',
    'authorization_bearer': r'bearer [a-zA-Z0-9_\-\.=:_\+\/]{5,100}',
    'authorization_api': r'api[key|_key|\s+]+[a-zA-Z0-9_\-]{5,100}',
    'mailgun_api_key': r'key-[0-9a-zA-Z]{32}',
    'twilio_api_key': r'SK[0-9a-fA-F]{32}',
    'twilio_account_sid': r'AC[a-zA-Z0-9_\-]{32}',
    'twilio_app_sid': r'AP[a-zA-Z0-9_\-]{32}',
    'paypal_braintree_access_token': r'access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}',
    'square_oauth_secret': r'sq0csp-[ 0-9A-Za-z\-_]{43}|sq0[a-z]{3}-[0-9A-Za-z\-_]{22,43}',
    'square_access_token': r'sqOatp-[0-9A-Za-z\-_]{22}|EAAA[a-zA-Z0-9]{60}',
    'stripe_standard_api': r'sk_live_[0-9a-zA-Z]{24}',
    'stripe_restricted_api': r'rk_live_[0-9a-zA-Z]{24}',
    'github_access_token': r'[a-zA-Z0-9_-]*:[a-zA-Z0-9_\-]+@github\.com*',
    'rsa_private_key': r'-----BEGIN RSA PRIVATE KEY-----',
    'ssh_dsa_private_key': r'-----BEGIN DSA PRIVATE KEY-----',
    'ssh_dc_private_key': r'-----BEGIN EC PRIVATE KEY-----',
    'pgp_private_block': r'-----BEGIN PGP PRIVATE KEY BLOCK-----',
    'json_web_token': r'ey[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*$',
    'slack_token': r"\"api_token\":\"(xox[a-zA-Z]-[a-zA-Z0-9-]+)\"",
    'SSH_privKey': r"([-]+BEGIN [^\s]+ PRIVATE KEY[-]+[\s]*[^-]*[-]+END [^\s]+ PRIVATE KEY[-]+)",
    'possible_Creds': r"(?i)(" \
                      r"password\s*[`=:\"]+\s*[^\s]+|" \
                      r"password is\s*[`=:\"]*\s*[^\s]+|" \
                      r"pwd\s*[`=:\"]*\s*[^\s]+|" \
                      r"passwd\s*[`=:\"]+\s*[^\s]+)",
    'firebase_secrets': r'[a-z0-9.-]+\.firebaseio\.com',
    'facebook-token_secrets': r'EAACEdEose0cBA[0-9A-Za-z]+',
    'facebook-oauth_secrets': r'facebook.*[\'|\"][0-9a-f]{32}[\'|\"]',
    'google-service-account_secrets': r'\"type\": \"service_account\"',
    'google-token_secrets': r'ya29\.[0-9A-Za-z\-\_]+',
    'twitter-token_secrets': r'twitter.*[1-9][0-9]+-[0-9a-zA-Z]{40}',
    'aws-keys_secrets': r'([^A-Z0-9]|^)(AKIA|A3T|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{12,}',
    'asymmetric-keys_secrets': r'\-\-\-\-\-BEGIN ((EC|PGP|DSA|RSA|OPENSSH) )?PRIVATE KEY( BLOCK)?\-\-\-\-\-',
    'google-oauth_secrets': r'[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com',
    'github_secrets': r'github.*[\'|\"][0-9a-zA-Z]{35,40}[\'|\"]',
    'heroku-keys_secrets': r'heroku.*[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}',
    'mailchimp-keys_secrets': r'[0-9a-f]{32}-us[0-9]{1,2}',
    'paypal-token_secrets': r'access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}',
    'picatic-keys_secrets': r'sk_live_[0-9a-z]{32}',
    'slack-token_secrets': r'(xox[p|b|o|a]-[0-9]{12}-[0-9]{12}-[0-9]{12}-[a-z0-9]{32})',
    'slack-webhook_secrets' : r'https://hooks.slack.com/services/T[a-zA-Z0-9_]{8}/B[a-zA-Z0-9_]{8}/[a-zA-Z0-9_]{24}',
    'square-keys_secrets' : r'rsq0csp-[0-9A-Za-z\\-\\_]{43}',
    'twitter-oauth_secrets' : r'twitter.*[\'|\"][0-9a-zA-Z]{35,44}[\'|\"]',
    'miscellanious' : r'(aws_access|aws_secret|api[_-]?key|ListBucketResult|S3_ACCESS_KEY|Authorization:|RSA PRIVATE|Index of|aws_|secret|ssh-rsa AA)',
    'ip_address' : r'(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])',
    'another_secret' : r'access_key',
	    'another_secret' : r'access_token',
    'another_secret' : r'accessKey',
    'another_secret' : r'accessToken',
    'another_secret' : r'account_sid',
    'another_secret' : r'accountsid',
    'another_secret' : r'admin_pass',
    'another_secret' : r'admin_user',
    'another_secret' : r'api_key',
    'another_secret' : r'api_secret',
    'another_secret' : r'apikey',
    'another_secret' : r'app_key',
    'another_secret' : r'app_secret',
    'another_secret' : r'app_url',
    'another_secret' : r'application_id',
    'another_secret' : r'aws_secret_token',
    'another_secret' : r'authsecret',
    'another_secret' : r'aws_access',
    'another_secret' : r'aws_access_key_id',
    'another_secret' : r'aws_bucket',
    'another_secret' : r'aws_config',
    'another_secret' : r'aws_default_region',
    'another_secret' : r'aws_key',
    'another_secret' : r'aws_secret',
    'another_secret' : r'aws_secret_access_key',
    'another_secret' : r'aws_secret_key',
    'another_secret' : r'aws_token',
    'another_secret' : r'bucket_password',
    'another_secret' : r'client_secret',
    'another_secret' : r'cloudinary_api_key',
    'another_secret' : r'cloudinary_api_secret',
    'another_secret' : r'cloudinary_name',
    'another_secret' : r'connectionstring',
    'another_secret' : r'consumer_secret',
    'another_secret' : r'database_dialect',
    'another_secret' : r'database_host',
    'another_secret' : r'database_logging',
    'another_secret' : r'database_password',
    'another_secret' : r'database_schema',
    'another_secret' : r'database_schema_test',
    'another_secret' : r'database_url',
    'another_secret' : r'database_username',
    'another_secret' : r'db_connection',
    'another_secret' : r'db_database',
    'another_secret' : r'db_dialect',
    'another_secret' : r'db_host',
    'another_secret' : r'db_password',
    'another_secret' : r'db_port',
    'another_secret' : r'db_server',
    'another_secret' : r'db_username',
    'another_secret' : r'dbpasswd',
    'another_secret' : r'dbpassword',
    'another_secret' : r'dbuser',
    'another_secret' : r'django_password',
    'another_secret' : r'elastica_host',
    'another_secret' : r'elastica_port',
    'another_secret' : r'elastica_prefix',
    'another_secret' : r'email_host_password',
    'another_secret' : r'facebook_app_secret',
    'another_secret' : r'facebook_secret',
    'another_secret' : r'fb_app_secret',
    'another_secret' : r'fb_id',
    'another_secret' : r'fb_secret',
    'another_secret' : r'gatsby_wordpress_base_url',
    'another_secret' : r'gatsby_wordpress_client_id',
    'another_secret' : r'gatsby_wordpress_client_secret',
    'another_secret' : r'gatsby_wordpress_password',
    'another_secret' : r'gatsby_wordpress_protocol',
    'another_secret' : r'gatsby_wordpress_user',
    'another_secret' : r'github_id',
    'another_secret' : r'github_secret',
    'another_secret' : r'google_id',
    'another_secret' : r'google_oauth',
    'another_secret' : r'google_oauth_client_id',
    'another_secret' : r'google_oauth_client_secret',
    'another_secret' : r'google_oauth_secret',
    'another_secret' : r'google_secret',
    'another_secret' : r'google_server_key',
    'another_secret' : r'gsecr',
    'another_secret' : r'heroku_api_key',
    'another_secret' : r'heroku_key',
    'another_secret' : r'heroku_oauth',
    'another_secret' : r'heroku_oauth_secret',
    'another_secret' : r'heroku_oauth_token',
    'another_secret' : r'heroku_secret',
    'another_secret' : r'heroku_secret_token',
    'another_secret' : r'htaccess_pass',
    'another_secret' : r'htaccess_user',
    'another_secret' : r'incident_bot_name',
    'another_secret' : r'incident_channel_name',
    'another_secret' : r'jwt_passphrase',
    'another_secret' : r'jwt_password',
    'another_secret' : r'jwt_public_key',
    'another_secret' : r'jwt_secret',
    'another_secret' : r'jwt_secret_key',
    'another_secret' : r'jwt_secret_token',
    'another_secret' : r'jwt_token',
    'another_secret' : r'jwt_user',
    'another_secret' : r'keyPassword',
    'another_secret' : r'mail_driver',
    'another_secret' : r'mail_encryption',
    'another_secret' : r'mail_from_address',
    'another_secret' : r'mail_from_name',
    'another_secret' : r'mail_host',
    'another_secret' : r'mail_password',
    'another_secret' : r'mail_port',
    'another_secret' : r'mail_username',
    'another_secret' : r'mailgun_key',
    'another_secret' : r'mailgun_secret',
    'another_secret' : r'maps_api_key',
    'another_secret' : r'mix_pusher_app_cluster',
    'another_secret' : r'mix_pusher_app_key',
    'another_secret' : r'mysql_password',
    'another_secret' : r'oauth_discord_id',
    'another_secret' : r'oauth_discord_secret',
    'another_secret' : r'oauth_key',
    'another_secret' : r'oauth_token',
    'another_secret' : r'oauth2_secret',
    'another_secret' : r'password',
    'another_secret' : r'paypal_identity_token',
    'another_secret' : r'paypal_sandbox',
    'another_secret' : r'paypal_secret',
    'another_secret' : r'paypal_token',
    'another_secret' : r'playbooks_url',
    'another_secret' : r'postgres_password',
    'another_secret' : r'private_key',
    'another_secret' : r'pusher_app_cluster',
    'another_secret' : r'pusher_app_id',
    'another_secret' : r'pusher_app_key',
    'another_secret' : r'pusher_app_secret',
    'another_secret' : r'queue_driver',
    'another_secret' : r'redis_host',
    'another_secret' : r'redis_password',
    'another_secret' : r'redis_port',
    'another_secret' : r'response_auth_jwt_secret',
    'another_secret' : r'response_data_secret',
    'another_secret' : r'root_password',
    'another_secret' : r'sa_password',
    'another_secret' : r'secret',
    'another_secret' : r'secret_access_key',
    'another_secret' : r'secret_bearer',
    'another_secret' : r'secret_key',
    'another_secret' : r'secret_token',
    'another_secret' : r'secretKey',
    'another_secret' : r'security_credentials',
    'another_secret' : r'send_keys',
    'another_secret' : r'sentry_dsn',
    'another_secret' : r'session_driver',
    'another_secret' : r'session_lifetime',
    'another_secret' : r'sf_username',
    'another_secret' : r'sid twilio',
    'another_secret' : r'sid_token',
    'another_secret' : r'sid_twilio',
    'another_secret' : r'slack_channel',
    'another_secret' : r'slack_incoming_webhook',
    'another_secret' : r'slack_key',
    'another_secret' : r'slack_outgoing_token',
    'another_secret' : r'slack_secret',
    'another_secret' : r'slack_signing_secret',
    'another_secret' : r'slack_token',
    'another_secret' : r'slack_url',
    'another_secret' : r'slack_webhook',
    'another_secret' : r'slack_webhook_url',
    'another_secret' : r'square_access_token',
    'another_secret' : r'square_apikey',
    'another_secret' : r'square_app',
    'another_secret' : r'square_app_id',
    'another_secret' : r'square_appid',
    'another_secret' : r'square_secret',
    'another_secret' : r'square_token',
    'another_secret' : r'squareSecret',
    'another_secret' : r'squareToken',
    'another_secret' : r'ssh2_auth_password',
    'another_secret' : r'sshkey',
    'another_secret' : r'storePassword',
    'another_secret' : r'strip_key',
    'another_secret' : r'strip_secret',
    'another_secret' : r'strip_secret_token',
    'another_secret' : r'strip_token',
    'another_secret' : r'stripe_key',
    'another_secret' : r'stripe_secret',
    'another_secret' : r'stripe_secret_token',
    'another_secret' : r'stripe_token',
    'another_secret' : r'stripSecret',
    'another_secret' : r'stripToken',
    'another_secret' : r'stripe_publishable_key',
    'another_secret' : r'token_twilio',
    'another_secret' : r'trusted_hosts',
    'another_secret' : r'twi_auth',
    'another_secret' : r'twi_sid',
    'another_secret' : r'twilio_account_id',
    'another_secret' : r'twilio_account_secret',
    'another_secret' : r'twilio_account_sid',
    'another_secret' : r'twilio_accountsid',
    'another_secret' : r'twilio_api',
    'another_secret' : r'twilio_api_auth',
    'another_secret' : r'twilio_api_key',
    'another_secret' : r'twilio_api_secret',
    'another_secret' : r'twilio_api_sid',
    'another_secret' : r'twilio_api_token',
    'another_secret' : r'twilio_auth',
    'another_secret' : r'twilio_auth_token',
    'another_secret' : r'twilio_secret',
    'another_secret' : r'twilio_secret_token',
    'another_secret' : r'twilio_sid',
    'another_secret' : r'twilio_token',
    'another_secret' : r'twilioapiauth',
    'another_secret' : r'twilioapisecret',
    'another_secret' : r'twilioapisid',
    'another_secret' : r'twilioapitoken',
    'another_secret' : r'TwilioAuthKey',
    'another_secret' : r'TwilioAuthSid',
    'another_secret' : r'twilioauthtoken',
    'another_secret' : r'TwilioKey',
    'another_secret' : r'twiliosecret',
    'another_secret' : r'TwilioSID',
    'another_secret' : r'twiliotoken',
    'another_secret' : r'twitter_api_secret',
    'another_secret' : r'twitter_consumer_key',
    'another_secret' : r'twitter_consumer_secret',
    'another_secret' : r'twitter_key',
    'another_secret' : r'twitter_secret',
    'another_secret' : r'twitter_token',
    'another_secret' : r'twitterKey',
    'another_secret' : r'twitterSecret',
    'another_secret' : r'wordpress_password',
    'another_secret' : r'zen_key',
    'another_secret' : r'zen_tkn',
    'another_secret' : r'zen_token',
    'another_secret' : r'zendesk_api_token',
    'another_secret' : r'zendesk_key',
    'another_secret' : r'zendesk_token',
    'another_secret' : r'zendesk_url',
    'another_secret' : r'zendesk_username',
    'another_secret' : r'zendesk_password',
}

_template = '''
<!DOCTYPE html>
<html>
<head>
  <meta charset="UTF-8">
  <style>
       h1 {
          font-family: sans-serif;
       }
       a {
          color: #000;
       }
       .text {
          font-size: 16px;
          font-family: Helvetica, sans-serif;
          color: #323232;
          background-color: white;
       }
       .container {
          background-color: #e9e9e9;
          padding: 10px;
          margin: 10px 0;
          font-family: helvetica;
          font-size: 13px;
          border-width: 1px;
          border-style: solid;
          border-color: #8a8a8a;
          color: #323232;
          margin-bottom: 15px;
       }
       .button {
          padding: 17px 60px;
          margin: 10px 10px 10px 0;
          display: inline-block;
          background-color: #f4f4f4;
          border-radius: .25rem;
          text-decoration: none;
          -webkit-transition: .15s ease-in-out;
          transition: .15s ease-in-out;
          color: #333;
          position: relative;
       }
       .button:hover {
          background-color: #eee;
          text-decoration: none;
       }
       .github-icon {
          line-height: 0;
          position: absolute;
          top: 14px;
          left: 24px;
          opacity: 0.7;
       }
  </style>
  <title>LinkFinder Output</title>
</head>
<body contenteditable="true">
  $$content$$

  <a class='button' contenteditable='false' href='https://github.com/m4ll0k/SecretFinder/issues/new' rel='nofollow noopener noreferrer' target='_blank'><span class='github-icon'><svg height="24" viewbox="0 0 24 24" width="24" xmlns="http://www.w3.org/2000/svg">
  <path d="M9 19c-5 1.5-5-2.5-7-3m14 6v-3.87a3.37 3.37 0 0 0-.94-2.61c3.14-.35 6.44-1.54 6.44-7A5.44 5.44 0 0 0 20 4.77 5.07 5.07 0 0 0 19.91 1S18.73.65 16 2.48a13.38 13.38 0 0 0-7 0C6.27.65 5.09 1 5.09 1A5.07 5.07 0 0 0 5 4.77a5.44 5.44 0 0 0-1.5 3.78c0 5.42 3.3 6.61 6.44 7A3.37 3.37 0 0 0 9 18.13V22" fill="none" stroke="#000" stroke-linecap="round" stroke-linejoin="round" stroke-width="2"></path></svg></span> Report an issue.</a>
</body>
</html>
'''


def parser_error(msg):
    print('Usage: python %s [OPTIONS] use -h for help' % sys.argv[0])
    print('Error: %s' % msg)
    sys.exit(0)


def getContext(matches, content, name, rex='.+?'):
    ''' get context '''
    items = []
    matches2 = []
    for i in [x[0] for x in matches]:
        if i not in matches2:
            matches2.append(i)
    for m in matches2:
        context = re.findall('%s%s%s' % (rex, m, rex), content, re.IGNORECASE)

        item = {
            'matched': m,
            'name': name,
            'context': context,
            'multi_context': True if len(context) > 1 else False
        }
        items.append(item)
    return items


def parser_file(content, mode=1, more_regex=None, no_dup=1):
    ''' parser file '''
    if mode == 1:
        if len(content) > 1000000:
            content = content.replace(";", ";\r\n").replace(",", ",\r\n")
        else:
            content = jsbeautifier.beautify(content)
    all_items = []
    for regex in _regex.items():
        r = re.compile(regex[1], re.VERBOSE)
        if mode == 1:
            all_matches = [(m.group(0), m.start(0), m.end(0)) for m in re.finditer(r, content)]
            items = getContext(all_matches, content, regex[0])
            if items != []:
                all_items.append(items)
        else:
            items = [{
                'matched': m.group(0),
                'context': [],
                'name': regex[0],
                'multi_context': False
            } for m in re.finditer(r, content)]
        if items != []:
            all_items.append(items)
    if all_items != []:
        k = []
        for i in range(len(all_items)):
            for ii in all_items[i]:
                if ii not in k:
                    k.append(ii)
        if k != []:
            all_items = k

    if no_dup:
        all_matched = set()
        no_dup_items = []
        for item in all_items:
            if item != [] and type(item) is dict:
                if item['matched'] not in all_matched:
                    all_matched.add(item['matched'])
                    no_dup_items.append(item)
        all_items = no_dup_items

    filtered_items = []
    if all_items != []:
        for item in all_items:
            if more_regex:
                if re.search(more_regex, item['matched']):
                    filtered_items.append(item)
            else:
                filtered_items.append(item)
    return filtered_items


def parser_input(input):
    ''' Parser Input '''
    # method 1 - url
    schemes = ('http://', 'https://', 'ftp://', 'file://', 'ftps://')
    if input.startswith(schemes):
        return [input]
    # method 2 - url inpector firefox/chrome
    if input.startswith('view-source:'):
        return [input[12:]]
    # method 3 - Burp file
    if args.burp:
        jsfiles = []
        items = []

        try:
            items = xml.etree.ElementTree.fromstring(open(args.input, 'r').read())
        except Exception as err:
            print(err)
            sys.exit()
        for item in items:
            jsfiles.append(
                {
                    'js': base64.b64decode(item.find('response').text).decode('utf-8', 'replace'),
                    'url': item.find('url').text
                }
            )
        return jsfiles
    # method 4 - folder with a wildcard
    if '*' in input:
        paths = glob.glob(os.path.abspath(input))
        for index, path in enumerate(paths):
            paths[index] = "file://%s" % path
        return (paths if len(paths) > 0 else parser_error('Input with wildcard does not match any files.'))

    # method 5 - local file
    path = "file://%s" % os.path.abspath(input)
    return [path if os.path.exists(input) else parser_error(
        'file could not be found (maybe you forgot to add http/https).')]


def html_save(output):
    ''' html output '''
    hide = os.dup(1)
    os.close(1)
    os.open(os.devnull, os.O_RDWR)
    try:
        text_file = open(args.output, "wb")
        text_file.write(_template.replace('$$content$$', output).encode('utf-8'))
        text_file.close()

        print('URL to access output: file://%s' % os.path.abspath(args.output))
        file = 'file:///%s' % (os.path.abspath(args.output))
        if sys.platform == 'linux' or sys.platform == 'linux2':
            subprocess.call(['xdg-open', file])
        else:
            webbrowser.open(file)
    except Exception as err:
        print('Output can\'t be saved in %s due to exception: %s' % (args.output, err))
    finally:
        os.dup2(hide, 1)


def cli_output(matched):
    ''' cli output '''
    for match in matched:
        print(match.get('name') + '\t->\t' + match.get('matched').encode('ascii', 'ignore').decode('utf-8'))


def urlParser(url):
    ''' urlParser '''
    parse = urlparse(url)
    urlParser.this_root = parse.scheme + '://' + parse.netloc
    urlParser.this_path = parse.scheme + '://' + parse.netloc + '/' + parse.path


def extractjsurl(content, base_url):
    ''' JS url extract from html page '''
    soup = html.fromstring(content)
    all_src = []
    urlParser(base_url)
    for src in soup.xpath('//script'):
        src = src.xpath('@src')[0] if src.xpath('@src') != [] else []
        if src != []:
            if src.startswith(('http://', 'https://', 'ftp://', 'ftps://')):
                if src not in all_src:
                    all_src.append(src)
            elif src.startswith('//'):
                src = 'http://' + src[2:]
                if src not in all_src:
                    all_src.append(src)
            elif src.startswith('/'):
                src = urlParser.this_root + src
                if src not in all_src:
                    all_src.append(src)
            else:
                src = urlParser.this_path + src
                if src not in all_src:
                    all_src.append(src)
    if args.ignore and all_src != []:
        temp = all_src
        ignore = []
        for i in args.ignore.split(';'):
            for src in all_src:
                if i in src:
                    ignore.append(src)
        if ignore:
            for i in ignore:
                temp.pop(int(temp.index(i)))
        return temp
    if args.only:
        temp = all_src
        only = []
        for i in args.only.split(';'):
            for src in all_src:
                if i in src:
                    only.append(src)
        return only
    return all_src


def send_request(url):
    ''' Send Request '''
    # read local file
    # https://github.com/dashea/requests-file
    if 'file://' in url:
        s = requests.Session()
        s.mount('file://', FileAdapter())
        return s.get(url).content.decode('utf-8', 'replace')
    # set headers and cookies
    headers = {}
    default_headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.36',
        'Accept': 'text/html, application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.8',
        'Accept-Encoding': 'gzip'
    }
    if args.headers:
        for i in args.header.split('\\n'):
            # replace space and split
            name, value = i.replace(' ', '').split(':')
            headers[name] = value
            # add cookies
    if args.cookie:
        headers['Cookie'] = args.cookie

    headers.update(default_headers)
    # proxy
    proxies = {}
    if args.proxy:
        proxies.update({
            'http': args.proxy,
            'https': args.proxy,
            # ftp
        })
    try:
        resp = requests.get(
            url=url,
            verify=False,
            headers=headers,
            proxies=proxies
        )
        return resp.content.decode('utf-8', 'replace')
    except Exception as err:
        print(err)
        sys.exit(0)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("-e", "--extract", help="Extract all javascript links located in a page and process it",
                        action="store_true", default=False)
    parser.add_argument("-i", "--input", help="Input a: URL, file or folder", required="True", action="store")
    parser.add_argument("-o", "--output", help="Where to save the file, including file name. Default: output.html",
                        action="store", default="output.html")
    parser.add_argument("-r", "--regex", help="RegEx for filtering purposes against found endpoint (e.g: ^/api/)",
                        action="store")
    parser.add_argument("-b", "--burp", help="Support burp exported file", action="store_true")
    parser.add_argument("-c", "--cookie", help="Add cookies for authenticated JS files", action="store", default="")
    parser.add_argument("-g", "--ignore", help="Ignore js url, if it contain the provided string (string;string2..)",
                        action="store", default="")
    parser.add_argument("-n", "--only", help="Process js url, if it contain the provided string (string;string2..)",
                        action="store", default="")
    parser.add_argument("-H", "--headers", help="Set headers (\"Name:Value\\nName:Value\")", action="store", default="")
    parser.add_argument("-p", "--proxy", help="Set proxy (host:port)", action="store", default="")
    args = parser.parse_args()

    if args.input[-1:] == "/":
        # /aa/ -> /aa
        args.input = args.input[:-1]

    mode = 1
    if args.output == "cli":
        mode = 0
    # add args
    if args.regex:
        # validate regular exp
        try:
            r = re.search(args.regex, ''.join(
                random.choice(string.ascii_uppercase + string.digits) for _ in range(random.randint(10, 50))))
        except Exception as e:
            print('your python regex isn\'t valid')
            sys.exit()

        _regex.update({
            'custom_regex': args.regex
        })

    if args.extract:
        content = send_request(args.input)
        urls = extractjsurl(content, args.input)
    else:
        # convert input to URLs or JS files
        urls = parser_input(args.input)
    # conver URLs to js file
    output = ''
    for url in urls:
        print('[ + ] URL: ' + url)
        if not args.burp:
            file = send_request(url)
        else:
            file = url.get('js')
            url = url.get('url')

        matched = parser_file(file, mode)
        if args.output == 'cli':
            cli_output(matched)
        else:
            output += '<h1>File: <a href="%s" target="_blank" rel="nofollow noopener noreferrer">%s</a></h1>' % (
            escape(url), escape(url))
            for match in matched:
                _matched = match.get('matched')
                _named = match.get('name')
                header = '<div class="text">%s' % (_named.replace('_', ' '))
                body = ''
                # find same thing in multiple context
                if match.get('multi_context'):
                    # remove duplicate
                    no_dup = []
                    for context in match.get('context'):
                        if context not in no_dup:
                            body += '</a><div class="container">%s</div></div>' % (context)
                            body = body.replace(
                                context, '<span style="background-color:yellow">%s</span>' % context)
                            no_dup.append(context)
                        # --
                else:
                    body += '</a><div class="container">%s</div></div>' % (match.get('context')[0])
                    body = body.replace(
                        match.get('context')[0],
                        '<span style="background-color:yellow">%s</span>' % (match.get('context')[0])
                    )
                output += header + body
    if args.output != 'cli':
        html_save(output)
