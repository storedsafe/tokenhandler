#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
when       who                       what
2019-07-22 fredrik@storedsafe.com    Minor cosmetic changes.
2019-07-22 fredrik.eriksson@cert.se  Rewritten from scratch with python3 support.

This is small script to login and acquire a token used for subsequent REST API calls.
It can also be used to keep a token alive, by schedule a 'check' action regulary (e.g. cron(1)).

"""

import argparse
import getpass
import http.client
import json
import logging
import os
import re
import ssl
import sys
import urllib.request, urllib.parse, urllib.error
import stat

__author__     = "Fredrik Eriksson"
__copyright__  = "Copyright 2020, Fredrik Eriksson"
__license__    = "GPL"
__version__    = "1.0.6"
__maintainer__ = "Fredrik Soderblom"
__email__      = "fredrik@storedsafe.com"
__status__     = "Production"

LOG_NAME = 'storedsafe'
rc_file_tokens = {
        'token': re.compile(r'^token:([a-zA-Z0-9]+)$'),
        'username': re.compile(r'^username:([-a-zA-Z0-9_.@]+)$'),
        'apikey': re.compile(r'^apikey:([-a-zA-Z0-9]+)$'),
        'hostname': re.compile(r'^mysite:([-a-zA-Z0-9_.]+)$')
        }

def get_args():
    parser = argparse.ArgumentParser(description='Acquire and maintain StoredSafe tokens')
    
    parser.add_argument('-f', '--file',
            help='File where StoredSafe token is/should be stored (defaults to ~/.storedsafe-client.rc).',
            default="{}/.storedsafe-client.rc".format(os.path.expanduser('~')))
    parser.add_argument('-q', '--quiet',
            help='Silence all output except errors and requests for input.', 
            action="store_true")
    parser.add_argument('-c', '--trusted-ca',
            help='File or directory containing certificates of trusted CAs.',
            default=None)

    subparsers = parser.add_subparsers(title='action', help='What to do')
    subparsers.required = True
    subparsers.dest = 'action'
    login = subparsers.add_parser('login', help='Login to StoredSafe and acquire token')
    login.add_argument('-u', '--username', 
            default=os.getenv('STOREDSAFE_USER'),
            help='StoredSafe username.')
    login.add_argument('-s', '--hostname',
            default=os.getenv('STOREDSAFE_HOST'),
            help='hostname of StoredSafe server.')
    login.add_argument('-a', '--apikey',
            default=os.getenv('STOREDSAFE_APIKEY'),
            help='API-key to use.')

    check = subparsers.add_parser('check', help='Renew token if still valid.')
    logout = subparsers.add_parser('logout', help='Logout from StoredSafe and disable token.')
    return parser.parse_args()

def main():
    log = logging.getLogger(LOG_NAME)
    handler = logging.StreamHandler()
    log.addHandler(handler)

    args = get_args()
    if args.action == 'check':
        params = get_ss_login_params(args, batch=True)
        if 'token' not in params:
            if not args.quiet:
                log.warning('Token missing, not logged in.')
            sys.exit(1)
        res = check(host=params['hostname'], token=params['token'], ca=args.trusted_ca)
        if res['CALLINFO']['status'] == 'SUCCESS':
            # Rotate token if needed
            # https://developer.storedsafe.com/introduction/index.html#token-rotation
            if res['CALLINFO']['token'] != res['DATA']['token']:
                params['token'] = res['CALLINFO']['token']
                save_ss_login_params(args.file, params)

            if not args.quiet:
                print('StoredSafe token still valid.')
        else:
            if res['ERRORCODES'].get('1200'):
              print('Token invalid, not logged in.')
            else:
              fail('StoredSafe returned an error: {}'.format(res['ERRORCODES']))

    elif args.action == 'logout':
        params = get_ss_login_params(args, batch=True)
        if 'token' not in params:
            if not args.quiet:
                log.warning('Token missing, not logged in.')
            sys.exit(1)
        res = logout(host=params['hostname'], token=params['token'], ca=args.trusted_ca)
        if res['CALLINFO']['status'] == 'SUCCESS':
            del params['token']
            save_ss_login_params(args.file, params)
            if not args.quiet:
                print('Logout successful.')
        else:
            fail('StoredSafe returned an error: {}'.format(res['ERRORCODES']))

    elif args.action == 'login':
        params = get_ss_login_params(args)
        if 'token' in params:
            del params['token']
        params['ca'] = args.trusted_ca
        res = login(**params)
        if res['CALLINFO']['status'] == 'SUCCESS':
            params['token'] = res['CALLINFO']['token']
            save_ss_login_params(args.file, params)
            if not args.quiet:
                print('Login successful.')
        else:
            fail('StoredSafe returned an error: {}'.format(res['ERRORCODES']))

def save_ss_login_params(path, params):
    d = os.path.dirname(path)
    if os.path.exists(d) and os.path.isdir(d):
        st = os.stat(d)
        if ((bool(st.st_mode & stat.S_IROTH)) or \
            (bool(st.st_mode & stat.S_IWOTH)) or\
            (bool(st.st_mode & stat.S_IWGRP))):
            fail('Insecure permissions on directory \"{}\"'.format(d))
    else:
        fail('\"{}\" is not a directory.'.format(d))

    old_umask = os.umask(0o66)
    try:
        with open(path, 'w') as f:
            if 'token' in params:
                f.write('token:{}\n'.format(params['token']))
            f.write('username:{}\napikey:{}\nmysite:{}\n'.format(
                params['username'],
                params['apikey'],
                params['hostname']))
        os.umask(old_umask)
    except OSError as oe:
        os.umask(old_umask)
        fail('Could not save StoredSafe parameters: {}'.format(oe))

def get_ss_login_params(args, batch=False):
    params = {}
    try:
        with open(args.file, 'r') as f:
            for line in f:
                for name,regex in list(rc_file_tokens.items()):
                    match = re.match(regex, line)
                    if match:
                        params[name] = match.group(1)
    except (OSError, FileNotFoundError):
        pass

    args_dict = vars(args)
    for key in ['username', 'hostname', 'apikey']:
        if not key in params:
            if key in args_dict and args_dict[key]:
                params[key] = args_dict[key]
            elif not batch:
                params[key] = input('Please enter StoredSafe {}: '.format(key))
    
    params['password'] = os.getenv('STOREDSAFE_PASS')
    params['otp'] = os.getenv('STOREDSAFE_OTP')

    if not batch:
        if not params['password']:
            params['password'] = getpass.getpass('StoredSafe password: ')
        if not params['otp']:
            params['otp'] = getpass.getpass('Enter OTP (Yubikey or TOTP): ')

    return params

def do_https_req(host, method, url, payload, ca):
    if method == 'GET':
        url = "{}?{}".format(url, urllib.parse.urlencode(payload, doseq=True))
        payload = None
    else:
        payload = json.dumps(payload)

    if ca == None:
        ssl_context = ssl.create_default_context(purpose=ssl.Purpose.SERVER_AUTH)
    elif os.path.isdir(ca):
        ssl_context = ssl.create_default_context(purpose=ssl.Purpose.SERVER_AUTH, capath=ca)
    elif os.path.isfile(ca):
        ssl_context = ssl.create_default_context(purpose=ssl.Purpose.SERVER_AUTH, cafile=ca)
    else:
        fail("Invalid ca path: {}".format(ca))

    try:
        con = http.client.HTTPSConnection(host, context = ssl_context)
        con.request(method, url, payload)
    except ssl.CertificateError as ce:
        fail("SSL verification failed for http://{}: {}".format(host, ce))
    except (http.client.HTTPException, ConnectionError, OSError) as he:
        fail("Could not contact StoredSafe at https://{}: {}".format(host, he))
    
    response = con.getresponse()
    return json.loads(response.read())

def login(username, hostname, apikey, password, otp, ca):
    if len(otp) > 8:
        payload = {
                'username': username,
                'keys': "{}{}{}".format(password, apikey, otp)
                }
    else:
        payload = {
                'username': username,
                'passphrase': password,
                'otp': otp,
                'apikey': apikey,
                'logintype': 'totp'
                }
    return do_https_req(hostname, 'POST', '/api/1.0/auth', payload, ca)

def logout(host, token, ca):
    return do_https_req(host, 'GET', '/api/1.0/auth/logout', { 'token': token }, ca)

def check(host, token, ca):
    return do_https_req(host, 'POST', '/api/1.0/auth/check', { 'token': token }, ca)

def fail(msg):
    log = logging.getLogger(LOG_NAME)
    log.error(msg)
    sys.exit(2)

if __name__ == '__main__':
    main()
