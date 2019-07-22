# tokenhandler

tokenhandler.py is a simple script to login and aquire a token used for subsequent REST API calls to a StoredSafe instance.

It can also be used to keep a token alive, by schedule a ```tokenhandler.py check``` regulary (e.g. via cron(1)).

The script is written in Python v3 and has been tested on macOS Sierra and on Linux (any fairly recent version of Ubuntu or Red Hat should work fine).

It is designed for version 1.0 of StoredSafes REST-Like API.

## Installation instructions

This script requires Python v3 and some libraries. All of the required libraries are normally installed by default.

It has been developed and tested using Python v3.7.4, on macOS Sierra 10.14.5.

## Syntax

```
$ tokenhandler.py --help
usage: tokenhandler.py [-h] [-f FILE] [-q] [-c TRUSTED_CA]
                       {login,check,logout} ...

Aquire and maintain StoredSafe tokens

optional arguments:
  -h, --help            show this help message and exit
  -f FILE, --file FILE  File where StoredSafe token is/should be stored
                        (defaults to ~/.storedsafe-client.rc)
  -q, --quiet           Silence all output except errors and requests for
                        input
  -c TRUSTED_CA, --trusted-ca TRUSTED_CA
                        File or directory containing certificates of trusted
                        CAs

action:
  {login,check,logout}  What to do
    login               Login to StoredSafe and aquire token
    check               Renew token if still valid
    logout              Logout from StoredSafe and disable token
```
Optional arguments can be:

```
--file FILE, -f FILE
```
> Store token and relevant information in FILE (Defaults to ```~/.storedsafe-client.rc```)

```
--quiet, -q
```
> Silence all output except errors and requests for input

```
--trusted-ca TRUSTED_CA, -c TRUSTED_CA
```
> File or directory containing certificates of trusted CAs

And action can be any of:

```
login
``` 
> Login to the StoredSafe appliance, aquire a token and store all relevant information in ```~/.storedsafe-client.rc```.

```
logout
```
> Logout from the StoredSafe appliance and destroy the aquired token. Zeroes out the token in ```~/.storedsafe-client.rc```.

```
check
```
> Renews the lifetime of the aquired token and ensures connectivity to the StoredSafe appliance. Can be scheduled with cron(1).

### Login
When action is ```login``` the following optional arguments might be used.

```
--username USERNAME, -u USERNAME
```
> StoredSafe username.

```
--hostname HOSTNAME, -h HOSTNAME
```
> hostname of StoredSafe server.

```
--apikey APIKEY, -a APIKEY
```
> API-key to use.

#### Environment variables
When action is ```login``` the following optional environment variables might be used.

```
$ export STOREDSAFE_USER="sven"
```
> StoredSafe username.

```
$ export STOREDSAFE_HOST="safe.domain.cc"
```
> hostname of StoredSafe server.

```
$ export STOREDSAFE_APIKEY="MyAPIKey"
```
> API-key to use.

```
$ export STOREDSAFE_PASS="<super-secret-passphrase>"
```
> Passphrase for login.

```
$ export STOREDSAFE_OTP="<an-yubikey-otp>"
```
> OTP (or TOTP) to be used for login.

Usage
=====
Login to the StoredSafe appliance. This will aquire a valid token which can be used for subsequent REST API calls to StoredSafe.

```
$ tokenhandler.py login
Please enter StoredSafe username: sven
Please enter StoredSafe hostname: safe.domain.cc
Please enter StoredSafe apikey: AnAPIKey
StoredSafe password: <secret password entered>
Enter OTP (Yubikey or TOTP): <OTP or TOTP>
Login successful.

```
If a previous login has been done (the ```~/.storedsafe-client.rc``` exists), information will be used from it to suggest values.

```
$ tokenhandler.py login
StoredSafe password: <secret password entered>
Enter OTP (Yubikey or TOTP): <OTP or TOTP>
Login successful.
```

Check validity of the token, connectivity to the StoredSafe appliance and renew lifetime of the aquired token.

```
$ tokenhandler.py check
StoredSafe token still valid.
```

Logout and destroy the aquired token.

```
$ tokenhandler.py logout
Logout successful.
```

## Limitations / Known issues

Script tries to ensure fairly strict permissions on the actual rc-file and the directory where it is stored. If it finds any of those insufficient, it will print an error message and exit.

```~/.storedsafe-client.rc``` is expected to be only readable and writeable by it's owner.

The directory to hold the RC file (```--file``` option) is expected to be only readable and writeable by it's owner and possibly have read permissions for the users group.

## Legacy
The old, python2, client is available in the ```python2``` directory.

## Author
The refactored tokehandler for python3 was completely re-written from scratch by Fredrik Eriksson, CERT-SE. Many thanks and mad shouts to him.

## License
GPL
