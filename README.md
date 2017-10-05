# storedsafe-tokenhandler

storedsafe-tokenhandler.py is a simple script to login and aquire a token used for subsequent REST API calls to a StoredSafe instance.

It can also be used to keep a token alive, by schedule a ```storedsafe-tokenhandler.py --check``` regulary (e.g. via cron(1)).

The script is written in Python v2 and has been tested on macOS Sierra and on Linux (any fairly recent version of Ubuntu or Red Hat should work fine).

It is designed for version 1.0 of StoredSafes REST-Like API.

## Installation instructions

This script requires Python v2 and some libraries. All of the required libraries are normally installed by default.

It has been developed and tested using Python v2.7.10, on macOS Sierra 10.12.6.

## Syntax

```
Usage: storedsafe-tokenhandler.py [-loc]
 --login (or -l)	To login to the StoredSafe appliance
 --logout (or -o)	To logout from the StoredSafe appliance
 --check (or -c)	To check/refresh already obtained token

All actions require that you firstly authenticate in order to obtain a token.
Once you have a token you can use it to authenticate new REST operations.

Authentication information is saved to ~/.storedsafe-client.rc, be sure to protect it properly.
```

```
--login
``` 
> Login to the StoredSafe appliance, aquire a token and store all relevant information in ```~/.storedsafe-client.rc```

```
--logout
```
> Logout from the StoredSafe appliance and destroy the aquired token. Zeroes out the token in ```~/.storedsafe-client.rc```

```
--check
```
> Renews the lifetime of the aquired token and ensures connectivity to the StoredSafe appliance. Can be scheduled with cron(1).

Usage
=====
Login to the StoredSafe appliance. This will aquire a valid token which can be used for subsequent REST API calls to StoredSafe.

```
$ storedsafe-tokenhandler.py --login
Enter Username: sven
Enter Apikey: AnAPIKey
Enter Site (storedsafe.example.com): safe.domain.cc
Enter Password: <secret password entered>
Press Yubikey: <OTP generated>
200 OK
Login succeeded, please remember to log out when done.
```
If a previous login has been done (the ```~/.storedsafe-client.rc``` exists), information will be used from it to suggest values.

```
$ storedsafe-tokenhandler.py --login
Apikey is set to "AnAPIKey", do you want to keep it? (<Y>/n):
Site is set to "safe.domain.cc", do you want to keep it? (<Y>/n):
Username is set to "sven", do you want to keep it? (<Y>/n):
Enter Password: <secret password entered>
Press Yubikey: <OTP generated>
200 OK
Login succeeded, please remember to log out when done.
```

Check validity of the token, connectivity to the StoredSafe appliance and renew lifetime of the aquired token.

```
$ storedsafe-tokenhandler.py --check
200 OK
```

Logout and destroy the aquired token.

```
$ storedsafe-tokenhandler.py --logout
Logout successful.
```

## Limitations / Known issues
None.

## License
GPL
