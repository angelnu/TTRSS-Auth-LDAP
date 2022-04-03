# Tiny Tiny RSS LDAP authentication

This plugin adds authentication with LDAP.


## Installation

First of app, make sure you have `php-ldap` installed.
For Debian/Ubuntu users, just do

`sudo apt-get install php-ldap`

Git clone to `plugins.local/auth_ldap`


## Configuration

Setup variables via `.env`:

* Required:
  - `TTRSS_PLUGINS=auth_ldap`
  - `TTRSS_LDAP_AUTH_SERVER_URI="ldap://localhost:389/"`
* Optional:
  - `TTRSS_LDAP_AUTH_USETLS=True` - Enables StartTLS Support for ldap://
  - `TTRSS_LDAP_AUTH_ALLOW_UNTRUSTED_CERT=True` - Allows untrusted certificate
  - `TTRSS_LDAP_AUTH_BINDDN="cn=???,dc=example,dc=com"` - bind DN. `???` is replaced with the userId (escaped) trying to login
  - `TTRSS_LDAP_AUTH_BINDPW="ServiceAccountsPassword"` - bind password. Defaults to password entered by user trying to login
  - `TTRSS_LDAP_AUTH_BASEDN="dc=example,dc=com"` - base DN to search users
  - `TTRSS_LDAP_AUTH_SEARCHFILTER="(&(objectClass=person)(uid=???))"` - LDAP search filter. It must return a single user. If not set only a binding is done to loging the user.
  - `TTRSS_LDAP_AUTH_LOGIN_ATTRIB="cn"` - LDAP attribute with the login ID for tt-rss
  - `TTRSS_LDAP_AUTH_FULLNAME_ATTRIB="name"` - LDAP attribute with the full username. It will be used to update the user email in tt-rss
  - `TTRSS_LDAP_AUTH_EMAIL_ATTRIB="mail"` - LDAP attribute with the email. It will be used to update the user email in tt-rss
  - `TTRSS_LDAP_AUTH_DEBUG=True` - logs login process
