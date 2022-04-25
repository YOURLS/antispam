# Plugin for YOURLS 1.5+: Antispam

## What for

This is an antispam plugin that uses major DNS blacklists to detect spam, at link creation time and at visit time :

- URL are checked against the blacklist when short urls are created.
- They are also randomly checked when someone follows a short URL and if the link has been compromised recently, the 
short URL is deleted.

DNS backlists used: `zen.spamhaus.org`, `multi.surbl.org`, `bl.spamcop.net`, `combined.abuse.ch`, `dnsbl.sorbs.net`.

## How to

* In `/user/plugins`, create a new folder named `antispam`
* Drop these files in that directory
* Go to the Plugins administration page and activate the plugin 
* Have fun

## Disclaimer - please read

Checking against DNS blacklists may or may not work for you, this may depend on the type of spam you are getting and on
other factors such as your server IP, your server ISP, the DNS you are using. It may even result in all domains being
blacklisted from your server. Try and see.

If you're not sure what DNS blacklists are, you can check out the [DNSBLs list](https://www.dnsbl.info/).

If you're still not sure this plugin is for you, we recommend you use another plugin, such as
[Google Safe Browsing](https://github.com/YOURLS/google-safe-browsing), or a plugin that will add a captcha to your
public interface -- see the plugin list at https://github.com/YOURLS/awesome-yourls.
