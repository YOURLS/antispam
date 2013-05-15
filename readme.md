Plugin for YOURLS 1.5+: Antispam

# What for

This is a __merciless__ __antispam__ plugin that uses the three major blacklists (<a href="http://spamhaus.org">Spamhaus</a>, <a href="http://uribl.com/">URIBL</a> and <a href="http://surbl.org/">SURBL</a>).

URL are checked against the blacklist when short urls are created.

In a future version, there will be also a check once in a while after they have been created, to remove URL that have been compromised after creation

When a domain is blacklisted, you cannot create a short URL to it, and all previously created short URLs pointing to it are deleted.

# How to

* In `/user/plugins`, create a new folder named `antispam`
* Drop these files in that directory
* Go to the Plugins administration page and activate the plugin 
* Have fun

