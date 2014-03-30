Plugin for YOURLS 1.5+: Antispam

# What for

This is a __merciless__ __antispam__ plugin that uses the three major blacklists (<a href="http://spamhaus.org">Spamhaus</a>, <a href="http://uribl.com/">URIBL</a> and <a href="http://surbl.org/">SURBL</a>).

URL are checked against the blacklist when short urls are created. They are also randomly checked when someone follows a short
URL and if the link has been compromised recently, the short URL is created.

# How to

* In `/user/plugins`, create a new folder named `antispam`
* Drop these files in that directory
* Go to the Plugins administration page and activate the plugin 
* Have fun

# Disclaimer

Checking against blacklists may or may not work for you, this may depend on the type of spam you are getting. Try and see.