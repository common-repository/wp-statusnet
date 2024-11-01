=== WP-Status.net ===
Contributors: Xavier Media
Tags: Status.net, Identica, Twitter, status updates, oauth, Yourls.org
Requires at least: 2.7.0
Tested up to: 3.3.1
Stable tag: 1.4.2

Posts your blog posts to one or multiple Status.net servers and even to Twitter

== Description ==

Every time you make a new blog post this plugin will post a status update to the Status.net servers and Twitter accounts 
you have specified. You can set as many acounts on as many servers you like. You can even have the plugin to post to
different account on the same [Status.net](http://status.net) server.

The links to your blog can be shortened by one of seven different link shortener services like TinyURL.com.

== Installation ==

1. Upload `wp-status-net/wp-status-net.php' to the '/wp-content/plugins/' directory
2. Activate the plugin through the 'Plugins' menu in WordPress
3. Go to the 'WP-Status.net' menu option under 'Settings' to specify the accounts and servers

== Frequently Asked Questions ==

= How to use Oauth with Twitter? =

1. Register a new application at http://dev.twitter.com/apps/new
    * Application Type must be set on Browser
    * The Callback URL should be the URL of your blog
    * Default Access type MUST be set to Read & Write
2. Fill in the Consumer Key and Consumer Secret in the correct fields (will show up as soon as you select Server Type "Twitter" and "Oauth" in the server list)
3. Click on the link called "My Access Tokens" at http://dev.twitter.com (right menu)
4. Fill in your Access Token and the Access Token Secret in the correct fields
5. Now you should be able to post to Twitter

= How do I get access to the 2ve.org link shortener API? =

The 2ve.org service is at the moment only open for Xavier Media, but you can choose any of the other link shorteners instead.

= How can I suggest a new feature or report a bug? =

Visit our support forum at http://www.xavierforum.com/php-&-cgi-scripts-f3.html

== Changelog ==

= 1.4.2 =
* Added support for Yourls.org on your own site 

= 1.4.1 =
* Removed RT.nu since they are no longer in service

= 1.3.1 =
* Minor bug fix in Oauth for Twitter
* Fixed problem with bit.ly links

= 1.3 =
* Oauth is now available for Twitter servers. For Status.net server that will be available in a later version (hopefully 1.4)
* Optional suffix possible for posts

= 1.1 =
* Added possibility to have a unique prefix for each server when posting blog posts to a Status.net server

= 1.0 =
* The first version

== Upgrade Notice ==

= 1.0 =
* The first version

`<?php code(); // goes in backticks ?>`