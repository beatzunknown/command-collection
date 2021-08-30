# Open Source Intelligence Techniques

This document will contain notes from Open Source Intelligence Techniques by Michael Bazzell.

## 1. Prepare Your Computer

### Firefox Addons

* Fireshot
* ublock origin
* Https everywhere
* Exifviewer
* Mjsonviewer
* User agent switcher
* Image search options
* Resurrect pages
* Copy all links

### Chrome Extensions

* Prophet
* 360social

### Buscador Tools

* Spiderfoot
* Metadata anonymization toolkit

## 3. Search Engines

### Google Operators

* Quotation marks (`""`) for exact search
* `site:` operator to restrict search to domains
* `filetype:` operator. Note that pirated file types like MP3, MP4, AVI, etc are not indexed for filetype search
* Hyphen(`-`) to remove search terms
* `inurl:` operator to do a search on url. Supports logic like `(stringA|stringB)`
* `intitle:` operator searches the page title
* `allintitle:` operator is same but allows for any permutation of search terms
* `OR` operator
* Asterisk (`*`) operator for wildcard characters
* Range (`..`) operator to search between two identifiers like years or numbers
* `related:` operator collects a domain and provides online content related to it
* Google Cache - in search results you can click the downward arrow next to a result to view its cached version

### Yandex Operators

* Quotations (`""`) for exact match
* Asterisk (`*`) wildcard to represent missing word
* `&` Operator for words in same sentence
* `/Number` (like /2) operator for words within the number of words from each other
* `&&` For words within the same webpage
* `~` operator to exclude word
* `+`Operator to require a word
* `|` Operator to represent OR

### Other Search Tools

* Bing
* Yandex
* Archive.is
* Wayback machine
* Google advanced search
* Google scholar
* Google patents
* Ahmia tor search engine
* Search engine colossus (index of most search engines)
* File mare (FTP content)
* Napalm FTP (recent FTP content)
* IntelTechniques Search Tool

## 4. Social Networks: Facebook

### Creating Covert Accounts

* Email - use smaller providers like GMX. gmx.us is even less common than gmx.com
* Facebook - turn off VPN, Tor, etc and connect to a residential connection. Clear all cache with CCleaner and create an account from [m.facebook.com](m.facebook.com) and provide the GMX address to avoid requiring a cellular number
* Twitter - may need to go off VPN
* Instagram - no resistance
* Yahoo - May be able to bypass cell number verification when using GMX address with an IP not tied to a previous account for 30 days.
* Gmail - Provide the GMX address as alternative form of contact.

## 5. Social Networks: Twitter

* Twitter person search ([twitter.com/#!/who_to_follow]()) - search page for handling real name searches, rather than handle names
* Twitter Directory ([twitter.com/i/directory/profiles]())  - browse through millions of profiles alphabetically
* Followerwonk Bios ([moz.com/followerwonk/bio]()) - filter through searches of users. Eg, narrow by location, number of tweets, etc
* `http://web.archive.org/web/*/twitter.com/<username>` - search profile on Wayback Machine to find deleted tweets
* Twitter Bio Changes ([spoonbill.io]()) - view history of user's Twitter bio
* First Tweet ([http://ctrlq.org/first]()) - view first user that used a trending hashtag or keyword
* First Follower ([socialrank.co/firstfollower]()) - find the first follower of a user
* TweetBeaver ([tweetbeaver.com]()) - export content from an account
  * Convert Name to ID
  * Convert ID to Name
  * Check if 2 accounts follow each other
  * Download a user's favourites
  * Search within a user's favourites
  * Download a user's timeline
  * Search within a user's timeline
  * Get a user's account data - name, ID, Bio, creation date, etc
  * Download a user's friend list or followers list
  * Bulk account data download
* Tweetpaths ([tweetpaths.com]()) - map where (location) a user has sent their tweets from
* MapD: MIT ([http://mapd.csail.mit.edu/tweetmap/]())
* All My Tweets ([allmytweets.net]()) - show all of a user's tweets on one page
* Twitter Archiver ([labnol.org/internet/save-twitter-hashtag-tweets/6505]()) - Based on filters, save records of tweets into a Google Spreadsheet. The addon will also poll for new records every hour and update the spreadsheet until you delete the search.
* Sleeping Time ([sleepingtime.org]()) - tool analyses tweets to determine when a user sleeps. Could be useful to identify timezone
* Twiangulate ([twiangulate.com]()) - identify mutuals between 2 accounts
* Followerwonk ([followerwonk.com]()) - similar to Twiangulate but better and allows 3 way comparisons
* BackTweets ([backtweets.com]()) - identifies twitter posts that included a link to a specific site. Works even when the posts used bit.ly links
* Twitonomy ([twitonomy.com]()) - Overall analytics of user accounts
* TweetTopic ([tweettopicexplorer.neoformix.com]()) - generates word cloud for a user, to show most common words

### Search Operators

* `from:` operator - find messages from a user (not including retweets or promo)
* `to:` operator - find messages to a user
* `geocode:<lat>,<long>,<dist>km` - find tweets posted within a distance of a coordinate. Can specify text to find in quotation marks (`""`) afterwards
* Quotation marks (`""`)  for mandatory search terms
* `OR` for optional search terms
* `since:YYYY-mm-dd` - filter tweets as off a given date
* `until:YYYY-mm-dd` - filter tweet until a given date
* View full resolution images - open image in new tab. Add `:orig` to the end of the URL for highest res image version (likely original)

