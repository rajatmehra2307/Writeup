### Problem Description

This was an interesting challenge that made use of a bug in the code, that allows us to create two files of same name in a zip.
For this challenge, we are given two files ```verify_hash.py``` and ```commands.zip.b64```

```commands.zip.b64``` is a Base64 encoded zip file, on decoding it and extracting the contents we see two files, ```README.md``` and ```command.txt``` that has the text ```echo 'Hello World!'```.
The ```verify_hash.py``` file contains the following code

```
import hashlib
import os
import sys
import zipfile

def get_file(name, archive):
    return [file for file in archive.infolist() if file.filename == name][0]

archive = zipfile.ZipFile(sys.argv[1])
file = get_file("commands/command.txt", archive)
data = archive.read(file)
md5 = hashlib.md5(data).hexdigest()

if md5 == "0e491b13e7ca6060189fd65938b0b5bc":
    archive.extractall()
    os.system("bash commands/command.txt")
    os.system("rm -r commands")
else:
    print("Invalid Command")

```

In order to solve this challenge we need to pass the command ```cat flag.txt``` such that it gets executed and also bypass the MD5 check

### Attack 

On interesting thing to note is that in the code, the ```get_file()``` function iterates through the files in the zip, and picks the first ```command.txt``` for the contents. However, when executing the contents inside ```command.txt```, we first extract it and then execute them. Extracting the zip, keeps the last file in case two files have the same name. 

Using this idea, we can create two files with the same name as ```command.txt```, where the first has the content ```echo 'Hello World!'```, while the second has ```cat flag.txt```. But it's difficult to create two files with same name. So here is what I did, instead of writing the payload for outputting flag.txt in ```command.txt```, a wrote it in a file called ```commanp.txt```. The I did the zipped the two files
```
zip -r command.zip commands/command.txt commands/commanp.txt
```
Then using hexedit, the changed the name of ```commandp.txt``` to ```command.txt```
Then I base64 encoded this zip and sent this as a payload.
And we have our flag :)

```
flag: utflag{https://youtu.be/bZe5J8SVCYQ}
```