import os
import urllib.request
from os.path import exists

REMOTE_FILE_URL="https://raw.githubusercontent.com/broemp/windows_setup/master/CSGO/autoexec.cfg"
LOCAL_FILE_PATH="autoexec.cfg"

# Load local File
dirname = os.path.dirname(__file__)
filename = os.path.join(dirname, LOCAL_FILE_PATH)

# Load Remote File
remoteFile = urllib.request.urlopen(REMOTE_FILE_URL)
remoteFileContent= remoteFile.read().decode("utf8")

#Check if file exists
if not exists(filename):
    print("File not found")
    with open(filename, "w") as file:
        file.write(remoteFileContent)
        print("File Updated!")
    exit()

# Load local File
localFile=open(filename, "r")
localFileContent=localFile.read()
localFile.close()

# Compare Files
if(remoteFileContent!=localFileContent):

    print("Unterschiede gefunden!")
    print("Datei wird geupdatet!")

    with open(filename, "w") as file:
        file.write(remoteFileContent)
        print("File Updated!")

else:
    print("Keine Unterschiede gefunden!")