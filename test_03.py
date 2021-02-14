from getpass import getpass, getuser
import sys
import re

from cannon import Account, Shell

"""Test for auth fallback, public-key authorization and linux sudo"""

print("Test logging into linux with ssh...")
# Test password fallback and ssh_key authorization...
passwd = getpass("password for mpenning: ")
acct01 = Account('mpenning', 'badPassword')
acct02 = Account(getuser(), passwd, ssh_key='~/.ssh/id_rsa')

conn = Shell('localhost', credentials=(acct02, acct01),
    mode="linux", debug=True, log_screen=True,
    log_file="mylog.txt", strip_colors=True)

conn.execute('pwd', timeout=5)

########### sudo ##########################################################
# FIXME - the script works using execute("sudo cmd", prompts=("assword:"))
#    and then execute(passwd).  However, better checking of index is
#    desired in case of failed password handling...  we could decide based
#    on `index`
index = conn.execute('sudo uname -a', prompts=(r"assword.+?:",))
print("INDEX", index)
conn.execute(passwd)  # Send the password to the password prompt

conn.execute('sudo ls /tmp')
conn.execute('ls')

#conn.detect_prompt()
conn.execute('whoami', command_timeout=5)

#conn.interact()   # FIXME, I can't find a way to make interact() stop crashing

print("WHOAMI RESULT QUOTED '{}'".format(conn.response))
conn.execute('uptime', command_timeout=5)
print("UPTIME '{}'".format(conn.response))
conn.close()
