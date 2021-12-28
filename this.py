from getpass import getpass, getuser
import sys
import re

from cannon import Account, Shell

"""Test for auth fallback, public-key authorization and linux sudo"""

print("Test logging into linux with ssh...")
# Test password fallback and ssh_key authorization...
username = getuser()
acct01 = Account(username, getpass("Password for %s: " % username), ssh_key='~/.ssh/id_rsa')

conn = Shell('localhost', credentials=(acct01,),
    mode="linux", debug=False, log_screen=True,
    strip_colors=True)

conn.execute('uname -a', timeout=5)

########### sudo ##########################################################
#
index = conn.execute('sudo uname -a', prompts=(r"assword.+?:",))
print("INDEX", index)
conn.execute(passwd)

conn.execute('sudo ls /tmp')
conn.execute('ls')

# FIXME, interact() is broken...
#conn.interact()

conn.execute('whoami', command_timeout=5)
print("WHOAMI RESULT QUOTED '{}'".format(conn.response))
conn.execute('uptime', command_timeout=5)
print("UPTIME '{}'".format(conn.response))
conn.close()

