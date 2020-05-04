from getpass import getpass, getuser
import re

from cannon import Account, Shell

"""Test for auth fallback, public-key authorization and linux sudo"""

print("Test logging into linux with ssh...")
# Test password fallback and ssh_key authorization...
acct01 = Account('mpenning', 'badPassword')
acct02 = Account(getuser(), getpass(), ssh_key='~/.ssh/id_rsa')

conn = Shell('localhost', credentials=(acct01, acct02),
    debug=True, log_screen=True)
#conn.execute("export PS1='host>'", command_timeout=1)
#conn.detect_prompt()
#conn.sync_prompt()
conn.execute('ls')
for file in re.split('\s+', conn.response):
    print("FILE "+file)
conn.execute('sudo uname -a')
conn.execute('sudo ls /tmp')
#conn.detect_prompt()
conn.execute('whoami', command_timeout=5)
#conn.interact()   # FIXME, I can't find a way to make interact() stop crashing
print("WHOAMI RESULT QUOTED '{}'".format(conn.response))
conn.execute('uptime', command_timeout=5)
print("UPTIME '{}'".format(conn.response))
conn.close()
