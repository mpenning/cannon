import time
from cannon import Shell, Account

print("Logging into route-views")
conn = Shell('route-views.oregon-ix.net', credentials=(Account('rviews', ''),),
    auto_priv_mode=False, log_file='', log_screen=True, debug=False)
conn.execute('term len 0')
#conn.sync_prompt(require_detect_prompt=False)
conn.execute('show interface te0/0/0')
conn.execute('show ip vrf')
conn.execute('show ip bgp summ')
conn.execute('show proc cpu sort')
conn.execute('show inventory')
conn.execute('show users')
conn.execute('ping 4.2.2.2')

for ii in range(0, 3):
    conn.execute('show version')
version = conn.response

intfs = conn.execute('show ip int brief', template="""Value INTF (\S+)\nValue IPADDR (\S+)\nValue STATUS (up|down|administratively down)\nValue PROTO (up|down)\n\nStart\n  ^${INTF}\s+${IPADDR}\s+\w+\s+\w+\s+${STATUS}\s+${PROTO} -> Record""")
print(intfs)
conn.close()

print("-----------------")
print(version)
