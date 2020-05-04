import time
from cannon import Shell, Account

print("Logging into route-views")
conn = Shell('route-views.oregon-ix.net', credentials=(Account('rviews', ''),),
    auto_priv_mode=False, log_file='mylog.txt', log_screen=True, debug=True)
conn.execute('term len 0')
#conn.sync_prompt(require_detect_prompt=False)
conn.execute('show version')
time.sleep(3)

intfs = conn.execute('show ip int brief', template="""Value INTF (\S+)\nValue IPADDR (\S+)\nValue STATUS (up|down|administratively down)\nValue PROTO (up|down)\n\nStart\n  ^${INTF}\s+${IPADDR}\s+\w+\s+\w+\s+${STATUS}\s+${PROTO} -> Record""")
print(intfs)
conn.close()
