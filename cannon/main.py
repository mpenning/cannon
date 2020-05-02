from contextlib import closing
from io import StringIO
import platform
import socket
import time
import sys
import re
import os
assert sys.version_info>=(3,0,0), "cannon does not support Python 2"

from rich import print as rich_print
from textfsm import TextFSM
import pexpect as px
import transitions

"""Can't trigger event _go_LOGIN_SUCCESS_UNPRIV from state SEND_LOGIN_PASSWORD!"""

class UnexpectedPrompt(Exception):
    """Exception for an Unexpected Prompt"""
    def __init__(self):
        super(UnexpectedPrompt, self)

class PromptDetectionError(Exception):
    """Exception for an Unexpected Prompt"""
    def __init__(self):
        super(PromptDetectionError, self)

class TeeStdoutFile(object):
    """Simple class to send stdout to screen and log_file simultaneously"""
    def __init__(self, log_file="", filemode="w", log_screen=False):
        self.log_file = os.path.expanduser(log_file)
        self.filemode = filemode
        self.log_screen = log_screen
        self.stdout = sys.stdout

        try:
            assert os.path.isfile(self.log_file) is False
        except AssertionError:
            raise ValueError("Cannot overwrite existing log_file={}".format(
                self.log_file))
            sys.exit(1)

        self.fh = open(self.log_file, self.filemode)

    def __del__(self):
        sys.stdout = self.stdout
        try:
            self.fh.close()
        except AttributeError:
            # We hit this if self.fh was never opened such as existing log_file
            pass

    def write(self, line):
        self.fh.write(line)
        self.stdout.write(line)

    def flush(self):
        self.fh.flush()

    def close(self):
        self.fh.close()


class Account(object):
    def __init__(self, user, passwd="", priv_passwd="", ssh_key=""):
        self.user = user
        self.passwd = passwd
        self.priv_passwd = priv_passwd
        self.ssh_key = os.path.expanduser(ssh_key) # Path to ssh private key

    def __repr__(self):
        return """<Account user:{} passwd:{} priv_passwd:{} ssh_key: {}>""".format(self.user, self.passwd, self.priv_passwd, self.ssh_key)

class Shell(transitions.Machine):
    def __init__(self, host='', credentials=(), 
        ssh_keepalive=60, protocols=({'proto': 'ssh', 'port': 22},
        {'proto': 'telnet', 'port': 23}), auto_priv_mode=True,
        log_screen=False, log_file='', debug=False, command_timeout=30,
        login_timeout=10, relogin_delay=120, encoding='utf-8',
        login_attempts=3):

        STATES = ('INIT_SESSION', 'SELECT_PROTOCOL', 
            'SELECT_LOGIN_CREDENTIALS', 'SEND_LOGIN_USERNAME', 
            'SEND_LOGIN_PASSWORD', 'CONNECT', 
            'LOGIN_SUCCESS_UNPRIV', 'LOGIN_SUCCESS_PRIV',
            'LOGIN_TIMEOUT', 'SEND_PRIV_PASSWORD', 
            'INTERACT', 'CLOSE_SESSION')
        super(Shell, self).__init__(states=STATES, initial='INIT_SESSION')

        self.host = host
        self.credentials = credentials
        self.protocols = protocols
        self.auto_priv_mode = auto_priv_mode
        self.log_screen = log_screen
        self.log_file = os.path.expanduser(log_file)
        self.debug = debug
        self.command_timeout = command_timeout
        self.login_timeout = login_timeout
        self.relogin_delay = relogin_delay
        self.encoding = encoding
        self.login_attempts = login_attempts

        self.child = None   # Pexpect's child object
        self.username = None
        self.password = None
        self.ssh_key = ""
        self.ssh_keepalive = int(ssh_keepalive)
        self.credentials_iterator = self.iter_credentials()
        self.proto_dict = {}

        self.prompt_str = ""    # This gets set in self.sync_prompt()
        # Detect a typical linux CLI prompt...
        #self.linux_prompt_capture = '([^\r\n{0}]+)\s*$'.format(re.escape('$'))
        self.linux_prompt_capture = '[\r\n]*[^\r\n{0}]+\s*$'.format(re.escape('$'))
        # Build the template before detecting prompt
        self.base_prompt_regex = self.build_prompt_regex()

        # Define regex capture groups for the prompts above...
        # NOTE there are no prompts in these strings..
        self.base_prompt_regex_capture = [':', ':', 
            '(\S[^\n\r>]+?)\s*$', self.linux_prompt_capture, 
            '(\S[^\n\r{0}]+?)\s*$'.format(re.escape('#'))]

        self.matching_prompt_regex = ""
        self.matching_prompt_regex_index = -1

        #######################################################################
        ## Transitions to SELECT_PROTOCOL state
        #######################################################################
        self.add_transition(trigger='_go_SELECT_PROTOCOL', 
            source='INIT_SESSION', dest='SELECT_PROTOCOL',
            after='after_SELECT_PROTOCOL_cb')

        #######################################################################
        ## Transitions to SELECT_LOGIN_CREDENTIALS state
        #######################################################################
        self.add_transition(trigger='_go_SELECT_LOGIN_CREDENTIALS', 
            source='SELECT_PROTOCOL', dest='SELECT_LOGIN_CREDENTIALS',
                after='after_SELECT_LOGIN_CREDENTIALS_cb')

        self.add_transition(trigger='_go_SELECT_LOGIN_CREDENTIALS', 
            source='SEND_LOGIN_PASSWORD', dest='SELECT_LOGIN_CREDENTIALS',
                after='after_SELECT_LOGIN_CREDENTIALS_cb')

        #######################################################################
        ## Transitions to CONNECT state
        #######################################################################
        self.add_transition(trigger='_go_CONNECT', 
            source='CONNECT', dest='CONNECT',
            after='after_CONNECT_cb')

        self.add_transition(trigger='_go_CONNECT', 
            source='SELECT_LOGIN_CREDENTIALS', dest='CONNECT',
            after='after_CONNECT_cb')

        #######################################################################
        ## Transitions to SEND_LOGIN_PASSWORD state
        #######################################################################
        self.add_transition(trigger='_go_SEND_LOGIN_USERNAME', 
            source='CONNECT', dest='SEND_LOGIN_USERNAME',
            after='after_SEND_LOGIN_USERNAME_cb')

        # In case we got to interact prematurely...
        self.add_transition(trigger='_go_SEND_LOGIN_USERNAME', 
            source='INTERACT', dest='SEND_LOGIN_USERNAME',
            after='after_SEND_LOGIN_USERNAME_cb')

        #######################################################################
        ## Transitions to SEND_LOGIN_PASSWORD state
        #######################################################################
        self.add_transition(trigger='_go_SEND_LOGIN_PASSWORD', 
            source='CONNECT', dest='SEND_LOGIN_PASSWORD',
            after='after_SEND_LOGIN_PASSWORD_cb')

        # In case we got to interact prematurely...
        self.add_transition(trigger='_go_SEND_LOGIN_PASSWORD', 
            source='INTERACT', dest='SEND_LOGIN_PASSWORD',
            after='after_SEND_LOGIN_PASSWORD_cb')

        #######################################################################
        ## Transitions to LOGIN_SUCCESS_UNPRIV state
        #######################################################################
        self.add_transition(trigger='_go_LOGIN_SUCCESS_UNPRIV', 
            source='SEND_LOGIN_USERNAME', dest='LOGIN_SUCCESS_UNPRIV',
            after='after_LOGIN_SUCCESS_UNPRIV_cb')

        self.add_transition(trigger='_go_LOGIN_SUCCESS_UNPRIV', 
            source='SEND_LOGIN_PASSWORD', dest='LOGIN_SUCCESS_UNPRIV',
            after='after_LOGIN_SUCCESS_UNPRIV_cb')

        self.add_transition(trigger='_go_LOGIN_SUCCESS_UNPRIV', 
            source='CONNECT', dest='LOGIN_SUCCESS_UNPRIV',
            after='after_LOGIN_SUCCESS_UNPRIV_cb')

        #######################################################################
        ## Transitions to SEND_PRIV_PASSWORD state
        #######################################################################
        self.add_transition(trigger='_go_LOGIN_SUCCESS_UNPRIV', 
            source='LOGIN_SUCCESS_UNPRIV', dest='SEND_PRIV_PASSWORD',
            after='after_SEND_PRIV_PASSWORD_cb')

        #######################################################################
        ## Transitions to LOGIN_SUCCESS_PRIV state
        #######################################################################
        self.add_transition(trigger='_go_LOGIN_SUCCESS_PRIV', 
            source='CONNECT', dest='LOGIN_SUCCESS_PRIV',
            after='after_LOGIN_SUCCESS_PRIV_cb')

        self.add_transition(trigger='_go_LOGIN_SUCCESS_PRIV', 
            source='SEND_LOGIN_PASSWORD', dest='LOGIN_SUCCESS_PRIV',
            after='after_LOGIN_SUCCESS_PRIV_cb')

        #######################################################################
        ## Transitions to INTERACT state
        #######################################################################
        self.add_transition(trigger='_go_INTERACT', 
            source='LOGIN_SUCCESS_UNPRIV', dest='INTERACT',
            after='after_INTERACT_cb')

        self.add_transition(trigger='_go_INTERACT', 
            source='LOGIN_SUCCESS_PRIV', dest='INTERACT',
            after='after_INTERACT_cb')

        self.add_transition(trigger='_go_INTERACT', 
            source='INTERACT', dest='INTERACT',
            after='after_INTERACT_cb')

        #######################################################################
        ## Unconditionally transition to the SELECT_PROTOCOL state
        #######################################################################
        self._go_SELECT_PROTOCOL()

    def execute(self, cmd=None, template=None, prompts=(),
        command_timeout=0.0, carriage_return=True):
        """Run a command and optionally parse with a TextFSM template

            - `cmd` is the command to execute
            - `template` is a string with the text of the TextFSM template
            - `prompts` is a tuple of prompt regexs to apply to the output of the command
            - `command_timeout` is how long we should wait for the command prompt to return
            - `carriage_return` indicates whether the command should be followed with a carriage-return.  The values are either True or False (default is True, meaning the CR will be sent after the command).

        execute() returns a list of dicts if `template` is specified; otherwise
        it returns None.
        """
        assert cmd is not None

        if command_timeout==0.0:
            command_timeout = self.command_timeout

        arg_list = ('cmd', 'template', 'prompts', 'command_timeout',
            'carriage_return')
        arg = list()
        if self.debug:
            # build the debugging string...
            for ii in arg_list:
                if ii=='cmd':
                    arg.append("'"+cmd+"'")
                elif ii=='template' and template is not None:
                    arg.append('template=TRUNCATED'.format(template))
                elif ii=='template' and template is None:
                    arg.append('template=None')
                elif ii=='prompts':
                    arg.append('prompts={}'.format(prompts))
                elif ii=='command_timeout':
                    arg.append('command_timeout={}'.format(command_timeout))
                elif ii=='carriage_return':
                    arg.append('carriage_return={}'.format(carriage_return))
            logstr = ', '.join(arg)
            rich_print('[bold blue]execute([/bold blue][bold green]{}[/bold green][bold blue])[/bold blue]'.format(logstr))

        if carriage_return:
            self.csendline(cmd)
        else:
            self.child.send(cmd)

        # Extend the list of cli_prompts if `prompts` was specified
        cli_prompts = self.base_prompt_regex
        # Ensure we match sudo first... this regex is tricky to get right...
        cli_prompts.insert(0, '[Pp]assword[^\r\n]{0,20}?:')
        if prompts!=():
            assert isinstance(prompts, tuple)
            cli_prompts.extend(prompts)  # Add command-specific prompts here...

        # Look for prompt matches after executing the command
        index = self.cexpect(cli_prompts, timeout=command_timeout)

        # Handle sudo password prompt...
        if index==0:  # a password prompt
            if self.debug:
                rich_print("    [bold blue]Responding to password prompt:[/bold blue] [bold yellow]'{}'[/bold yellow]".format(
                    self.child.after.splitlines()[-1]))
            assert self.password!="", "Hit a password prompt without a password"
            self.csendline(self.password)
            index = self.cexpect(cli_prompts, timeout=command_timeout)


        ## If template is specified, parse the response into a list of dicts...
        if template is not None:
            if os.path.isfile(str(template)):
                # open the textfsm template from disk...
                fh = open(template, 'r')
            else:
                # build a fake filehandle around textfsm template string
                fh = StringIO(template)
            fsm = TextFSM(fh)
            header = fsm.header
            values = fsm.ParseText(self.response)
            assert values != [], "Could not match any values with the template."

            ## Pack the extracted values into a list of dicts, using keys from
            ##   the header file
            retval = list()

            # Values is a nested list of captured information
            for ii in (values, values[0]):
                if not isinstance(ii, list):
                    continue
                for row in ii:
                    try:
                        # Require the row to be a list
                        assert isinstance(row, list)
                        # Require row to be exactly as long as the header list
                        assert len(row)==len(header)
                        row_dict = {}
                        for idx, value in enumerate(row):
                            row_dict[header[idx]] = value
                        retval.append(row_dict)
                    except AssertionError:
                        break
                if len(retval)>0:
                    return retval
        else:
            return None

    def csendline(self, text):
        assert self.child.isalive()
        if self.debug:
            rich_print("    [bold blue]csendline('{}')[/bold blue]".format(
                text))
            rich_print("    [bold blue]---------[/bold blue]")
        self.child.sendline(text)

    def cexpect(self, pattern_list, timeout=-1):
        assert self.child.isalive()
        if self.debug:
            rich_print("    [bold blue]cexpect([/bold blue][bold green]pattern_list, timeout={}[/bold green][bold blue])[/bold blue]".format(timeout))
        now = time.time()
        try:
            match_index = self.child.expect(pattern_list, timeout=timeout)
            if self.debug:
                delta_secs = round(time.time()-now, 4)
                rich_print("\n      [bold blue]^^ cexpect() matched pattern_list index={}[/bold blue]".format(match_index))
                rich_print("\n      [bold blue]^^ cexpect() matched regex={}[/bold blue]".format(repr(pattern_list[match_index])))
                rich_print("      [bold blue]^^ cexpect() matching_prompt='{}'[/bold blue]".format(self.matching_prompt))
                rich_print("      [bold blue]^^ cexpect() match time: {} seconds[/bold blue]".format(delta_secs))

            self.matching_prompt_regex_index = match_index
            self.matching_prompt_regex = pattern_list[match_index]

        except px.exceptions.EOF:
            if self.debug:
                rich_print("      [bold red]EOF exception[/bold red]")
            match_index = -1

        except px.exceptions.TIMEOUT:
            if self.debug:
                rich_print("      [bold red]TIMEOUT exception[/bold red]")
            match_index = -1

        return match_index

    @property
    def matching_prompt(self):
        """Derive the matching prompt string (what matched the regex)"""
        after = self.child.after
        prompt_str = after.splitlines()[-1]
        if self.debug:
            rich_print("[bold blue]matching_prompt(): '{}'[/bold blue]".format(prompt_str))
        return prompt_str

    @property
    def response(self):
        return self.child.before

    def exit(self):
        self.child.close()

    def close(self):
        self.exit()

    def quit(self):
        self.exit()

    def iter_protocols(self):
        for proto_dict in self.protocols:
            yield proto_dict

    def iter_credentials(self):
        for cred in self.credentials:
            if self.debug:
                rich_print("    [bold blue]Select credentials:[/bold blue]")
                rich_print("        [bold yellow]{}[/bold yellow]".format(
                    repr(cred)))
            yield cred

    def sync_prompt(self):
        """Catch up with any queued prompts, we know to exit if we get a px.exceptions.TIMEOUT error"""
        if self.debug:
            rich_print("[bold blue]Entering sync_prompt()[/bold blue]")

        # self.detect_prompt() **must** come before self.sync_prompt()
        try:
            assert self.prompt_str!=""
        except AssertionError:
            raise PromptDetectionError("detect_prompt() must run before sync_prompt()")

        self.csendline('')

        finished = False
        while not finished:
            # Use a very short timeout here...
            index = self.cexpect(self.base_prompt_regex, timeout=1)

            if index==-1:
                # We got an EOF or TIMEOUT error...
                self.login_attempts = 0
                finished = True

            elif (index==0 or index==1):
                raise Exception("Unexpected prompt in sync_prompt()")

            elif index==2:
                # We should only get to this prompt if auto_priv_mode is 
                #     False
                assert self.auto_priv_mode is False
                self.login_attempts = 0
            elif index==3:
                # We should only get to this prompt if auto_priv_mode is 
                #     False
                assert self.auto_priv_mode is False
                self.login_attempts = 0
            elif index==4:
                # We don't need to attempt any more logins if we have 
                #     a priv prompt
                self.login_attempts = 0

    def detect_prompt(self):
        """detect_prompt() checks for premature entry into INTERACT and also looks for a prompt string"""
        # Detect the prompt as best-possible...
        if self.debug:
            rich_print("[bold blue]Entering detect_prompt()[/bold blue]")

        abbv_prompt_list = ['sername:', 'assword:', '>', re.escape('$'), 
            re.escape('#')]

        # Double check that this isn't a pre-login banner...
        finished = False
        while not finished:
            # Use a very short timeout here...
            index = self.cexpect(abbv_prompt_list, timeout=1)
            if index==-1:
                if self.debug:
                    rich_print("[bold blue]    detect_prompt() TIMEOUT condition 1[/bold blue]")
                finished = True
            elif index==0:
                # We probably went to detect_prompt() based on some banner
                # This should be a username prompt...
                if self.debug:
                    rich_print("[bold blue]    detect_prompt() found a premature entry into detect_prompt().  Redirecting to state SEND_LOGIN_USERNAME[/bold blue]")
                self._go_SEND_LOGIN_USERNAME()
            elif index==1:
                # We probably went to detect_prompt() based on some banner
                # This should be a password prompt...
                if self.debug:
                    rich_print("[bold blue]    detect_prompt() found a premature entry into detect_prompt().  Redirecting to state SEND_LOGIN_PASSWORD[/bold blue]")
                self._go_SEND_LOGIN_PASSWORD()

            ## FIXME I might have to delete this case... probably breaks junos
            ## with a login banner (using hash characters)

            ## GUACAMOLE
            #elif index>1:
            #    finished = True

        if self.debug:
            rich_print("\n    [bold blue]detect_prompt() using prompt detection heuristics[/bold blue]")
        self.csendline('')
        # Use a very short timeout here
        index = self.cexpect(abbv_prompt_list, timeout=1)
        self.prompt_str = self.child.before.strip().splitlines()[-1]
        if self.debug:
            rich_print("\n    [bold blue]detect_prompt() found prompt_str:[/bold blue] '{}'".format(self.prompt_str))

        self.build_prompt_regex()  # Adjust the prompt regex after detection

        return self.prompt_str

    def build_prompt_regex(self):
        """Assign self.base_prompt_regex with the latest prompt info"""
        if self.debug:
            rich_print("[bold blue]build_prompt_regex() called[/bold blue]")
            rich_print("    [bold blue]self.prompt_str='{}'[/bold blue]".format(
                self.prompt_str))

        self.linux_prompt = '[\n\r]+{0}[^{1}]*?{1}\s*'.format(re.escape(
            self.prompt_str), re.escape('$'))

        self.base_prompt_regex = ['assword:', 'sername:', 
            #r'[\n\r]+{}[^\n\r>]*?>\s*'.format(self.prompt_str), 
            '[\n\r]+{0}.*?>\s*'.format(re.escape(self.prompt_str)),
            #linux_prompt, r'[\n\r]+{0}[^\n\r#]*?{1}\s*'.format(
            self.linux_prompt, '[\n\r]+{0}.*?{1}\s*'.format(
            re.escape(self.prompt_str), re.escape('#'))]

        return self.base_prompt_regex

    def after_SELECT_PROTOCOL_cb(self):
        """Attempt to make a raw TCP connection to the protocol's TCP port"""

        if self.debug:
            rich_print("[bold blue]Entering state: [/bold blue][bold magenta]{}[/bold magenta]".format(
                self.state))

        finished = False
        for ii in range(0, 3):

            if finished:
                continue

            for proto_dict in self.iter_protocols():
                self.proto_dict = proto_dict
                proto_name, proto_port = proto_dict.get('proto'), proto_dict.get('port')
                if self.debug:
                    rich_print("    [bold blue]Trying TCP socket to {} port {}[/bold blue]".format(self.host, proto_port))
                with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as proto_sock:
                    proto_sock.settimeout(3)
                    try:
                        if proto_sock.connect_ex((self.host, proto_port))==0:
                            ## We completed a tcp connection to proto_port...
                            ##   now, get the credentials
                            if self.debug:
                                rich_print("    [bold blue]SUCCESS: port {}[/bold blue]".format(proto_port))
                            finished = True
                            break
                    except socket.gaierror:
                        raise Exception("'{}' is an unknown hostname".format(self.host))
                if ((ii==0) or (ii==1)) and (finished is False):
                   
                    time.sleep(self.relogin_delay)  # Give the host time to recover from auto-login

        if (finished is False):
            raise Exception("Cannot connect to host: '{}'".format(self.host))
        else:
            self._go_SELECT_LOGIN_CREDENTIALS()  # Get the proper credentials

    def after_SELECT_LOGIN_CREDENTIALS_cb(self):

        if self.debug:
            rich_print("[bold blue]Entering state: [/bold blue][bold magenta]{}[/bold magenta]".format(
                self.state))

        while self.login_attempts>=0:
            cred = next(self.credentials_iterator)
            self.username = cred.user
            self.password = cred.passwd
            self.ssh_key = cred.ssh_key

            if self.child is not None:
                self.child.close()      # Make way for a fresh child instance

            self._go_CONNECT()

            self.login_attempts -= 1

    def after_CONNECT_cb(self):
        """Build an ssh / telnet session to self.host"""

        if self.debug:
            rich_print("[bold blue]Entering state: [/bold blue][bold magenta]{}[/bold magenta]".format(
                self.state))

        if self.child is not None:
            self.child.close()

        # Implement ssh or telnet command...
        if self.proto_dict['proto']=='ssh' and self.ssh_key!="":
            cmd = 'ssh -l {} -p {} -i {} -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no -o ServerAliveInterval={} {}'.format(self.username, self.proto_dict['port'], self.ssh_key, self.ssh_keepalive, self.host)

        elif self.proto_dict['proto']=='ssh' and self.ssh_key=="":
            # https://serverfault.com/a/1002182/78702
            cmd = 'ssh -l {} -p {} -o PubkeyAuthentication=no -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no -o ServerAliveInterval={} {}'.format(self.username, self.proto_dict['port'], self.ssh_keepalive, self.host)

        elif self.proto_dict['proto']=='telnet':
            cmd = 'telnet {} {}'.format(self.host, self.proto_dict['port'])

        # run the ssh or telnet command
        try:
            if self.debug:
                rich_print("  [bold blue]pexpect.spawn([/bold blue]'{}'[bold blue])[/bold blue]".format(cmd))
            self.child = px.spawn(cmd, timeout=self.login_timeout,
                encoding=self.encoding)

            # https://pexpect.readthedocs.io/en/stable/commonissues.html
            #self.child.delaybeforesend = None

        except px.exceptions.EOF:
            time.sleep(70)


        # log to screen if requested
        if self.log_screen and self.log_file=="":
             self.child.logfile = sys.stdout

        # log to file if requested
        elif (self.log_screen is False) and self.log_file!="":
            self.child.logfile = open(self.log_file, 'w')

        # log to both screen and file if requested
        elif (self.log_screen is True) and self.log_file!="":
            self.child.logfile = TeeStdoutFile(log_file=self.log_file,
            log_screen=self.log_screen)

        index = self.cexpect(self.base_prompt_regex, 
            timeout=self.login_timeout)

        if self.debug:
            rich_print("   [bold blue]after_CONNECT_cb() - self.child.expect() matched prompt index:[/bold blue] {}".format(index))

        if index==-1:
            time.sleep(70)
            self._go_CONNECT()
        elif index==0:
            self._go_SEND_LOGIN_PASSWORD()
        elif index==1:
            self._go_SEND_LOGIN_USERNAME()
        elif index==2:
            self._go_LOGIN_SUCCESS_UNPRIV()
        elif index==3:
            self._go_LOGIN_SUCCESS_UNPRIV()
        elif index==4:
            self._go_LOGIN_SUCCESS_PRIV()

    def after_SEND_LOGIN_PASSWORD_cb(self):

        if self.debug:
            rich_print("[bold blue]Entering state: [/bold blue][bold magenta]{}[/bold magenta]".format(
                self.state))

        self.csendline(self.password)

        try:
            index = self.cexpect(self.base_prompt_regex,
                timeout=self.login_timeout)

            if self.debug:
                rich_print("\n   [bold blue]after_SEND_LOGIN_PASSWORD_cb() - self.child.expect() matched prompt index:[/bold blue] {}".format(index))

            if index==0:  # This was the wrong password
                self.child.close()
                self._go_SELECT_LOGIN_CREDENTIALS()  # Restart login with different creds
            elif index==1:  # Strange event... should not see username entry here...
                raise UnexpectedPrompt(
                    # FIXME
                    "UnexpectedPrompt: '{}' - after_SEND_LOGIN_PASSWORD_cb".format(""
                    ))
            elif index==2:
                self._go_LOGIN_SUCCESS_UNPRIV()  # We got an unpriv prompt here
            elif index==3:
                self._go_LOGIN_SUCCESS_UNPRIV()  # We got an unpriv prompt here
            elif index==4:
                self._go_LOGIN_SUCCESS_PRIV()  # We got a priv prompt

        except px.exceptions.EOF:
            if self.debug:
                rich_print("   [bold red]after_SEND_LOGIN_PASSWORD_cb() - pexpect.exceptions.EOF error[/bold red]")
            self.child.close()
            self._go_SELECT_LOGIN_CREDENTIALS()  # Restart login with different creds

        except px.exceptions.TIMEOUT:
            if self.debug:
                rich_print("   [bold red]after_SEND_LOGIN_PASSWORD_cb() - pexpect error: TIMEOUT[/bold red]")
            self.child.close()
            self._go_SELECT_LOGIN_CREDENTIALS()  # Restart login with different creds

    def after_SEND_LOGIN_USERNAME_cb(self):

        if self.debug:
            rich_print("[bold blue]Entering state: [/bold blue][bold magenta]{}[/bold magenta]".format(
                self.state))

        self.csendline(self.username)

        index = self.cexpect(self.base_prompt_regex,
            timeout=self.login_timeout)

        if self.debug:
            rich_print("   [bold blue]after_SEND_LOGIN_USERNAME_cb() - self.child.expect() matched prompt index:[/bold blue] {}".format(index))

        if index==0:
            self._go_SEND_LOGIN_PASSWORD()
        elif index==1:
            self._go_SELECT_LOGIN_CREDENTIALS()
        elif index==2:
            self._go_LOGIN_SUCCESS_UNPRIV()  # We got an unpriv prompt here
        elif index==3:
            self._go_LOGIN_SUCCESS_UNPRIV()  # We got an unpriv prompt here
        elif index==4:
            self._go_LOGIN_SUCCESS_PRIV()    # We got a priv prompt here

    def after_LOGIN_SUCCESS_UNPRIV_cb(self):

        if self.debug:
            rich_print("[bold blue]Entering state: [/bold blue][bold magenta]{}[/bold magenta]".format(
                self.state))

        if self.auto_priv_mode is True:
            self.csendline('enable')

            index = self.child.expect(self.base_prompt_regex,
                timeout=self.command_timeout)

            if self.debug:
                rich_print("   [bold blue]after_LOGIN_SUCCESS_UNPRIV_cb() - self.child.expect() matched prompt index:[/bold blue] {}".format(index))

            if index==0:
                self._go_SEND_PRIV_PASSWORD()
            elif index==1:
                raise Exception("Unexpected prompt: 'name:'")
            elif index==2:
                raise Exception("Unexpected prompt: '>'")
            elif index==3:
                raise Exception("Unexpected prompt: '$'")
            elif index==4:
                self._go_LOGIN_SUCCESS_PRIV()    # We got a priv prompt here

        self._go_INTERACT()

    def after_SEND_PRIV_PASSWORD_cb(self):

        if self.debug:
            rich_print("[bold blue]Entering state: [/bold blue][bold magenta]{}[/bold magenta]".format(
                self.state))

        self.csendline(self.password)

        index = self.cexpect(self.base_prompt_regex,
            timeout=self.command_timeout)

        if self.debug:
            rich_print("   [bold blue]after_SEND_PRIV_PASSWORD_cb() - self.child.expect() matched prompt index:[/bold blue] {}".format(index))

        if index==0:
            self._go_SEND_PRIV_PASSWORD()
        elif index==1:
            raise Exception("Unexpected prompt: 'name:'")
        elif index==2:
            raise Exception("Unexpected prompt: '>'")
        elif index==3:
            raise Exception("Unexpected prompt: '$'")
        elif index==4:
            self._go_LOGIN_SUCCESS_PRIV()    # We got a priv prompt here

    def after_LOGIN_SUCCESS_PRIV_cb(self):

        if self.debug:
            rich_print("[bold blue]Entering state: [/bold blue][bold magenta]{}[/bold magenta]".format(
                self.state))

        self._go_INTERACT()

    def after_INTERACT_cb(self):
        """Catch up on any queued command prompts and prepare for user to interact"""

        if self.debug:
            rich_print("[bold blue]Entering state: [/bold blue][bold magenta]{}[/bold magenta]".format(
                self.state))

        self.detect_prompt()  # detect_prompt() *must* come before sync_prompt()
        self.sync_prompt()


if __name__=='__main__':
    sess = Shell(
        host='route-views.oregon-ix.net',
        credentials=(
            Account(user='rviews', passwd=''),
        ),

        log_screen=False,
        auto_priv_mode=False,
        debug=True,
        )
    sess.execute('term len 0')
    values = sess.execute('show ip int brief', 
        template="""Value INTF (\S+)\nValue IPADDR (\S+)\nValue STATUS (up|down|administratively down)\nValue PROTO (up|down)\n\nStart\n  ^${INTF}\s+${IPADDR}\s+\w+\s+\w+\s+${STATUS}\s+${PROTO} -> Record""")
    print("VALUES "+str(values))
    sess.close()
