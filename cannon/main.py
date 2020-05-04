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
import snoop

"""Can't trigger event _go_LOGIN_SUCCESS_UNPRIV from state SEND_LOGIN_PASSWORD!"""

class UnexpectedPrompt(Exception):
    """Exception for an Unexpected Prompt"""
    def __init__(self, error=""):
        super(UnexpectedPrompt, self).__init__(error)

class PromptDetectionError(Exception):
    """Exception for an Unexpected Prompt"""
    def __init__(self, error=""):
        super(PromptDetectionError, self).__init__(error)

# DO NOT escape '$' here
EXPECTED_LAST_PROMPT_CHARS = (':', '>', '#', '$')

class TeeStdoutFile(object):
    """Simple class to send stdout to screen and log_file simultaneously"""
    def __init__(self, log_file="", filemode="w", log_screen=False,
        encoding='utf-8'):
        self.log_file = os.path.expanduser(log_file)
        self.filemode = filemode
        self.log_screen = log_screen
        self.stdout = sys.stdout
        self.encoding = encoding

        try:
            assert os.path.isfile(self.log_file) is False
        except AssertionError:
            raise ValueError("Cannot overwrite existing log_file={}".format(
                self.log_file))
            sys.exit(1)

        self.fh = open(self.log_file, self.filemode, encoding=self.encoding)

    def __del__(self):
        sys.stdout = self.stdout
        try:
            self.fh.close()
        except AttributeError:
            # We hit this if self.fh was never opened such as existing log_file
            pass

    def write(self, line):
        for ii in line:
            if isinstance(ii, bytes):
                self.fh.write(ii.decode(self.encoding))
                self.stdout.write(ii.decode(self.encoding))
            elif isinstance(ii, str):
                self.fh.write(ii)
                self.stdout.write(ii)

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
        {'proto': 'telnet', 'port': 23}), auto_priv_mode=None,
        log_screen=False, log_file='', debug=False, command_timeout=30,
        login_timeout=10, relogin_delay=120, encoding='utf-8',
        login_attempts=3):

        STATES = ('INIT_SESSION', 'SELECT_PROTOCOL', 
            'SELECT_LOGIN_CREDENTIALS', 'SEND_LOGIN_USERNAME', 
            'SEND_LOGIN_PASSWORD', 'CONNECT', 
            'LOGIN_SUCCESS_UNPRIV', 'LOGIN_SUCCESS_PRIV',
            'LOGIN_TIMEOUT', 'SEND_PRIV_PASSWORD', 
            'LOGIN_COMPLETE', 'INTERACT', 'CLOSE_SESSION')
        super(Shell, self).__init__(states=STATES, initial='INIT_SESSION')

        self.host = host
        self.credentials = credentials
        self.protocols = protocols
        self.auto_priv_mode = auto_priv_mode
        if auto_priv_mode is not None:
            rich_print("[bold red]WARNING: auto_priv_mode will be deprecated.  Please stop using this option.[/bold red]")
            time.sleep(2.5)
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
        self.linux_prompt_capture = '[\r\n]*[^\r\n{0}]+\s*{0}'.format(re.escape('$'))
        # Build the template before detecting prompt
        self.base_prompt_regex = self.build_base_prompt_regex()

        # Define regex capture groups for the prompts above...
        # NOTE there are no prompts in these strings..
        self.base_prompt_regex_capture = [':', ':', 
            '(\S[^\n\r>]+?)\s*$', self.linux_prompt_capture, 
            '(\S[^\n\r{0}]+?)\s*$'.format(re.escape('#'))]
            #'(\S[^\n\r>]+?)\s*>', self.linux_prompt_capture, 
            #'(\S[^\n\r{0}]+?)\s*{0}'.format(re.escape('#'))]

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

        self.add_transition(trigger='_go_SELECT_LOGIN_CREDENTIALS', 
            source='LOGIN_COMPLETE', dest='SELECT_LOGIN_CREDENTIALS',
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
        ## Transitions to SEND_LOGIN_USERNAME state
        #######################################################################
        self.add_transition(trigger='_go_SEND_LOGIN_USERNAME', 
            source='CONNECT', dest='SEND_LOGIN_USERNAME',
            after='after_SEND_LOGIN_USERNAME_cb')

        # In case we got to LOGIN_COMPLETE prematurely...
        self.add_transition(trigger='_go_SEND_LOGIN_USERNAME', 
            source='LOGIN_COMPLETE', dest='SEND_LOGIN_USERNAME',
            after='after_SEND_LOGIN_USERNAME_cb')

        #######################################################################
        ## Transitions to SEND_LOGIN_PASSWORD state
        #######################################################################
        self.add_transition(trigger='_go_SEND_LOGIN_PASSWORD', 
            source='CONNECT', dest='SEND_LOGIN_PASSWORD',
            after='after_SEND_LOGIN_PASSWORD_cb')

        self.add_transition(trigger='_go_SEND_LOGIN_PASSWORD', 
            source='SEND_LOGIN_USERNAME', dest='SEND_LOGIN_PASSWORD',
            after='after_SEND_LOGIN_PASSWORD_cb')

        # In case we got to LOGIN_COMPLETE prematurely...
        self.add_transition(trigger='_go_SEND_LOGIN_PASSWORD', 
            source='LOGIN_COMPLETE', dest='SEND_LOGIN_PASSWORD',
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
        ## Transitions to LOGIN_COMPLETE state
        #######################################################################
        self.add_transition(trigger='_go_LOGIN_COMPLETE', 
            source='LOGIN_SUCCESS_UNPRIV', dest='LOGIN_COMPLETE',
            after='after_LOGIN_COMPLETE_cb')

        self.add_transition(trigger='_go_LOGIN_COMPLETE', 
            source='LOGIN_SUCCESS_PRIV', dest='LOGIN_COMPLETE',
            after='after_LOGIN_COMPLETE_cb')

        self.add_transition(trigger='_go_LOGIN_COMPLETE', 
            source='LOGIN_COMPLETE', dest='LOGIN_COMPLETE',
            after='after_LOGIN_COMPLETE_cb')

        #######################################################################
        ## Transitions to INTERACT state
        #######################################################################
        self.add_transition(trigger='_go_INTERACT', 
            source='LOGIN_COMPLETE', dest='INTERACT',
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
        assert self.child.isalive()  # Don't issue commands against a dead conn

        if self.debug:
            rich_print("[bold blue]execute() called[/bold blue]")

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
        # FIXME
        #cli_prompts = self.base_prompt_regex
        cli_prompts = self.build_base_prompt_regex()

        if prompts!=():
            assert isinstance(prompts, tuple)
            cli_prompts.extend(prompts)  # Add command-specific prompts here...

        # Look for prompt matches after executing the command
        index = self.cexpect(cli_prompts, timeout=command_timeout)

        # Handle sudo password prompt...
        if index==1:  # a password prompt
            if self.debug:
                rich_print("    [bold blue]Responding to password prompt:[/bold blue] [bold yellow]'{}'[/bold yellow]".format(
                    self.matching_prompt))
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
            rich_print("    [bold blue]csendline('{}') called[/bold blue]".format(
                text))
            rich_print("    [bold blue]---------[/bold blue]")
        # WARNING: use self.child.sendline(); do not use self.csendline() here
        self.child.sendline(text)

    def cexpect(self, pattern_list, timeout=-1):
        assert self.child.isalive()
        if self.debug:

            rich_print("    [bold blue]cexpect([/bold blue][bold green]pattern_list, timeout={}[/bold green][bold blue]) called[/bold blue]".format(timeout))
            # Expand all pattern_list terms...
            rich_print("        [bold blue]pattern_list = {}[/bold blue]".format("[["))
            for idx, term in enumerate(pattern_list):
                rich_print("            [bold blue]{} {},[/bold blue]".format(
                    idx, repr(term)))
            rich_print("        [bold blue]{}[/bold blue]".format(str("]]")))

        now = time.time()
        try:
            match_index = self.child.expect(pattern_list, timeout=timeout)
            if self.debug:
                delta_secs = round(time.time()-now, 4)
                rich_print("\n      [bold blue]^^ cexpect() matched regex at match_index {}={}[/bold blue]".format(match_index, repr(pattern_list[match_index])))
                # FIXME why can't I use quotes around self.matching_prompt in rich_print()
                rich_print("      [bold blue]^^ cexpect() matching_prompt={}[/bold blue]".format(repr(self.matching_prompt)))
                rich_print("      [bold blue]^^ cexpect() match time: {} seconds[/bold blue]".format(delta_secs))

            self.matching_prompt_regex_index = match_index
            self.matching_prompt_regex = pattern_list[match_index]

        except px.exceptions.EOF:
            if self.debug:
                rich_print("      [bold red]cexpect() EOF exception while waiting for pattern_list[/bold red]")
            match_index = -1

        except px.exceptions.TIMEOUT:
            if self.debug:
                rich_print("      [bold red]cexpect() TIMEOUT exception while waiting for pattern_list[/bold red]")
            match_index = -1

        return match_index

    def interact(self):
        self._go_INTERACT()

    @property
    def matching_prompt(self):
        """Get the matching prompt (what matched the regex, no regex chars)"""
        assert self.child.isalive()

        if self.debug:
            rich_print("[bold blue]matching_prompt property[/bold blue]")
        after = self.child.after
        candidate_prompt = after.splitlines()[-1].strip()   # Must use strip() here...

        match_bool = False
        for expected_last_char in EXPECTED_LAST_PROMPT_CHARS:
            if (candidate_prompt[-1]==expected_last_char):
                match_bool = True

        assert match_bool is True, "Can't find last prompt character in candidate_prompt: {}".format(candidate_prompt)
        if self.debug:
            rich_print("    [bold blue]candidate_prompt should have: {}[/bold blue]".format(EXPECTED_LAST_PROMPT_CHARS))
            rich_print("    [bold blue]candidate_prompt: '{}'[/bold blue]".format(candidate_prompt))
        return candidate_prompt

    @property
    def response(self):
        return self.child.before

    def exit(self):
        self.child.close()

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

    def sync_prompt(self, require_detect_prompt=True):
        """Catch up with any queued prompts, we know to exit if we get a px.exceptions.TIMEOUT error"""
        if self.debug:
            rich_print("[bold blue]sync_prompt(require_detect_prompt={}) called[/bold blue]".format(require_detect_prompt))

        # self.detect_prompt() *should* come before self.sync_prompt()
        if (self.prompt_str=="") and (require_detect_prompt is True):
            raise PromptDetectionError("detect_prompt() must run before sync_prompt()")

        # WARNING: use self.child.sendline(); do not use self.csendline() here
        self.child.sendline('')

        finished = False
        while not finished:
            # Use a very short timeout here...
            # WARNING self.child.expect() is required; do not use self.cexpect()
            try:
                index = self.child.expect(self.base_prompt_regex, timeout=1)
                if self.debug:
                    rich_print("    [bold blue]sync_prompt() index={}[/bold blue]".format(index))
            except px.exceptions.TIMEOUT:
                # We got an EOF or TIMEOUT error...
                self.login_attempts = 0
                finished = True
            except px.exceptions.EOF:
                # We got an EOF or TIMEOUT error...
                self.login_attempts = 0
                finished = True

            if index==-1:
                # We got an EOF or TIMEOUT error...
                self.login_attempts = 0
                finished = True

            if (index==0 or index==1):
                raise UnexpectedPrompt("Unexpected prompt in sync_prompt(): {}".format(self.matching_prompt))

            elif index==2:
                # We should only get to this prompt if auto_priv_mode is 
                #     False
                self.login_attempts = 0
            elif index==3:
                # We should only get to this prompt if auto_priv_mode is 
                #     False
                self.login_attempts = 0
            elif index==4:
                # We don't need to attempt any more logins if we have 
                #     a priv prompt
                self.login_attempts = 0


    def close(self):
        self.child.close()
        return (self.child.exitstatus, self.child.signalstatus)

    def detect_prompt(self):
        """detect_prompt() checks for premature entry into LOGIN_COMPLETE and also looks for a prompt string"""
        # Detect the prompt as best-possible...
        if self.debug:
            rich_print("[bold blue]detect_prompt() called[/bold blue]")

        abbv_prompt_list = [r'sername:', r'[Pp]assword[^\r\n]{0,20}?:', r'>', re.escape('$'), 
            re.escape('#')]

        #self.csendline('')  # FIXME I might need to delete this...

        # Double check that this isn't a pre-login banner...
        ii = 0
        finished = False
        while not finished:
            # Use a very short timeout here...
            # WARNING self.child.expect() is required; do not use self.cexpect()
            try:
                ii += 1  # Keep track of how many times we loop through input
                index = self.child.expect(abbv_prompt_list, timeout=1)
            except px.exceptions.TIMEOUT:
                assert self.child.isalive()
                if self.debug:
                    rich_print("[bold blue]    detect_prompt() pre-login finished because it found TIMEOUT condition while looking for abbv_prompt_list[/bold blue]")
                index = -1
                finished = True
            except px.exceptions.EOF:
                if self.debug:
                    rich_print("[bold blue]    detect_prompt() pre-login finished because it found EOF condition while looking for abbv_prompt_list[/bold blue]")
                index = -1
                finished = True

            if index==-1:
                assert self.child.isalive()
                if self.debug:
                    rich_print("[bold blue]    detect_prompt() index={}[/bold blue]".format(index))

            elif index==0:
                assert self.child.isalive()
                # We probably went to detect_prompt() based on some banner
                # This should be a username prompt...
                if self.debug:
                    rich_print("[bold blue]    detect_prompt() found a premature entry into detect_prompt().  Redirecting to state SEND_LOGIN_USERNAME[/bold blue]")
                self._go_SEND_LOGIN_USERNAME()

            elif index==1:
                assert self.child.isalive()
                # We probably went to detect_prompt() based on some banner
                # This should be a password prompt...
                if self.debug:
                    rich_print("[bold blue]    detect_prompt() found a premature entry into detect_prompt().  Redirecting to state SEND_LOGIN_PASSWORD[/bold blue]")

                self._go_SEND_LOGIN_PASSWORD()

            elif index>1:
                # We got a non-user, non-password prompt... exit this loop!
                # Start prompt detection heuristics...
                if self.debug:
                    finished = True

            if self.debug:
                rich_print("    [bold blue]detect_prompt() loop={}".format(ii))

        if self.debug:
            rich_print("\n    [bold blue]detect_prompt() finished the while loop after {} iterations. Detected prompt index={}[/bold blue]".format(ii, index))
            rich_print("    [bold blue]detect_prompt() using prompt detection heuristics[/bold blue]")
        # WARNING: use self.child.sendline(); do not use self.csendline() here
        self.child.sendline('')

        ### Start building prompt_str and base_prompt_regex
        # Use a very short timeout here
        # WARNING self.child.expect() is required; do not use self.cexpect()
        try:
            # replaced self.base_prompt_regex with abbv_prompt_list
            index = self.child.expect(abbv_prompt_list, timeout=1)
        except px.exceptions.TIMEOUT:
            assert self.child.isalive()
            if self.debug:
                rich_print("[bold blue]    detect_prompt() pre-login finished.  Hit TIMEOUT condition[/bold blue]")
        except px.exceptions.EOF:
            assert self.child.isalive()
            if self.debug:
                rich_print("[bold blue]    detect_prompt() pre-login finished.  Hit EOF condition[/bold blue]")

        ## Example of prompt detection on route-views.oregon-ix.org...
        hostname = self.child.before.strip()  # detect hostname    = route-views
        prompt_char = self.child.after.strip()# detect prompt_char = >
        hostname_output_list = hostname.splitlines()
        if len(hostname_output_list)==0:
            prompt_str = ""   # This is bad... we don't want to hit this...
        elif len(hostname_output_list)==1:
            prompt_str = hostname_output_list[0]
        elif len(hostname_output_list)>1:
            prompt_str = hostname_output_list[-1] # Get the last entry in list
        else:
            raise PromptDetectionError()
        self.prompt_str = prompt_str

        if self.debug:
            rich_print("\n        [bold blue]detect_prompt() found prompt_str:[/bold blue] '{}'".format(self.prompt_str))

        self.build_base_prompt_regex()  # Adjust the prompt regex after detection

        return self.prompt_str

    def build_base_prompt_regex(self):
        """Assign self.base_prompt_regex with the latest prompt info"""
        if self.debug:
            rich_print("[bold blue]build_base_prompt_regex() called[/bold blue]")
            rich_print("    [bold blue]self.prompt_str should not have the ending character (like ':', '>', '#', '$')[/bold blue]")
            rich_print("    [bold blue]self.prompt_str='{}'[/bold blue]".format(
                self.prompt_str))

        if self.debug:
            rich_print("    [bold blue]while not end_loop_bool[/bold blue]")

        self.linux_prompt = r'[\n\r]+{0}[^{1}]*?{1}\s*'.format(re.escape(
            self.prompt_str), re.escape('$'))

        self.base_prompt_regex = [r'sername:', r'[Pp]assword[^\r\n]{0,20}?:',
            #r'[\n\r]+{}[^\n\r>]*?>\s*'.format(self.prompt_str), 
            r'[\n\r]+{0}.*?>\s*'.format(re.escape(self.prompt_str)),
            #linux_prompt, r'[\n\r]+{0}[^\n\r#]*?{1}\s*'.format(
            self.linux_prompt, r'[\n\r]+{0}.*?{1}\s*'.format(
            re.escape(self.prompt_str), re.escape('#'))]

        if self.debug:
            # Expand all base_prompt_regex terms...
            rich_print("        [bold blue]self.base_prompt_regex = {}[/bold blue]".format("[["))
            for idx, term in enumerate(self.base_prompt_regex):
                rich_print("            [bold blue]{} {},[/bold blue]".format(
                    idx, repr(term)))
            rich_print("        [bold blue]{}[/bold blue]".format(str("]]")))

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
                self.close()      # Make way for a fresh child instance

            self._go_CONNECT()

            self.login_attempts -= 1

    def after_CONNECT_cb(self):
        """Build an ssh / telnet session to self.host"""

        if self.debug:
            rich_print("[bold blue]Entering state: [/bold blue][bold magenta]{}[/bold magenta]".format(
                self.state))

        if self.child is not None:
            self.close()

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

        if self.debug:
            rich_print("    [bold blue]Call cexpect() from after_CONNECT_cb()[/bold blue]")
        index = self.cexpect(self.base_prompt_regex, timeout=self.login_timeout)

        if self.debug:
            rich_print("       [bold blue]self.cexpect() matched prompt index:[/bold blue] {}".format(index))
            rich_print("       [bold blue]self.cexpect() matching prompt:[/bold blue] {}".format(self.base_prompt_regex[index]))

        if index==-1:
            time.sleep(70)
            self._go_CONNECT()
        elif index==0:
            self._go_SEND_LOGIN_USERNAME()
        elif index==1:
            self._go_SEND_LOGIN_PASSWORD()
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
                rich_print("\n   [bold blue]after_SEND_LOGIN_PASSWORD_cb() - self.child.expect() matching_ prompt:[/bold blue] {}".format(repr(self.base_prompt_regex[index])))

            if index==0:  # This was the wrong password
                self.close()
                self._go_SELECT_LOGIN_CREDENTIALS()  # Restart login with different creds
            elif index==1:
                self.close()
                self._go_SELECT_LOGIN_CREDENTIALS()  # Restart login with different creds
            elif index==2:
                self._go_LOGIN_SUCCESS_UNPRIV()  # We got an unpriv prompt here
            elif index==3:
                self._go_LOGIN_SUCCESS_UNPRIV()  # We got an unpriv prompt here
            elif index==4:
                self._go_LOGIN_SUCCESS_PRIV()  # We got a priv prompt

        except px.exceptions.EOF:
            if self.debug:
                rich_print("   [bold red]after_SEND_LOGIN_PASSWORD_cb() - pexpect.exceptions.EOF error[/bold red]")
            self.close()
            #self._go_SELECT_LOGIN_CREDENTIALS()  # Restart login with different creds
            self._go_CONNECT()  # Restart login with different creds

        except px.exceptions.TIMEOUT:
            if self.debug:
                rich_print("   [bold red]after_SEND_LOGIN_PASSWORD_cb() - pexpect error: TIMEOUT[/bold red]")
            self.close()
            #self._go_SELECT_LOGIN_CREDENTIALS()  # Restart login with different creds
            self._go_CONNECT()  # Restart login with different creds

    def after_SEND_LOGIN_USERNAME_cb(self):

        if self.debug:
            rich_print("[bold blue]Entering state: [/bold blue][bold magenta]{}[/bold magenta]".format(
                self.state))

        self.csendline(self.username)

        index = self.cexpect(self.base_prompt_regex,
            timeout=self.login_timeout)

        if self.debug:
            rich_print("   [bold blue]after_SEND_LOGIN_USERNAME_cb() - self.child.expect() matched prompt index:[/bold blue] {}".format(index))
            rich_print("   [bold blue]after_SEND_LOGIN_USERNAME_cb() - self.child.expect() matching_prompt:[/bold blue] {}".format(self.base_prompt_regex[index]))

        if index==0:
            self._go_SELECT_LOGIN_CREDENTIALS()
        elif index==1:
            self._go_SEND_LOGIN_PASSWORD()
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

        self.csendline('')

        index = self.cexpect(self.base_prompt_regex,
            timeout=self.command_timeout)

        if self.debug:
            rich_print("   [bold blue]after_LOGIN_SUCCESS_UNPRIV_cb() - self.child.expect() matched prompt index:[/bold blue] {}".format(index))
            rich_print("   [bold blue]after_LOGIN_SUCCESS_UNPRIV_cb() - self.child.expect() matching_prompt:[/bold blue] {}".format(self.base_prompt_regex[index]))

        if index==0:
            raise Exception("Unexpected prompt: 'name:'")
        elif index==1:
            self._go_SEND_PRIV_PASSWORD()
        elif index==2:
            pass # Got a '>' prompt
        elif index==3:
            pass # Got a '#' prompt
        elif index==4:
            self._go_LOGIN_SUCCESS_PRIV()    # We got a priv prompt here

        self._go_LOGIN_COMPLETE()

    def after_SEND_PRIV_PASSWORD_cb(self):

        if self.debug:
            rich_print("[bold blue]Entering state: [/bold blue][bold magenta]{}[/bold magenta]".format(
                self.state))

        self.csendline(self.password)

        index = self.cexpect(self.base_prompt_regex,
            timeout=self.command_timeout)

        if self.debug:
            rich_print("   [bold blue]after_SEND_PRIV_PASSWORD_cb() - self.child.expect() matched prompt index:[/bold blue] {}".format(index))
            rich_print("   [bold blue]after_SEND_PRIV_PASSWORD_cb() - self.child.expect() matching_prompt:[/bold blue] {}".format(self.base_prompt_regex[index]))

        if index==0:
            raise UnexpectedPrompt("Unexpected prompt: 'name:'")
        elif index==1:
            self._go_SEND_PRIV_PASSWORD()
        elif index==2:
            raise UnexpectedPrompt("Unexpected prompt: '>'")
        elif index==3:
            raise UnexpectedPrompt("Unexpected prompt: '$'")
        elif index==4:
            self._go_LOGIN_SUCCESS_PRIV()    # We got a priv prompt here

    def after_LOGIN_SUCCESS_PRIV_cb(self):

        if self.debug:
            rich_print("[bold blue]Entering state: [/bold blue][bold magenta]{}[/bold magenta]".format(
                self.state))

        self._go_LOGIN_COMPLETE()

    def after_LOGIN_COMPLETE_cb(self):
        """Clean up on any queued command prompts and accept user commands"""

        if self.debug:
            rich_print("[bold blue]Entering state: [/bold blue][bold magenta]{}[/bold magenta]".format(
                self.state))

        #if self.debug:
        #    rich_print("    [bold blue]Call detect_prompt() from LOGIN_COMPLETE[/bold blue]")
        if self.debug:
            rich_print("    [bold blue]Calling sync_prompt() from after_LOGIN_COMPLETE_cb()[/bold blue]")
        self.detect_prompt() # detect_prompt() *should* come before sync_prompt()
        self.sync_prompt()

    def after_INTERACT_cb(self):
        """Allow unscripted interaction with the system"""
        assert self.child.isalive()

        if self.debug:
            rich_print("[bold blue]Entering state: [/bold blue][bold magenta]{}[/bold magenta]".format(
                self.state))
        rich_print("[bold magenta]Enter INTERACT mode; use Cntl-] to escape[/bold magenta]")
        self.child.interact(escape_character=chr(4),
            input_filter=None, output_filter=interact_filter)


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
