package in.vojt.loonyshh.names

enum DisconnectCode(val code:Int):
    case HostNotAllowedToConnect     extends DisconnectCode(1)
    case ProtocolError               extends DisconnectCode(2)
    case KeyExchangeFailed           extends DisconnectCode(3)
    case Reserved                    extends DisconnectCode(4)
    case MacError                    extends DisconnectCode(5)
    case CompressionError            extends DisconnectCode(6)
    case ServiceNotAvailable         extends DisconnectCode(7)
    case ProtocolVersionNotSupported extends DisconnectCode(8)
    case HostKeyNotVerifiable        extends DisconnectCode(9)
    case ConnectionLost              extends DisconnectCode(10)
    case ByApplication               extends DisconnectCode(11)
    case TooManyConnections          extends DisconnectCode(12)
    case AuthCancelledByUser         extends DisconnectCode(13)
    case NoMoreAuthMethodsAvailable  extends DisconnectCode(14)
    case IllegalUserName             extends DisconnectCode(15)

enum ChannelOpenFailure(val code:Int):
    case ADMINISTRATIVELY_PROHIBITED extends ChannelOpenFailure(1)
    case CONNECT_FAILED              extends ChannelOpenFailure(2)
    case UNKNOWN_CHANNEL_TYPE        extends ChannelOpenFailure(3)
    case RESOURCE_SHORTAGE           extends ChannelOpenFailure(4)

enum PseudoTerminalModes(val code:Int):
    /** Indicates end of options. */
    case TTY_OP_END       extends PseudoTerminalModes(0)
    /** Interrupt character; 255 if none.  Similarly for the other characters.  Not all of these characters are supported on all systems. */
    case VINTR            extends PseudoTerminalModes(1)
    /** The quit character (sends SIGQUIT signal on POSIX systems). */
    case VQUIT            extends PseudoTerminalModes(2)
    /** Erase the character to left of the cursor. */
    case VERASE           extends PseudoTerminalModes(3)
    /** Kill the current input line. */
    case VKILL            extends PseudoTerminalModes(4)
    /** End-of-file character (sends EOF from the terminal). */
    case VEOF             extends PseudoTerminalModes(5)
    /** End-of-line character in addition to carriage return and/or linefeed. */
    case VEOL             extends PseudoTerminalModes(6)
    /** Additional end-of-line character. */
    case VEOL2            extends PseudoTerminalModes(7)
    /** Continues paused output (normally control-Q). */
    case VSTART           extends PseudoTerminalModes(8)
    /** Pauses output (normally control-S). */
    case VSTOP            extends PseudoTerminalModes(9)
    /** Suspends the current program. */
    case VSUSP            extends PseudoTerminalModes(10)
    /** Another suspend character. */
    case VDSUSP           extends PseudoTerminalModes(11)
    /** Reprints the current input line. */
    case VREPRINT         extends PseudoTerminalModes(12)
    /** Erases a word left of cursor. */
    case VWERASE          extends PseudoTerminalModes(13)
    /** Enter the next character typed literally, even if it is a special character */
    case VLNEXT           extends PseudoTerminalModes(14)
    /** Character to flush output. */
    case VFLUSH           extends PseudoTerminalModes(15)
    /** Switch to a different shell layer. */
    case VSWTCH           extends PseudoTerminalModes(16)
    /** Prints system status line (load, command, pid, etc). */
    case VSTATUS          extends PseudoTerminalModes(17)
    /** Toggles the flushing of terminal output. */
    case VDISCARD         extends PseudoTerminalModes(18)
    /** The ignore parity flag.  The parameter SHOULD be 0 if this flag is FALSE, and 1 if it is TRUE. */
    case IGNPAR           extends PseudoTerminalModes(30)
    /** Mark parity and framing errors. */
    case PARMRK           extends PseudoTerminalModes(31)
    /** Enable checking of parity errors. */
    case INPCK            extends PseudoTerminalModes(32)
    /** Strip 8th bit off characters. */
    case ISTRIP           extends PseudoTerminalModes(33)
    /** Map NL into CR on input. */
    case INLCR            extends PseudoTerminalModes(34)
    /** Ignore CR on input. */
    case IGNCR            extends PseudoTerminalModes(35)
    /** Map CR to NL on input. */
    case ICRNL            extends PseudoTerminalModes(36)
    /** Translate uppercase characters to lowercase. */
    case IUCLC            extends PseudoTerminalModes(37)
    /** Enable output flow control. */
    case IXON             extends PseudoTerminalModes(38)
    /** Any char will restart after stop. */
    case IXANY            extends PseudoTerminalModes(39)
    /** Enable input flow control. */
    case IXOFF            extends PseudoTerminalModes(40)
    /** Ring bell on input queue full. */
    case IMAXBEL          extends PseudoTerminalModes(41)
    /** Enable signals INTR, QUIT, [D]SUSP. */
    case ISIG             extends PseudoTerminalModes(50)
    /** Canonicalize input lines. */
    case ICANON           extends PseudoTerminalModes(51)
    /** Enable input and output of uppercase characters by preceding their lowercase equivalents with "\". */
    case XCASE            extends PseudoTerminalModes(52)
    /** Enable echoing. */
    case ECHO             extends PseudoTerminalModes(53)
    /** Visually erase chars. */
    case ECHOE            extends PseudoTerminalModes(54)
    /** Kill character discards current line. */
    case ECHOK            extends PseudoTerminalModes(55)
    /** Echo NL even if ECHO is off. */
    case ECHONL           extends PseudoTerminalModes(56)
    /** Don't flush after interrupt. */
    case NOFLSH           extends PseudoTerminalModes(57)
    /** Stop background jobs from output. */
    case TOSTOP           extends PseudoTerminalModes(58)
    /** Enable extensions. */
    case IEXTEN           extends PseudoTerminalModes(59)
    /** Echo control characters as ^(Char). */
    case ECHOCTL          extends PseudoTerminalModes(60)
    /** Visual erase for line kill. */
    case ECHOKE           extends PseudoTerminalModes(61)
    /** Retype pending input. */
    case PENDIN           extends PseudoTerminalModes(62)
    /** Enable output processing. */
    case OPOST            extends PseudoTerminalModes(70)
    /** Convert lowercase to uppercase. */
    case OLCUC            extends PseudoTerminalModes(71)
    /** Map NL to CR-NL. */
    case ONLCR            extends PseudoTerminalModes(72)
    /** Translate carriage return to newline (output). */
    case OCRNL            extends PseudoTerminalModes(73)
    /** Translate newline to carriage return-newline (output). */
    case ONOCR            extends PseudoTerminalModes(74)
    /** Newline performs a carriage return (output). */
    case ONLRET           extends PseudoTerminalModes(75)
    /** 7 bit mode. */
    case CS7              extends PseudoTerminalModes(90)
    /** 8 bit mode. */
    case CS8              extends PseudoTerminalModes(91)
    /** Parity enable. */
    case PARENB           extends PseudoTerminalModes(92)
    /** Odd parity, else even. */
    case PARODD           extends PseudoTerminalModes(93)
    /** Specifies the input baud rate in bits per second. */
    case TTY_OP_ISPEED    extends PseudoTerminalModes(128)
    /** Specifies the output baud rate in bits per second. */
    case TTY_OP_OSPEED    extends PseudoTerminalModes(129)

enum Service:
    case `ssh-userauth`
    case `ssh-connection`

enum AuthenticationMethod:
    case `publickey`
    case `password`
    case `hostBased`
    case `none`

enum ConnectionProtocolChannelType:
    case `session`
    case `x11`
    case `forwarded-tcpip`
    case `direct-tcpip`

enum ConnectionProtocolRequestType:
    case `tcpip-forward`
    case `cancel-tcpip-forward`

enum ConnectionProtocolChannelRequestName:
    case `pty-req`
    case `x11-req`
    case `env`
    case `shell`
    case `exec`
    case `subsystem`
    case `window-change`
    case `xon-xoff`
    case `signal`
    case `exit-status`
    case `exit-signal`

enum SignalName:
    case `ABRT`
    case `ALRM`
    case `FPE`
    case `HUP`
    case `ILL`
    case `INT`
    case `KILL`
    case `PIPE`
    case `QUIT`
    case `SEGV`
    case `TERM`
    case `USR1`
    case `USR2`

enum KeyExchangeMethod:
    case `diffie-hellman-group1-sha1`
    case `diffie-hellman-group14-sha1`
    case Unknown(value:String)

enum EncryptionAlgorithm:
    case `3des-cbc`
    case `blowfish-cbc`
    case `twofish256-cbc`
    case `twofish-cbc`
    case `twofish192-cbc`
    case `twofish128-cbc`
    case `aes256-cbc`
    case `aes192-cbc`
    case `aes128-cbc`
    case `serpent256-cbc`
    case `serpent192-cbc`
    case `serpent128-cbc`
    case `arcfour`
    case `idea-cbc`
    case `cast128-cbc`
    case `des-cbc`
    case `none`
    case Unknown(value:String)

enum MACAlgorithm:
    case `hmac-sha1`
    case `hmac-sha1-96`
    case `hmac-md5`
    case `hmac-md5-96`
    case `none`
    case Unknown(value:String)

enum PublicKeyAlgorithm:
    case `ssh-dss`
    case `ssh-rsa`
    case `pgp-sign-rsa`
    case `pgp-sign-dss`
    case Unknown(value:String)

enum CompressionAlgorithm:
    case `none`
    case `zlib`
    case Unknown(value:String)
