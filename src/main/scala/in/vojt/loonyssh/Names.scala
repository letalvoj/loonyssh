package in.vojt.loonyssh

import scala.annotation.alpha

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

object DisconnectCode extends SSHReader.ByKey[DisconnectCode, Int](_.code)

enum ChannelOpenFailure(val code:Int):
    case ADMINISTRATIVELY_PROHIBITED extends ChannelOpenFailure(1)
    case CONNECT_FAILED              extends ChannelOpenFailure(2)
    case UNKNOWN_CHANNEL_TYPE        extends ChannelOpenFailure(3)
    case RESOURCE_SHORTAGE           extends ChannelOpenFailure(4)

object ChannelOpenFailure extends SSHReader.ByKey[ChannelOpenFailure, Int](_.code)

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

object PseudoTerminalModes extends SSHReader.ByKey[PseudoTerminalModes, Int](_.code)

enum Service:
    @alpha("ssh-userauth")
    case `ssh-userauth`
    @alpha("ssh-connection")
    case `ssh-connection`

enum AuthenticationMethod:
    @alpha("publickey")
    case `publickey`
    @alpha("password")
    case `password`
    @alpha("hostBased")
    case `hostBased`
    @alpha("none")
    case `none`

enum ConnectionProtocolChannelType:
    @alpha("session")
    case `session`
    @alpha("x11")
    case `x11`
    @alpha("forwarded-tcpip")
    case `forwarded-tcpip`
    @alpha("direct-tcpip")
    case `direct-tcpip`

enum ConnectionProtocolRequestType:
    @alpha("tcpip-forward")
    case `tcpip-forward`
    @alpha("cancel-tcpip-forward")
    case `cancel-tcpip-forward`

enum ConnectionProtocolChannelRequestName:
    @alpha("pty-req")
    case `pty-req`
    @alpha("x11-req")
    case `x11-req`
    @alpha("env")
    case `env`
    @alpha("shell")
    case `shell`
    @alpha("exec")
    case `exec`
    @alpha("subsystem")
    case `subsystem`
    @alpha("window-change")
    case `window-change`
    @alpha("xon-xoff")
    case `xon-xoff`
    @alpha("signal")
    case `signal`
    @alpha("exit-status")
    case `exit-status`
    @alpha("exit-signal")
    case `exit-signal`

enum SignalName:
    @alpha("ABRT")
    case `ABRT`
    @alpha("ALRM")
    case `ALRM`
    @alpha("FPE")
    case `FPE`
    @alpha("HUP")
    case `HUP`
    @alpha("ILL")
    case `ILL`
    @alpha("INT")
    case `INT`
    @alpha("KILL")
    case `KILL`
    @alpha("PIPE")
    case `PIPE`
    @alpha("QUIT")
    case `QUIT`
    @alpha("SEGV")
    case `SEGV`
    @alpha("TERM")
    case `TERM`
    @alpha("USR1")
    case `USR1`
    @alpha("USR2")
    case `USR2`

enum KeyExchangeMethod:
    @alpha("ecdh-sha2-nistp256")
    case `ecdh-sha2-nistp256`
    case Unknown(value:String)

enum EncryptionAlgorithm:
    @alpha("aes128-ctr")
    case `aes128-ctr`
    @alpha("none")
    case `none`
    case Unknown(value:String)

enum MACAlgorithm:
    @alpha("hmac-sha1")
    case `hmac-sha1`
    @alpha("hmac-sha2-256")
    case `hmac-sha2-256`
    @alpha("none")
    case `none`
    case Unknown(value:String)

enum PublicKeyAlgorithm:
    @alpha("ssh-rsa") 
    case `ssh-rsa`
    @alpha("ssh-ed25519") 
    case `ssh-ed25519`
    case Unknown(value:String)

enum CompressionAlgorithm:
    case zlib
    case none
    case Unknown(value:String)
