#!/bin/bash
read -r -d '' USAGE << EOM
# ------------------------------------------------------------------------------
# RFC 9116 helper; security.txt formatter & PGP signer.
#
# Usage: securitytxt-signer.sh input.txt [0xPGPKEY [output.txt]]
#
# Removes lines not matching the specification & HTTPS URLs not working, checks
# for required fields, updates Expires field to today + \$DAYS_MAX days (unless
# the optional PGP key expires before that). Optionally signs the security.txt
# with GnuPG & warns on Encryption fields not matching with the signing key.
#
# Can be used to re-sign a security.txt file with an updated Expires field as
# the validation removes the current signature.
#
# Author : Esa Jokinen (oh2fih)
# Home   : https://github.com/oh2fih/securitytxt-tools
# ------------------------------------------------------------------------------
EOM

# Settings
DAYS_MAX="364" # RFC 9116, 2.5.5 recommends less than a year; integer

# Args
INFILE="$1"
KEY="$2"
OUTFILE="$3"

# Print usage
echo -e "\033[0;32m${USAGE}\033[0m" >&2

if [ "$#" -lt 1 ]; then
  exit 1
fi

# Check for requirements. Print all unmet requirements at once.

required_command() {
  if ! command -v "$1" &> /dev/null; then
    if [ -z ${2+x} ]; then
      echo -e "\033[0;31mThis script requires ${1}!\033[0m" >&2
    else
      echo -e "\033[0;31mThis script requires ${1} ${2}!\033[0m" >&2
    fi
    ((UNMET=UNMET+1))
  fi
}

UNMET=0

required_command "sed"
required_command "awk"
required_command "grep"
required_command "date" "for date comparison & formatting"
required_command "curl" "for target HTTPS URL validation"

if [[ "$KEY" =~ ^0x[a-fA-F0-9]{8,40}$ ]]; then
  required_command "gpg" "for signing the security.txt"
fi

if [ ! -f "$INFILE" ]; then
  echo -e "\033[0;31mERROR! Input file not found (${INFILE})\033[0m" >&2
  ((UNMET=UNMET+1))
fi

if [ "$UNMET" -gt 0 ]; then
  exit 1
fi

shopt -s nocasematch

# Validate the PGP key.

if ! [[ "$KEY" =~ ^0x[a-fA-F0-9]{8,40}$ ]]; then
  echo -e -n '\033[0;33mValid key ID not specified;\033[0m' >&2
  echo -e '\033[0;33m only validating & formatting, not saving.\033[0m' >&2
else
  KEY_INFO=$(gpg --list-secret-keys "$KEY" 2> >(sed $'s,.*,\e[33m&\e[m,'>&2))

  KEY_EXPIRES=$(
    echo "$KEY_INFO" \
      | grep "sec" \
      | grep -Eo 'expires:\ [0-9\-]+' \
      | awk '{ print $2}' \
      | date -Iseconds -u -f - \
      | sed -e 's/+00:00$/Z/'
    )
  echo

  if [[ "$KEY_EXPIRES" = "" ]]; then
    echo -e "\033[0;31mERROR! Unable to sign with PGP key ${KEY}\033[0m" >&2
    exit 1
  fi

  # Replace PGP IDs with the full PGP fingerprint.
  GREPABLE_KEY=${KEY//0x/}
  FP=$(echo "$KEY_INFO" | grep -i "$GREPABLE_KEY" | sed -e 's/[^A-F0-9]//g')
  KEY="0x${FP}"
  if ! [[ "${KEY}" = "0x${GREPABLE_KEY^^}" ]]; then
    echo -e "\033[0;33mEXPANDED 0x${GREPABLE_KEY^^} TO ${KEY}\033[0;0m"
  fi
fi

# Configure output.

if [ "$#" -lt 3 ]; then
  echo -e '\033[0;33mOutput file not specified; printing to stdout.\033[0m' >&2
  OUTFILE="-"
elif [ -f "$OUTFILE" ]; then
  echo -e "\033[0;33mThe output file (${OUTFILE}) already exists.\033[0m" >&2
  echo -e "\033[0;33mGnuPG will ask later whether to overwrite it.\033[0m" >&2
  echo
fi

# Set expire date. 
# If the key expires before the DAYS_MAX, use the key expiration date instead.

EXPIRES=$(date -Iseconds -u -d "${DAYS_MAX} days" | sed -e 's/+00:00$/Z/')

if [ -z ${KEY_EXPIRES+x} ]; then 
  echo -e "\033[0;33mUSING EXPIRE (max ${DAYS_MAX} days): $EXPIRES\033[0;0m"
else
  EXPIRES_COMPARABLE=$(date -d "$EXPIRES" +%s)
  KEY_EXPIRES_COMPARABLE=$(date -d "$KEY_EXPIRES" +%s)

  echo -e "\033[0;33mComparing ${EXPIRES} to key expr ${KEY_EXPIRES}.\033[0;0m"

  if [ "$EXPIRES_COMPARABLE" -ge "$KEY_EXPIRES_COMPARABLE" ]; then
    EXPIRES="$KEY_EXPIRES"
    echo -e "\033[0;33mUSING EXPIRE (from key ${KEY}): ${EXPIRES}\033[0;0m"
  else
    echo -e "\033[0;33mUSING EXPIRE (max ${DAYS_MAX} days): ${EXPIRES}\033[0;0m"
  fi
fi

# HTTPS URL, HTTPS PGP public key & email address validators.

test_https_url() {
  if [[ "$1" =~ ^(https:) ]]; then
    RESP=$(curl --silent --fail -o /dev/null -w "%{http_code}" "$1") || return 1
    if ! [[ "$RESP" = "200" ]]; then
      echo "WARNING! HTTP STATUS $RESP (not 200 ok): $1" >&2
    fi
  else
    return 1
  fi
}

compare_https_pgpkey() {
  if [[ "$1" =~ ^(https:) ]]; then
    curl --silent --fail "$1" \
      | gpg --show-key 2> /dev/null \
      | grep "${FP}" > /dev/null
  else
    return 1
  fi
}

validate_email() {
  REGEX_USER="[[:alnum:]._%+-]+"
  REGEX_HOST="[[:alnum:].-]+"
  REGEX_TLD="(XN--[[:alnum:]-]{2,20}|[[:alpha:]]{2,18})"
  REGEX_EMAIL="^${REGEX_USER}@${REGEX_HOST}\.${REGEX_TLD}$"

  if [[ "$1" =~ $REGEX_EMAIL ]]; then
    return 0
  else
    return 1
  fi
}

# Long regular expressions used in validation and formatting.

REGEX_HTTPS_SHORT="^((Acknowledgments|Canonical|Hiring|Policy):[[:space:]])"
REGEX_HTTPS="^((Acknowledgments|Canonical|Hiring|Policy):[[:space:]])(https:)"

REGEX_ENC_DNS="^(Encryption:)[[:space:]](dns:)[0-9a-fA-F]{56}\._openpgpkey\."
REGEX_ENC_O4F="^(Encryption:)[[:space:]](openpgp4fpr:)[0-9a-fA-F]{40}$"

REGEX_LANG_PRE="^(Preferred-Languages:)[[:space:]]"
REGEX_LANG_TAG="[a-z]{1,8}(-[a-z]{1,8})?"
REGEX_LANG="${REGEX_LANG_PRE}(${REGEX_LANG_TAG},[[:space:]])*${REGEX_LANG_TAG}"

# Counters for mandatory, recommended and only-once fields.

CONTACT_SEEN=0
EXPIRES_SEEN=0
LANGUAGES_SEEN=0
CANONICAL_SEEN=0

# Validate & format.

FORMATTED=""
echo -e '\033[31m'

while read -r RAWLINE || { [ -n "$RAWLINE" ] && echo "ADDED NEWLINE @EOF"; }; do
  # Replace CR/LF with LF. This is not a requirement from the RFC, but required
  # by the operations on this script. (Not possible with parameter expansion.)
  # shellcheck disable=SC2001
  LINE=$(echo "$RAWLINE" | sed -e "s/\r$//")

  # Update Expires-field.
  if [[ "$LINE" =~ ^(Expires:) ]]; then
    if [ "$EXPIRES_SEEN" = 0 ]; then
      FORMATTED+="Expires: ${EXPIRES}"$'\n'
      ((EXPIRES_SEEN=EXPIRES_SEEN+1))
    else
      echo "REMOVED (EXPIRES ALREADY SET): ${LINE}" >&2
    fi

  # Validate & format Contact fields.
  elif [[ "$LINE" =~ ^(Contact:) ]]; then
    if [[ "$LINE" =~ ^(Contact:)[[:space:]](https:) ]]; then
      URL=$(echo "$LINE" | grep -Eo 'https://[^ >]+' | head -1)
      if test_https_url "$URL"; then
        FORMATTED+="${LINE}"$'\n'
        ((CONTACT_SEEN=CONTACT_SEEN+1))
      else
        echo "REMOVED (URL NOT WORKING): ${LINE}" >&2
      fi
    elif [[ "$LINE" =~ ^(Contact:)[[:space:]](mailto:) ]]; then
      EMAIL=$(echo "$LINE" | sed -n -e 's/^.*mailto://p')
      if validate_email "$EMAIL"; then
        FORMATTED+="${LINE}"$'\n'
        ((CONTACT_SEEN=CONTACT_SEEN+1))
      else
        echo "REMOVED (INVALID EMAIL): ${LINE}" >&2
      fi
    elif [[ "$LINE" =~ ^(Contact:)[[:space:]](tel:) ]]; then
      # Automatically fix a commmon tel: URI mistake based on RFC 3966, 5.1.1;
      # "tel" URIs MUST NOT use spaces in visual separators. Replacing spaces
      # with hyphens that are allowed in the examples (RFC 3966, 6).
      FIXEDLINE=$(echo "$LINE" | sed -e 's/[[:space:]]*$//' | sed "s/ /\\-/2g")
      if [[ "$FIXEDLINE" =~ ^(Contact:)[[:space:]](tel:)[+]?[0-9\-]+$ ]]; then
        if ! [[ "$FIXEDLINE" = "$LINE" ]]; then
          echo "FIXED (tel: MUST NOT use spaces; RFC 3966, 5.1.1): ${LINE}" >&2
        fi
        FORMATTED+="${FIXEDLINE}"$'\n'
        ((CONTACT_SEEN=CONTACT_SEEN+1))
      else
        echo "REMOVED (INVALID TEL): ${LINE}" >&2
      fi
    else
      echo "REMOVED (INVALID/UNKNOWN CONTACT URI): ${LINE}" >&2
    fi

  # Validate & format other HTTPS URI fields.
  elif [[ "$LINE" =~ $REGEX_HTTPS_SHORT ]]; then
    if [[ "$LINE" =~ $REGEX_HTTPS ]]; then
      URL=$(echo "$LINE" | grep -Eo 'https://[^ >]+' | head -1)
      if test_https_url "$URL"; then
        FORMATTED+="${LINE}"$'\n'
        if [[ "$LINE" =~ ^(Canonical):[[:space:]](https:) ]]; then
          ((CANONICAL_SEEN=CANONICAL_SEEN+1))
        fi
      else
        echo "REMOVED (URL NOT WORKING): ${LINE}" >&2
      fi
    else
      echo "REMOVED (SCHEME NOT SUPPORTED): ${LINE}" >&2
    fi

  # Validate & format Encryption fields.
  elif [[ "$LINE" =~ ^(Encryption:)[[:space:]] ]]; then
    if [[ "$LINE" =~ ^(Encryption:)[[:space:]](https:) ]]; then
      URL=$(echo "$LINE" | grep -Eo 'https://[^ >]+' | head -1)
      if test_https_url "$URL"; then
        # Comparison only if signing key is specified.
        if [[ "$KEY" =~ ^0x[a-fA-F0-9]{8,40}$ ]]; then
          if ! compare_https_pgpkey "$URL"; then
            echo "WARNING! SIGNING KEY NOT FOUND @ THE FETCHED URL: ${LINE}" >&2
          fi
        fi
        FORMATTED+="${LINE}"$'\n'
      else
        echo "REMOVED (URL NOT WORKING): ${LINE}" >&2
      fi
    elif [[ "$LINE" =~ ^(Encryption:)[[:space:]](openpgp4fpr:) ]]; then
      if [[ "$LINE" =~ $REGEX_ENC_O4F ]]; then
        # Comparison with empty fingerprint always passes.
        if ! [[ "$LINE" == *"$FP"* ]]; then
          echo "WARNING! SIGNING KEY & OPENPGP4FPR DO NOT MATCH: ${LINE}" >&2
        fi
        FORMATTED+="${LINE}"$'\n'
      else
        echo "REMOVED (INVALID OPENPGP4FPR; not 40 hex chars): ${LINE}" >&2
      fi
    elif [[ "$LINE" =~ ^(Encryption:)[[:space:]](dns:) ]]; then
      if [[ "$LINE" =~ $REGEX_ENC_DNS ]]; then
        FORMATTED+="${LINE}"$'\n'
      else
        echo "REMOVED (INVALID DNS OPENPGPKEY; not 56 hex chars): ${LINE}" >&2
      fi
    else
      echo "REMOVED (SCHEME NOT SUPPORTED): ${LINE}" >&2
    fi

  # Validate & format Preferred-Languages field.
  elif [[ "$LINE" =~ ^(Preferred-Languages):[[:space:]] ]]; then
    if [[ "$LINE" =~ $REGEX_LANG ]]; then
      if [ "$LANGUAGES_SEEN" = 0 ]; then
        FORMATTED+="${LINE}"$'\n'
        ((LANGUAGES_SEEN=LANGUAGES_SEEN+1))
      else
        echo "REMOVED (LANGUAGES ALREADY SET): ${LINE}" >&2
      fi
    else
      echo "REMOVED (INVALID LANGUAGES): ${LINE}" >&2
    fi

  # Remove invalid lines allowing comments and empty lines.
  elif [[ "$LINE" =~ ^# ]]; then
    FORMATTED+="${LINE}"$'\n'
  elif [[ "$LINE" =~ ^$ ]]; then
    if ! [[ "$FORMATTED" = "" ]]; then
      FORMATTED+="${LINE}"$'\n'
    fi
  else
    echo "REMOVED (INVALID LINE): ${LINE}" >&2
  fi

done < "$INFILE"

# Errors and warnings for mandatory & required fields.

if [ "$CONTACT_SEEN" = 0 ]; then
  echo "ERROR! VALID MANDATORY CONTACT FIELD IS MISSING." >&2
  exit 1
fi

if [ "$EXPIRES_SEEN" = 0 ]; then
  echo "ADDED MISSING MANDATORY EXPIRES FIELD." >&2
  FORMATTED+="Expires: ${EXPIRES}"$'\n'
fi

if [ "$CANONICAL_SEEN" = 0 ]; then
  echo "WARNING! VALID RECOMMENDED CANONICAL FIELD IS MISSING." >&2
fi

shopt -u nocasematch

echo -e '\033[0;33m---\033[0m'

# Remove duplicate blank lines.
FORMATTED=$(echo "$FORMATTED" | sed '/^$/N;/^\n$/D')

# Print formatted security.txt.
echo -E "$FORMATTED"
echo -e '\033[0;33m---\033[0m'

if ! [[ "$KEY" =~ ^0x[a-fA-F0-9]{8,40}$ ]]; then
  # No key; no signing.
  exit 0
fi

# GnuPG signing.

echo -e "\033[0;33mIs this information correct? Do you want to sign with key:"
echo -e "${KEY_INFO}\033[0m"
read -p "(y/N)" -n 1 -r
echo

if [[ ! "$REPLY" =~ ^[Yy]$ ]]; then
  echo -e '\033[0;31mAborting...\033[0m' >&2
  exit 1
fi

echo -e '\033[0;33m---\033[0m'

echo "$FORMATTED" \
  | gpg --clearsign --local-user "$KEY" --output "$OUTFILE" \
  2> >(sed $'s,.*,\e[33m&\e[m,'>&2) \
  || exit 1

if ! [[ "$OUTFILE" = "-" ]]; then
  echo -e "\033[0;33mSaved as \"${OUTFILE}\":\033[0m"
  cat "$OUTFILE"
fi
