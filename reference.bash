#!/bin/bash 
# sha512-crypt for GNU and Bash
# By Vidar 'koala_man' Holen

## This is the script that I used as reference to reverse engineer crypt(), at least for sha512

b64="./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

stringToNumber() { 
    expression=0
    for((i=0; i<${#1}; i++))
    do
        expression=$(printf '(%s)*256+%d' "$expression" "'${1:$i:1}")
    done
    bc <<< "$expression"
}

# Turn some string into a \xd4\x1d hex string
stringToHex() { 
    for((i=0; i<${#1}; i++))
    do
        printf '\\x%x' "'${1:i:1}"
    done
}

# Turn stdin into a \xd4\x1d style sha512 hash
sha512hex() { 
    sum=$(sha512sum) 
    read sum rest <<< "$sum" # remove trailing dash
    hex=$(sed 's/../\\x&/g' <<< "$sum")
    echo "$hex"
}

# Turn an integer into a crypt base64 string with n characters
### Take an number ($1) (representing a binary value), and return the first n ($2) b64 bytes of it
intToBase64() { 
    number=$1
    n=$2
    for((j=0; j<n; j++))
    do
        digit=$(bc <<< "$number % 64")
        number=$(bc <<< "$number / 64")
        echo -n "${b64:digit:1}"
    done
}

# From hex string $1, get the bytes indexed by $2, $3 ..
### This does the re-arraging of the hash
getBytes() { 
    num=$1
    shift
    ### This is a bashism, for i loops over $1 with shift
    for i
    do
        echo -n "${num:$((i*4)):4}"
    done
}


### converts a hex string to a number, the tr capitalizes it, sed removes the \x before the hex
hexToInt() { 
    {
    echo 'ibase=16;'
    tr a-f A-F <<< "$1" | sed -e 's/\\x//g'
    } | bc
}

base64EncodeBytes() {
    n=$1
    shift 
    bytes=$(getBytes "$@")
    int=$(hexToInt "$bytes")
    intToBase64 "$int" "$n"
}

doHash() { 
    password="$1"
    passwordLength=$(printf "$password" | wc -c)
    salt="$2"
    saltLength=$(printf "$salt" | wc -c)
    magic="$3"
    [[ -z $magic ]] && magic='$6$'

    salt=${salt#$magic}
    salt=${salt:0:64} # 16 first bytes

    intermediate=$(
    {
        # Start intermediate result
        printf "$password$salt" 

        # compute a separate sha512 sum
        alternate=$(printf "$password$salt$password" | sha512hex) 

        # Add one byte from alternate for each character in the password. Wtf?
        while true; do printf "$alternate"; done | head -c "$passwordLength"

        # For every 1 bit in the key length, add the alternate sum
        # Otherwise add the entire key (unlike MD5-crypt)
        for ((i=$passwordLength; i != 0; i>>=1)) 
        do
            if (( i & 1 ))
            then
                printf "$alternate"
            else 
                printf "$password" 
            fi
        done

    } | sha512hex
    )
    firstByte=$(hexToInt $(getBytes "$intermediate" 0))

    p_bytes=$(for((i=0; i<$passwordLength; i++)); do printf "$password"; done | sha512hex | head -c $((passwordLength*4)) )
    s_bytes=$(for((i=0; i<16+${firstByte}; i++)); do printf "$salt"; done  | sha512hex | head -c $((saltLength*4)) )


    for((i=0; i<5000; i++))
    do
        intermediate=$({
            (( i & 1 )) && printf "$p_bytes" || printf "$intermediate"
            (( i % 3 )) && printf "$s_bytes"
            (( i % 7 )) && printf "$p_bytes"
            (( i & 1 )) && printf "$intermediate" || printf "$p_bytes"
        } | sha512hex)
    done

    # Rearrange the bytes and crypt-base64 encode them
    hex=$(base64EncodeBytes 86 "$intermediate" \
        63  62 20 41  40 61 19  18 39 60  59 17 38  37 58 16  15 36 57  56 14 35 \
            34 55 13  12 33 54  53 11 32  31 52 10   9 30 51  50  8 29  28 49  7 \
             6 27 48  47  5 26  25 46  4   3 24 45  44  2 23  22 43  1   0 21 42)

    printf "%s$salt\$%s\n" "$magic" "$hex" 

}


if [[ $# < 1 ]] 
then
    echo "Usage: $0 password [salt]" >&2 
    exit 1
fi

password=$(stringToHex "$1")
salt=$(stringToHex "$2")
[[ -z $salt ]] && salt=$(tr -cd 'a-zA-Z0-9' < /dev/urandom | head -c 16) 

doHash "$password" "$salt" '$6$'
