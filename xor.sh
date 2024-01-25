#!/bin/bash

# Initialize flags for input types
hex_input=false
binary_input=false
hex_output=false
binary_output=false

# Parse command-line options
while getopts "hbHo" opt; do
    case $opt in
    h)
        hex_input=true
        ;;
    b)
        binary_input=true
        ;;
    H)
        hex_output=true
        ;;
    o)
        binary_output=true
        ;;
    \?)
        echo "Usage: $0 [-h] [-b] [-H] [-o] <string1> <string2>"
        echo "  -h       Treat input as hexadecimal"
        echo "  -b       Treat input as binary"
        echo "           Treat input as ASCII if no input flag is passed"
        echo "  -H       Output result in hexadecimal"
        echo "  -o       Output result in binary"
        echo "           Output result in ASCII if no output flag is passed"
        exit 1
        ;;
    esac
done

# Shift the options to access the remaining arguments (string1 and string2)
shift $((OPTIND - 1))

# Check if exactly two arguments are provided
if [ "$#" -ne 2 ]; then
    echo "Usage: $0 [-h] [-b] <string1> <string2>"
    echo "  -h       Treat input as hexadecimal"
    echo "  -b       Treat input as binary"
    echo "           Treat input as ASCII if no input flag is passed"
    echo "  -H       Output result in hexadecimal"
    echo "  -o       Output result in binary"
    echo "           Output result in ASCII if no output flag is passed"
    exit 1
fi

string1="$1"
string2="$2"

# Check if the strings have the same length
if [ "${#string1}" -ne "${#string2}" ]; then
    echo "Error: The two strings must have the same length"
    exit 1
fi

# Function to perform XOR operation on characters
xor_chars() {
    char1="$1"
    char2="$2"
    xor_result=$(((16#${char1}) ^ (16#${char2})))
    printf '%X' "$xor_result"
}

# Function to convert binary string to hexadecimal
binary_to_hex() {
    hex_result=$(printf '%X' "$((2#${1}))")
    printf "%02s" "$hex_result"
}

result=""

if [ "$hex_input" = true ]; then
    # Handle hexadecimal input
    for ((i = 0; i < ${#string1}; i++)); do
        char1="${string1:i:1}"
        char2="${string2:i:1}"
        result+="$(xor_chars "$char1" "$char2")"
    done
elif [ "$binary_input" = true ]; then
    # Handle binary input
    for ((i = 0; i < ${#string1}; i += 8)); do
        bin1="${string1:i:8}"
        bin2="${string2:i:8}"
        hex1=$(binary_to_hex "$bin1")
        hex2=$(binary_to_hex "$bin2")
        result+="$(xor_chars "$hex1" "$hex2")"
    done
else
    # Handle regular ASCII input
    for ((i = 0; i < ${#string1}; i++)); do
        char1="${string1:i:1}"
        char2="${string2:i:1}"
        result+=$(xor_chars "$(printf '%02X' "'$char1'")" "$(printf '%02X' "'$char2'")")
    done
fi

if [ "$hex_output" = true ]; then
    # Output in hexadecimal
    echo "$result"
elif [ "$binary_output" = true ]; then
    # Output in binary
    binary_result=""
    for ((i = 0; i < ${#result}; i++)); do
        hex_digit="${result:i:1}"
        binary_digit=$(printf '%04d' "$(echo "ibase=16;obase=2;$hex_digit" | bc)")
        binary_result+="$binary_digit"
    done
    echo "$binary_result"
else
    # Output in ASCII
    ascii_result=""
    for ((i = 0; i < ${#result}; i += 2)); do
        hex_byte="${result:i:2}"
        ascii_char=$(printf '\\x%s' "$hex_byte")
        ascii_result+="$ascii_char"
    done
    echo -e "$ascii_result"
fi
