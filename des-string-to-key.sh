#!/bin/bash
####
#
#   Copyright 2020 Perihelios LLC
#
#   Licensed under the Apache License, Version 2.0 (the "License");
#   you may not use this file except in compliance with the License.
#   You may obtain a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS,
#   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#   See the License for the specific language governing permissions and
#   limitations under the License.
#
####
#
#   Based on crypto/des/str2key.c from OpenSSL, which is:
#
#   Copyright 1995-2016 The OpenSSL Project Authors. All Rights Reserved.
#
#   Licensed under the Apache License 2.0 (the "License").  You may not use
#   this file except in compliance with the License.  You can obtain a copy
#   in the file LICENSE in the source distribution or at
#   https://www.openssl.org/source/license.html
#
####
#   Obtainable from: https://github.com/perihelios/bash-des-string-to-key
####

## Recommended Bash options (for any Bash script, really):
#
# set -e
# set -E
# shopt -s inherit_errexit
# set -o pipefail

DES_string_to_key() {
	local str="$1"

	local -a plaintextKey
	plaintextKey=($(charToArray "$str"))

	local -a digestKey=(0 0 0 0 0 0 0 0)
	local i

	for ((i = 0; i < ${#plaintextKey[@]}; i++)); do
		local index=$((i % 8))
		local n=${plaintextKey[$i]}

		if [[ $((i % 16)) -lt 8 ]]; then
	    		digestKey[$index]=$(((digestKey[index] ^ (n << 1)) & 0xff))
		else
			n=$(( ((n << 4) & 0xf0) | ((n >> 4) & 0x0f) ))
			n=$(( ((n << 2) & 0xcc) | ((n >> 2) & 0x33) ))
			n=$(( ((n << 1) & 0xaa) | ((n >> 1) & 0x55) ))
			index=$((7 - index))
			digestKey[$index]=$((digestKey[index] ^ n));
		fi
	done

	digestKey=($(arrayForceOddParity ${digestKey[@]}))

	# OpenSSL's DES_string_to_key calls DES_cbc_cksum, which always pads to block size
	#  with zeros. The OpenSSL des-cbc command, on the other hand, pads using PKCS#5.
	#  To use des-cbc while getting results like DES_cbc_cksum, prepad with zeros.
	#  Note that there will ALWAYS be an extraneous trailing block from des-cbc in this
	#  case, since PKCS#5 will pad data evenly divisible by block size with an extra
	#  block.
	local -a zeroPaddedKey
	zeroPaddedKey=($(arrayZeroPadToAlignment 8 ${plaintextKey[@]}))

	local -a encryptedKey 
	encryptedKey=($(
		arrayToBinary ${zeroPaddedKey[@]} |
			openssl des-cbc -K $(arrayToHex ${digestKey[@]}) -iv $(arrayToHex ${digestKey[@]}) |
			od -t d1 -A n -w${#zeroPaddedKey[@]} -N ${#zeroPaddedKey[@]}
	))

	arrayToHex $(arrayForceOddParity $(arrayRange $((${#encryptedKey[@]} - 8)) ${#encryptedKey[@]} ${encryptedKey[@]}))
}

arrayZeroPadToAlignment() {
	local alignment="$1"
	shift
	local -a data=("$@")

	local padding=$(( (alignment - ${#data[@]} % alignment) % alignment ))

	echo -n "${data[@]}"
	
	while [[ $padding -gt 0 ]]; do
		echo -n ' 0'
		padding=$(( padding - 1 ))
	done
}

arrayToBinary() {
	local -a data=("$@")

	if [[ ${#data[@]} -eq 0 ]]; then return; fi

	printf $(printf '\\x%02x' "${data[@]}")
}

charToArray() {
	local characters="$1"

	echo -n "$characters" | od -t d1 -A n -w${#characters}
}

arrayToHex() {
	local -a HEX=(0 1 2 3 4 5 6 7 8 9 a b c d e f)

	while [[ $# -gt 0 ]]; do
		c=$1
		c=$(((c >> 4) & 0xf))

		echo -n "${HEX[c]}"

		c=$1
		c=$((c & 0xf))

		echo -n "${HEX[c]}"
		shift
	done

	echo
}

arrayRange() {
	local startInclusive="$1"
	local endExclusive="$2"
	shift 2
	local array=("$@")

	local i
	for ((i = startInclusive; i < endExclusive; i++)); do
		echo -n "${array[$i]} "
	done
}

arrayForceOddParity() {
	while [[ $# -gt 0 ]]; do
		local n=$1
		shift

		local parity=0
		local odd=0

		if ((n & 0x80)); then let ++parity; fi
		if ((n & 0x40)); then let ++parity; fi
		if ((n & 0x20)); then let ++parity; fi
		if ((n & 0x10)); then let ++parity; fi
		if ((n & 0x08)); then let ++parity; fi
		if ((n & 0x04)); then let ++parity; fi
		if ((n & 0x02)); then let ++parity; fi
		if ((n & 0x01)); then
			let ++parity
			odd=1
		fi

		if ! ((parity & 1)); then
			if ((odd)); then
				echo -n $((n - 1))
			else
				echo -n $((n + 1))
			fi
		else
			echo -n $n
		fi

		echo ' '
	done
}
