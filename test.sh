#!/bin/bash -eE
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

set -o pipefail
shopt -s inherit_errexit

unset WORK_DIR CANONICAL FAILURE

trap tearDown EXIT

. des-string-to-key.sh

main() {
	beforeAll

	testCase n1200
	testCase 12345678
	testCase 123456789
	testCase abcdefghijklmnopqrstuvwxyz

	[[ -z $FAILURE ]]
}

beforeAll() {
	WORK_DIR="$(mktemp -d --tmpdir bash-test-des-string-to-key.XXXXXXXX)"
	CANONICAL="$(buildCanonical)"
}

buildCanonical() {
	local executable="$WORK_DIR/canonical"

	# C code modified from: https://www.adrian.idv.hk/2007-08-08-firmware/
	gcc -x c -o "$executable" -lssl -lcrypto - <<<'
		#include <openssl/des.h>
		#include <stdio.h>

		int main(int argc, char** argv) {
			DES_cblock key;
			DES_string_to_key(argv[1], &key);
			printf("%02x%02x%02x%02x%02x%02x%02x%02x\n",
				key[0], key[1], key[2], key[3], key[4], key[5], key[6], key[7]
			);
			return 0;
		}
	'

	echo "$executable"
}

testCase() {
	local str="$1"

	local expected=$("$CANONICAL" "$str")
	local actual=$(DES_string_to_key "$str")

	if [[ "$actual" == "$expected" ]]; then
		echo -ne '\e[32;1m\u2714\e[0m '
		echo "$str"
	else
		echo -ne '\e[31;1m\u2718\e[0m '
		echo "$str: Expected $expected, got $actual"
		FAILURE=1
	fi
}

tearDown() {
	if [[ -n "$WORK_DIR" ]]; then
		rm -rf "$WORK_DIR"
	fi
}

main "$@"
