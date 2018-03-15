# Overview

PassLocker creates a password repository.

# View help

		passlocker help

# Listing Accounts

		passlocker list

# Get information on a named account

		passlocker info "test account"
		passlocker info hex 74657374206163636f756e74
		passlocker info b64 dGVzdCBhY2NvdW50Cg==

# Get the active password on a named account

		passlocker get "test account"

# Add a simple password-based account

		passlocker add "test account 2" password

# Add a One-Time-Password account

		passlocker add "otp account" otp

# Add a Time-based One-Time-Password account

		passlocker add "totp account" totp [start_time] [interval] [num_digits] [hash_algo]

# Set the username for an account

		passlocker user "test account 2" "<username>"

# Add a note to an account

		passlocker note "test account 2" "<note>"

# Add a password to a password account 

		passlocker pw "test account 2" [raw|hex|b64] [file <filename>]

# Add OTP passwords

		passlocker pw "otp account" [raw|hex|b64] [file <filename>]

# Add a TOTP secret

		passlocker pw "totp account" [raw|hex|b64] [file <filename>]


