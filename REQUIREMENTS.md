# Requirements

## Background

I have recently moved to Stalwart mail server and enabled its unique transparent S/MIME encryption feature on my account. All my emails were synced with imapsync and transparently encrypted. This is a very promising capability that works well on macOS Apple Mail and reasonably well on Thunderbird, with only minor issues (it refuses to show images for encrypted messages and defaults to sending with encryption enabled).

However, iOS Mail intermittently shows `This message has not been downloaded from server` for some encrypted messages which can then not be viewed at all. There are lots of possible solutions shown for this issue which do not work reliably. Outlook does not support S/MIME without Enterprise Deployment, so there is currently no alternative client on iOS.

Searching does not work very well and SPAM filtering is possibly affected. At least it is not possible to rebuild each.

I have used offlineimap to sync my Stalwart account to a local Maildir and setup Dovecot in a container to make it available with IMAP protocol. My plan is to decrypt all my messages locally and then transfer back to Stalwart.

## Functional Requirements

1. Provide CLI arguments for host (localhost), port (8143), user (dc), password (password), privatekey, passphrase
1. Use STARTTLS
1. Accept any certificate including self-signed
1. Read ALL folders including unsubscribed, skipping non-selectable folders (`\Noselect`, `\NonExistent`)
1. Optionally limit to a single folder by name
1. Count option to show a count of messages for each folder and count of emails that are still S/MIME encrypted — does not require privatekey
1. Dryrun option to decrypt each message without modifying the mailbox
1. Exit with an error if decryption fails
1. Provide an option to ignore errors even in dryrun mode
1. Provide an option to move failed messages to (a possibly new folder) of the same name with .failed suffix
1. Dryrun should not make any changes including moving failed messages
1. Provide identifying information for any message with decryption errors, eg. date/time, subject, from address
1. Preserve all flags and headers on the message
1. Save the unencrypted version via IMAP APPEND to the same folder
1. Mark the original for deletion with STORE +FLAGS (\Deleted)
1. Message flags should not be changed on existing messages except when deleted
1. Private keys may not be encrypted, ignore passphrase if provided
1. Use Python in ~/.env
1. Handle Ctrl-C nicely
1. Show a nice Exception message if anything goes wrong
1. Additional (multiple extra) privatekey and passphrase options can be provided and should be attempted in order if it looks like the private key is cause of decryption failure, ie. support privatekey/passphrase, privatekey2/passphrase2
1. Only encrypted messages should be replaced
1. Skip deleted messages even if encrypted
1. CLOSE the folder after processing to expunge all messages marked \Deleted
1. Support parallel decryption within each folder via `--workers`
1. Support parallel folder processing with independent IMAP connections via `--connections`
1. Provide `--debug` option to show timestamped trace output for every IMAP operation
1. Filter `\Recent` from flags before APPEND (server-managed flag per RFC 3501)
1. Filter `\Deleted` from flags before APPEND so decrypted copies are not immediately marked for deletion
1. Quote folder names containing spaces in IMAP APPEND commands

## Clarification

S/MIME detection via Content-Type pkcs7-mime is correct. Key is PEM with optional passphrase. Use Python cryptography library for key validation, openssl cms for decryption. Save means IMAP APPEND to same folder then mark original \Deleted.
