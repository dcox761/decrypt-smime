#!/bin/sh
# /mnt/config/write-keywords.sh

find /mnt/mail/account -name cur -type d | while read cur_dir; do
    cat << 'EOF' > "$(dirname "$cur_dir")/dovecot-keywords"
0 $Forwarded
1 Forwarded
2 $MDNSent
3 $label1
4 $Label1
5 $Label4
6 $label5
7 receipt-handled
8 NonJunk
9 $NotJunk
10 $Junk
11 Junk
12 NotJunk
13 $MailFlagBit0
EOF
done
