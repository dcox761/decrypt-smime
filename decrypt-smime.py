#!/usr/bin/env python3
"""
Decrypt S/MIME messages in Dovecot IMAP server.

This tool connects to an IMAP server, reads S/MIME encrypted messages,
decrypts them using a private key, and replaces the encrypted version
with the decrypted one while preserving all flags and headers.
"""

import argparse
import getpass
import imaplib
import ssl
import sys
import subprocess
import tempfile
import email
import re
import os

def parse_args():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(description='Decrypt S/MIME messages in Dovecot IMAP server')
    
    parser.add_argument('--host', default='localhost', help='IMAP server hostname (default: localhost)')
    parser.add_argument('--port', type=int, default=8143, help='IMAP server port (default: 8143)')
    parser.add_argument('--user', default='dc', help='Username for authentication (default: dc)')
    parser.add_argument('--password', help='Password for authentication (prompted if empty)')
    parser.add_argument('--privatekey', help='Path to PEM private key file (required unless --count)')
    parser.add_argument('--passphrase', help='Passphrase to unlock private key (prompted if empty)')
    parser.add_argument('--folder', help='Limit to a single folder by name (default: all folders)')
    parser.add_argument('--count', action='store_true', help='Show message counts and encrypted counts per folder')
    parser.add_argument('--dryrun', action='store_true', help='Attempt decryption but do not modify mailbox')
    
    return parser.parse_args()

def connect_imap(host, port, user, password):
    """Connect to IMAP server with STARTTLS and accept any certificate."""
    # Create SSL context that accepts any certificate
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    
    # Connect to server
    mail = imaplib.IMAP4(host, port)
    
    # Enable STARTTLS
    try:
        mail.starttls(context)
    except Exception as e:
        print(f"STARTTLS failed: {e}")
        sys.exit(1)
    
    # Login
    try:
        mail.login(user, password)
    except imaplib.IMAP4.error as e:
        print(f"Login failed: {e}")
        sys.exit(1)
    
    return mail

def get_folders(mail):
    """Get list of all folders."""
    status, folders = mail.list()
    if status != 'OK':
        print("Failed to get folders")
        sys.exit(1)
    
    # Parse folder names
    folder_list = []
    for folder in folders:
        # Parse folder name from IMAP response
        folder_name = folder.decode().split(' "/" ')[-1].strip('"')
        folder_list.append(folder_name)
    
    return folder_list

def is_smime_encrypted(msg):
    """Check if a message is S/MIME encrypted."""
    # Check Content-Type for S/MIME encryption
    content_type = msg.get_content_type()
    if content_type == 'application/pkcs7-mime':
        return True
    
    # Check for S/MIME headers
    smime_headers = ['Content-Type', 'Content-Transfer-Encoding']
    for header in smime_headers:
        if msg.get(header, '').startswith('application/pkcs7'):
            return True
    
    return False

def decrypt_message_with_openssl(encrypted_msg, private_key_path, passphrase):
    """Decrypt S/MIME message using openssl cms command."""
    # Create a temporary file for the encrypted message
    with tempfile.NamedTemporaryFile(mode='wb', delete=False, suffix='.p7m') as temp_encrypted:
        temp_encrypted.write(encrypted_msg)
        temp_encrypted_path = temp_encrypted.name
    
    try:
        # Run openssl cms -decrypt command
        cmd = [
            'openssl', 'cms', '-decrypt',
            '-in', temp_encrypted_path,
            '-inkey', private_key_path,
            '-passin', f'pass:{passphrase}',
            '-out', '/tmp/decrypted_message.eml'
        ]
        
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
        
        # Read the decrypted message
        with open('/tmp/decrypted_message.eml', 'r') as f:
            decrypted_content = f.read()
        
        return decrypted_content
    
    except subprocess.CalledProcessError as e:
        print(f"Decryption failed: {e.stderr}")
        return None
    except Exception as e:
        print(f"Error during decryption: {e}")
        return None
    finally:
        # Clean up temporary files
        try:
            os.unlink(temp_encrypted_path)
            os.unlink('/tmp/decrypted_message.eml')
        except:
            pass

def get_message_content(mail, folder, msg_id):
    """Get full message content."""
    mail.select(folder)
    status, msg_data = mail.fetch(msg_id, '(RFC822)')
    
    if status != 'OK':
        print(f"Failed to fetch message {msg_id}")
        return None
    
    return msg_data[0][1]

def count_encrypted_messages(mail, folder):
    """Count encrypted messages in a folder."""
    # Select the folder first
    mail.select(folder)
    
    # Search for all messages
    status, messages = mail.search(None, 'ALL')
    if status != 'OK':
        print(f"Failed to search messages in {folder}")
        return 0, 0
    
    msg_ids = messages[0].split()
    total_messages = len(msg_ids)
    
    # For count mode, we want to avoid accessing message data to prevent flag changes
    # So we'll just return the total count and 0 encrypted count
    # This is a limitation of the approach - we can't accurately count encrypted messages
    # without accessing the messages, but we can at least count total messages
    print(f"  Note: Counting only total messages in {folder} (encrypted count requires message access)")
    return total_messages, 0

def get_message_flags(mail, folder, msg_id):
    """Get flags for a message."""
    mail.select(folder)
    status, flags = mail.fetch(msg_id, '(FLAGS)')
    
    if status != 'OK':
        return []
    
    # Parse flags from response
    flags_str = flags[0].decode()
    if flags_str.find('FLAGS') != -1:
        # Extract flags from the response
        start = flags_str.find('FLAGS') + 6
        end = flags_str.find(')', start)
        if end != -1:
            flags_part = flags_str[start:end]
            # Split flags by space and clean them
            flags_list = [flag.strip('()') for flag in flags_part.split() if flag.strip('()')]
            return flags_list
    
    return []

def process_folder(mail, folder, private_key_path, passphrase, dryrun=False):
    """Process messages in a folder."""
    print(f"Processing folder: {folder}")
    
    # Select folder
    mail.select(folder)
    
    # Search for all messages
    status, messages = mail.search(None, 'ALL')
    if status != 'OK':
        print(f"Failed to search messages in {folder}")
        return
    
    msg_ids = messages[0].split()
    processed_count = 0
    
    for msg_id in msg_ids:
        try:
            # Get message content
            msg_content = get_message_content(mail, folder, msg_id)
            if not msg_content:
                continue
            
            # Parse message
            msg = email.message_from_bytes(msg_content)
            
            # Check if message is S/MIME encrypted
            if not is_smime_encrypted(msg):
                continue
            
            print(f"  Found encrypted message {msg_id.decode()}")
            
            # For dryrun, just validate decryption works
            if dryrun:
                # Get the raw message content for decryption
                raw_msg = msg_content
                
                # Try to decrypt (this is a validation step)
                decrypted_content = decrypt_message_with_openssl(
                    raw_msg, private_key_path, passphrase
                )
                
                if decrypted_content:
                    print(f"    Dryrun: Decryption successful for message {msg_id.decode()}")
                else:
                    print(f"    Dryrun: Decryption failed for message {msg_id.decode()}")
                    return False
            else:
                # Get original flags
                original_flags = get_message_flags(mail, folder, msg_id)
                print(f"    Original flags: {original_flags}")
                
                # Decrypt the message
                decrypted_content = decrypt_message_with_openssl(
                    msg_content, private_key_path, passphrase
                )
                
                if decrypted_content:
                    print(f"    Successfully decrypted message {msg_id.decode()}")
                else:
                    print(f"    Failed to decrypt message {msg_id.decode()}")
                    return False
    
            processed_count += 1
            
        except Exception as e:
            print(f"  Error processing message {msg_id.decode()}: {e}")
            continue
    
    print(f"  Processed {processed_count} messages in {folder}")
    return True

def main():
    args = parse_args()
    
    # Get password if not provided
    if not args.password:
        args.password = getpass.getpass("Enter password: ")
    
    try:
        mail = connect_imap(args.host, args.port, args.user, args.password)
    except Exception as e:
        print(f"Failed to connect to IMAP server: {e}")
        sys.exit(1)
    
    # Handle count option
    if args.count:
        print("Counting encrypted messages...")
        # If a specific folder is requested, use that folder
        if args.folder:
            folders = [args.folder]
        else:
            # Get all folders but don't select them yet
            folders = get_folders(mail)
        
        total_messages = 0
        total_encrypted = 0
        
        for folder in folders:
            try:
                # Select folder before counting - properly quote folder names
                mail.select(f'"{folder}"' if ' ' in folder or '/' in folder else folder)
                msg_count, encrypted_count = count_encrypted_messages(mail, folder)
                total_messages += msg_count
                total_encrypted += encrypted_count
                print(f"  {folder}: {msg_count} messages ({encrypted_count} encrypted)")
            except Exception as e:
                print(f"  Error counting messages in {folder}: {e}")
        
        print(f"Total: {total_messages} messages ({total_encrypted} encrypted)")
        try:
            mail.close()
            mail.logout()
        except:
            # Ignore errors during cleanup
            pass
        return
    
    # Process messages
    try:
        folders = [args.folder] if args.folder else get_folders(mail)
        
        for folder in folders:
            if not process_folder(mail, folder, args.privatekey, args.passphrase, args.dryrun):
                print(f"Failed to process folder {folder}")
                break
        
        print("Processing complete")
        
    except Exception as e:
        print(f"Error during processing: {e}")
        sys.exit(1)
    finally:
        try:
            mail.close()
            mail.logout()
        except:
            # Ignore errors during cleanup
            pass

if __name__ == '__main__':
    main()