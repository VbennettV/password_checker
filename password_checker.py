"""
This is the most secure way to check whether your password has ever been hacked.
It is also able to check as many passwrod as you want.
Although it has a website, but when you check your password from a website, it will transfer to a server through wire. Someone could intercept it in the middle.
So the most secure way is to use the API and make the program yourself.
How it works?
It uses a website called https://haveibeenpwned.com/
"""

import requests #enable use to manually request something and have the data back.
import hashlib
import sys

"""
Cannot put password as plain english. You need hash it.
This is the tool used https://passwordsgenerator.net/sha1-hash-generator/
Hashing is a one way algorithm, always store data in Hash. There are many algoritms, the one the website used is SHA1.
Why website used the hashed password is also for security reason as well. Never seend the password in plain text throught the wire.
In additon to hashing the passwrod, the website use a modern technique called k anonymity, lots of big companys are using this tech. 
It returns you all the matching hashed passwords with first 5 characters. After received the response, then we can check the hashed function.
K anonymity enables you to stay anomymous.
"""

def request_api_data(query_char):
    url = 'https://api.pwnedpasswords.com/range/' + query_char
    res = requests.get(url)
    if res.status_code != 200:
        raise RuntimeError(f'Error fetching: {res.status_code}, check the api and try again.')
    else:
        return res

def get_password_leaks_count(hashes, hash_to_check):
    hashes = (line.split(':') for line in hashes.text.splitlines())
    for h, count in hashes:
        if h == hash_to_check:
            return count
    return 0 # Actually this 0 can be commented out.

def pwned_api_check(password):
    sha1password = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    first5_char, tail = sha1password[:5], sha1password[5:]
    response = request_api_data(first5_char)
    return get_password_leaks_count(response, tail)

print(pwned_api_check('123'))

def main(args):
    for password in args:
        count = pwned_api_check(password)
        if count:
            print(f'{password} was found {count} times... you should probably change your passwrods')
        else:
            print(f'{password} was not found. Carry on! ')
    return "done!"

with open('Password to check.txt', 'r') as file:
    password_queue = file.read().splitlines()

if __name__ == '__main__':
    sys.exit(main(password_queue))
