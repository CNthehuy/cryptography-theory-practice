# **Submit a PDF of these questions for final submission, not the Markdown**
### _Answers will be added later by Chris and PDF will be pushed later_  
1.1a:   
_The One Time Pad (OTP) encryption is highly secure, but why do we not see it much in practice? Explain at least two reasons (some discussed in class!)_  
One Time Pad is not seen much in practice because the key must be the same size as the message, and the encryption uses TRNGs which are slow to generate. Because the key must be the same size as the message, a 5 GB message would need to have a 5 GB key. This means you would need access to some secure communication to send a 5 GB key before you encrypt and send the encoded message. Additionally, the use of TRNGs means that, while having true randomness, generating keys is very slow and expensive due to needing additional hardware.  
  
1.1b:  
_Why does an ideal OTP encryption achieve information-theoretical security?_  
OTP encryption gives information-theoretical security because the attacker may know the ciphertext, but because the key is truly random, secret, and used once, the ciphertext gives no information about the message, so $C = M \oplus K$ where both M, message, and K, key, are both unknown.  

1.2:  
_What is the birthday attack against hash functions? Given an n-bit hash output, mathematically formulate the upper bound of collision probability of it. Specifically, write how the birthday paradox is formulated. You can use approximations if needed._  
The birthday attack against hash functions is finding collisions in hash functions, then taking advantage of the collision by changing the message while preserving the original hash.  
If we have $k$ messages, the probability of at least one collision is   
$P_{collision} \approx 1 - e^{-\frac{k(k-1)}{2^{n+1}}} \approx \frac{k(k-1)}{2^{n+1}}$  
$\frac{k(k-1)}{2^{n+1}} \approx 1$ -> $k^2 \approx 2^{n+1}$ -> $k \approx \sqrt{2^{n+1}}$ -> $k \approx 2^\frac{n+1}{2}$ -> $k \approx \sqrt{2}\cdot 2^\frac{n}{2}$ -> $k \approx 2^\frac{n}{2}$  

1.3:  
_What is Kerckhoffs’s principle in modern cryptography? Write 2-3 paragraphs of explanation and why it is important._  
Kerckoffs’s principle is that a system should be secure even if everything, but the key, is public. Basically, even if the attacker knows the ciphertext and encryption algorithm, the attacker shouldn’t be able to break the encryption and view the message without the key. 
This is important because encryption algorithms are public already, which means they can continue to be used to secure data. Additionally, this means that these algorithms can be viewed by anyone and tested for vulnerabilities, while maintaining the security of systems currently using those algorithms. This principle also goes against protecting systems by hiding features because it is more likely those features will be exposed at some point, so it is better to ensure security even when exposed.  

1.4:  
_Describe the Kerberos and Needham-Schroeder protocols, specifically touching on how the two are related and how they function as challenge-response protocols. Write 2-3 paragraphs of explanation._  
The Needham-Schroeder protocol authenticates two parties by using a trusted third party. The two parties communicate with the third party to get a shared session key. In terms of challenge-response, one party sends a nonce, and the receiver sends a secret key to prove its identity. 
The Kerberos protocol is a derivative of the Needham-Schroeder protocol that uses tickets and a third party to verify the sender and receiver’s identity on an open network. Kerberos uses a Key Distribution Center to authenticate users. The KDC distributes tickets and keys. These tickets and keys are then used to authenticate each party’s identity without sending passwords.  