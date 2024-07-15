import random
import hashlib
from sympy import primerange, isprime

# variable for keyGen
# global w, x, y, z,P1, P2, c, d, h, H, sk, pk
p = 191
P1 = 17
Q = 1


print("la valeur de p est : ", p)
# variable for Encrypt
# global u1, u2, e, v , ciphertext


# Direct computation of Lucas sequences for V
def lucas_mod(n, P1, Q, p):
    V0 = 2
    V1 = P1

    if n == 0:
        return V0 % p
    elif n == 1:
        return V1 % p

    for i in range(2, n + 1):
        V2 = (P1 * V1 - Q * V0) % p
        V0, V1 = V1, V2

    return V1


# Utility function to generate a random prime number within a range
def generate_random_prime(min_value, max_value, exclude=[]):
    primes = list(primerange(min_value, max_value))
    primes = [prime for prime in primes if prime not in exclude]
    return random.choice(primes)


# Updated Key generation algorithm using lucas_V
def generate_keys(min_prime, max_prime):
    # Step 1: Choose a prime p and initial values P1 and Q=1


    # Step 2: Choose random prime elements (w, x, y, z) in F_{p^2}^*
    w = generate_random_prime(min_prime, max_prime, exclude=[p, P1])
    x = generate_random_prime(min_prime, max_prime, exclude=[p, P1, w])
    y = generate_random_prime(min_prime, max_prime, exclude=[p, P1, w, x])
    z = generate_random_prime(min_prime, max_prime, exclude=[p, P1, w, x, y])

    # Compute P2, c, d, h
    P2 = lucas_mod(w, P1, Q, p)
    c = lucas_mod(x, P1, Q, p)
    d = lucas_mod(y, P1, Q, p)
    h = lucas_mod(z, P1, Q, p)

    # Step 3: Choose a hash function H
    H = hashlib.sha256

    # Private key
    sk = (w, x, y, z)

    # Public key
    pk = (P1, P2, c, d, h, H)

    return sk, pk



# test keyGen
private_key, public_key = generate_keys(2,p)
sk=private_key
pk=public_key

print("Private Key: (w, x, y, z)= ", sk)
print("Public Key: (P1, P2, c, d, h, H)= ", pk)




# Hash function
def hash_function(*args):
    # Concatenate all arguments and hash them using SHA-256
    hash_input = ''.join(map(str, args)).encode()
    return int(hashlib.sha256(hash_input).hexdigest(), 16)


# Encryption algorithm
def encrypt_message(pk):
  m = 37

  print("le message m est: ", m)


# Step 1: Choose a secret number k
  k = random.randint(1, p)

  print("le secret k est: ", k)


# Step 2: Compute u1, u2, G, e, alpha, v
  u1 = lucas_mod(k, pk[0], Q, p)
  u2 = lucas_mod(k, pk[1], Q, p)

  G = lucas_mod(k, pk[4], Q, p)
  print(" la valeur de G est: ", G)

  e = (G * m) % p
  print(" la valeur de e est: ", e)

  alpha = hash_function(u1, u2, e) % p
  print("alpha est de :", alpha)

  v1=lucas_mod(k, pk[2], Q, p)
  k_alpha= k * alpha
  k_alpha_mod= k_alpha % p
  v2=lucas_mod(k_alpha_mod, pk[3],   Q, p)

  v = (v1 * v2) % p
  ciphertext=(u1, u2, e, v)

# Return the ciphertext
  return ciphertext


# test encryption
ciphertext = encrypt_message(pk)

print("le message chifrré est: (u1, u2, e, v)= ", ciphertext)




# Decryption algorithm
def decrypt_message(sk):

    # Step 1: Pick the secret key sk = (w, x, y, z)

    # Step 2: Verify the conditions: V_w(u1, 1) mod p = u2 and V_x+yα(u1, 1)= v
    # V_x+yα(u1, 1) = V_x(u1, 1) ·V_yα(u1, 1) mod p


    condition1= lucas_mod(sk[0], ciphertext[0], Q, p)
    v_x = lucas_mod(sk[1], ciphertext[0], Q, p)
    alpha = hash_function(ciphertext[0], ciphertext[1], ciphertext[2]) % p

    print("le nouveau alpha est de:", alpha)
    yalpha = (sk[2] * alpha) % p
    v_yalpha = lucas_mod(yalpha, ciphertext[0], Q, p)
    condition2 = (v_x * v_yalpha) % p


    if condition1 == ciphertext[1] and condition2 == ciphertext[3]:
       print("l'algorithme est valid")

       # Step 3: Compute m = e/V_z(u1, 1) mod p

       print(" la valeur de e est: ", ciphertext[2])
       print(" la valeur de V_z(u1, 1) mod p est: ", lucas_mod(sk[3], ciphertext[0], Q, p))

       G_inv = pow(lucas_mod(sk[3], ciphertext[0], Q, p), -1, p)  # Modular inverse of G
       m = (ciphertext[2] * G_inv) % p

       # print("le message clair est : ", m)

       return  m

    else:
       print("le test n'est n'est pas bon")



# test decryption

textclair = decrypt_message(sk)

print(textclair)

