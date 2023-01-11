import hashlib
import secrets
import sys
from pprint import pprint


def main():
    print("We're going to make a lamport signature!")
    print("First, let's generate a private key.")
    print("The private key is two sets of 256 256-bit numbers (512) in total. Hit enter to generate it.")
    input()
    privkey = {0: [secrets.token_bytes(32) for x in range(256)], 1: [secrets.token_bytes(32) for x in range(256)]}
    print("Done! Press enter to see your secret key (in real life, you'd keep it secret)")
    input()
    pprint(privkey)
    print("That's 2 sets of 256 256-bit numbers. That means your private key is 128kB!")
    print("Ok, now to compute the public key, we're going to hash each element in your private key. Hit enter to do "
          "that.")
    input()
    pubkey = {0: [hashlib.sha256(x).hexdigest() for x in privkey[0]],
              1: [hashlib.sha256(y).hexdigest() for y in privkey[1]]}
    print("All done! Hit enter to see the public key. This is what you would send to your counterparty, or publish "
          "publicly.")
    input()
    pprint(pubkey)
    print("Pretty big! The public key is also 128kB!")
    print("Ok! Onto the exciting part. we're going to sign some data!")
    msg_string = input("What string do you want to sign? ")
    msg = hashlib.sha256(msg_string.encode("UTF8"))
    print("First we hash the message: " + msg.hexdigest())
    print("and now for each bit in the message, we're going to pick the corresponding item from privkey[0] if the bit "
          "is a 0, and from privkey[1] if the bit is a 1.")
    print("hit enter to do that and see the signature")
    input()
    signature = [0 for i in range(256)]
    msg = int.from_bytes(msg.digest(), sys.byteorder)  # picking big endian arbitrarily.
    for i in range(256):
        x = msg >> i & 1  # set x to the ith bit (either 1 or 0)
        signature[i] = privkey[x][i]
    print("Here's the signature: ")
    pprint(signature)
    print("Pretty huge right!? It's 256 256-bit numbers, so that's a 64kB signature!")
    print("Now let's verify the signature with the public key!")
    print("How that works is we're going to we're going to pick the corresponding item from pubkey[0] if the bit "
          "is a 0, and from pubkey[1] if the bit is a 1.")
    print("In other words, its the same selection process that we just did to make the signature, but we're pulling "
          "from the pubkey instead of the privkey")
    print("And then for each of these pubkey entries, we'll make sure that the corresponding entry in the signature "
          "hashes to the pubkey entry")
    print("Hit enter to do that")
    input()
    for i in range(256):
        print("Checking bit " + str(i))
        x = msg >> i & 1  # set x to the ith bit (either 1 or 0)
        pubkey_value = pubkey[x][i]
        signature_value = signature[i]
        if hashlib.sha256(signature_value).hexdigest() != pubkey_value:
            print("BAD SIGNATURE!")
            return
    print("Signature is valid!")
    print("Hope you had fun. I sure did!")


if __name__ == '__main__':
    main()
