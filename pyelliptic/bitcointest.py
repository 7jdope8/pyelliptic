import bitcoin as b
import hashlib

priv = hashlib.sha256('correct horse battery staple').hexdigest()
pub = b.privToPub(priv)

c = b.encrypt('123',pub)
d = b.decrypt(c,priv)

assert d == '123'

print "Encryption seems to work"

s = b.sign('123',priv)

assert b.verify('123',s,pub)

print "Signing and verification seems to work"
