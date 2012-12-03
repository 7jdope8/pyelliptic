import ecdsa

def sign_message(self, privkey, message):
    private_key = ecdsa.SigningKey.from_string( self.get_private_key(address, password), curve = SECP256k1 )
    public_key = private_key.get_verifying_key()
    signature = private_key.sign_digest( Hash( self.msg_magic( message ) ), sigencode = ecdsa.util.sigencode_string )
    assert public_key.verify_digest( signature, Hash( self.msg_magic( message ) ), sigdecode = ecdsa.util.sigdecode_string)
    for i in range(4):
        sig = base64.b64encode( chr(27+i) + signature )
        try:
            self.verify_message( address, sig, message)
            return sig
        except:
            continue
    else:
        raise BaseException("error: cannot sign message")


def verify_message(self, address, signature, message):
    """ See http://www.secg.org/download/aid-780/sec1-v2.pdf for the math """
    from ecdsa import numbertheory, ellipticcurve, util
    import msqr
    curve = curve_secp256k1
    G = generator_secp256k1
    order = G.order()
    # extract r,s from signature
    sig = base64.b64decode(signature)
    if len(sig) != 65: raise BaseException("Wrong encoding")
    r,s = util.sigdecode_string(sig[1:], order)
    nV = ord(sig[0])
    if nV < 27 or nV >= 35:
        raise BaseException("Bad encoding")
    if nV >= 31:
        compressed = True
        nV -= 4
    else:
        compressed = False

    recid = nV - 27
    # 1.1
    x = r + (recid/2) * order
    # 1.3
    alpha = ( x * x * x  + curve.a() * x + curve.b() ) % curve.p()
    beta = msqr.modular_sqrt(alpha, curve.p())
    y = beta if (beta - recid) % 2 == 0 else curve.p() - beta
    # 1.4 the constructor checks that nR is at infinity
    R = ellipticcurve.Point(curve, x, y, order)
    # 1.5 compute e from message:
    h = Hash( self.msg_magic( message ) )
    e = string_to_number(h)
    minus_e = -e % order
    # 1.6 compute Q = r^-1 (sR - eG)
    inv_r = numbertheory.inverse_mod(r,order)
    Q = inv_r * ( s * R + minus_e * G )
    public_key = ecdsa.VerifyingKey.from_public_point( Q, curve = SECP256k1 )
    # check that Q is the public key
    public_key.verify_digest( sig[1:], h, sigdecode = ecdsa.util.sigdecode_string)
    # check that we get the original signing address
    addr = public_key_to_bc_address( encode_point(public_key, compressed) )
    if address != addr:
        raise BaseException("Bad signature")



