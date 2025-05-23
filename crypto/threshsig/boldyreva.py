"""An implementation of (unique) threshold signatures based on
Gap-Diffie-Hellman Boldyreva, 2002 https://eprint.iacr.org/2002/118.pdf

Dependencies:
    Charm, http://jhuisi.github.io/charm/ a wrapper for PBC (Pairing
    based crypto)

"""
try:
    # < python 3.8
    # Deprecated since version 3.1.
    from base64 import encodestring, decodestring 
except:
    # >= python 3.9
    from base64 import encodebytes as encodestring, decodebytes as decodestring

try:
    from charm.toolbox.pairinggroup import PairingGroup, ZR, G1, G2, pair
    from charm.core.math.pairing import pc_element, serialize as charm_serialize, deserialize as charm_deserialize
    #from charm.core.math.pairing import pairing,pc_element,ZR,G1,G2,GT,init,pair,hashPair,H,random,,ismember,order
    from operator import mul
    from functools import reduce
except Exception as err:
    print(err)
    exit(-1)


# group = PairingGroup('SS512')
# group = PairingGroup('MNT159')
group = PairingGroup('MNT224')

def ismember(g):
    return group.ismember(g)

def g12serialize(g):
    return group.serialize(g, compression=True)


def g12deserialize(g):
    return group.deserialize(g, compression=True)


def serialize(g):
    """ """
    # Only work in G1 here
    return decodestring(group.serialize(g)[2:])


def deserialize0(g):
    """ """
    # Only work in G0 here
    return group.deserialize(b'0:'+encodestring(g))


def deserialize1(g):
    """ """
    # Only work in G1 here
    return group.deserialize(b'1:'+encodestring(g))


def deserialize2(g):
    """ """
    # Only work in G2 here
    return group.deserialize(b'2:'+encodestring(g))

g1 = group.deserialize(b'1:Hw8fQ59CfkFyNR2rGK5BLWSfwfxAlFMA89IkTAE=')
g1.initPP()
g2 = group.deserialize(b'2:Plp1Jb6RDCvLNI6RGCQAuZghgJcwml/93322Nh0sZdVnwIFKYsOxxgFtg416U2vl/RIUfPT0ShEVekx6xXYIMhoV+CTwlViWtd7hQE//azdpwtOFAQ==')
g2.initPP()
#g1 = group.hash('geng1', G1)
#g1.initPP()
# g2 = g1
#g2 = group.hash('geng2', G2)
#g2.initPP()
ZERO = group.random(ZR, seed=59)*0
ONE = group.random(ZR, seed=60)*0+1


def polynom_eval(x, coefficients):
    """Polynomial evaluation."""
    y = ZERO
    xx = ONE
    for coeff in coefficients:
        y += coeff * xx
        xx *= x
    return y


# class TBLSPairingElement(object):
#     def __init__(self, element):
#         self.element = element
#         self.serialization_cache = decodestring(group.serialize(self.element))
#         self.G = self.serialization_cache[:2]
    
#     def __getstate__(self):
#         """ """
#         d = dict(self.__dict__).copy()
#         del d['element']
#         return d

#     def __setstate__(self, d):
#         """ """
#         self.__dict__ = d
#         self.element = group.deserialize(encodestring(self.serialization_cache))
    
#     def __repr__(self) -> str:
#         return str(self.G) + str(self.serialization_cache)

# class TBLSPairingElement(object):
#     def __init__(self, element):
#         self.element = element
#         self.serialization_cache = charm_serialize(element, True)
#         self.G = self.serialization_cache[:2]
    
#     def __getstate__(self):
#         """ """
#         d = dict(self.__dict__).copy()
#         del d['element']
#         return d

#     def __setstate__(self, d):
#         """ """
#         self.__dict__ = d
#         self.element = charm_deserialize(G1, self.serialization_cache, True)
    
#     def __repr__(self) -> str:
#         return str(self.G) + str(self.serialization_cache)

# class TBLSPairingElement(object):
#     def __init__(self, element):
#         self.element = element
#         self.serialization_cache = serialize(self.element)
    
#     def __getstate__(self):
#         """ """
#         d = dict(self.__dict__).copy()
#         del d['element']
#         return d

#     def __setstate__(self, d):
#         """ """
#         self.__dict__ = d
#         self.element = deserialize1(self.serialization_cache)
    
#     # def __repr__(self) -> str:
#     #     return str(self.serialization_cache)

# class TBLSPairingElement(object):
#     def __init__(self, element):
#         self.element = element
    
#     def __getstate__(self):
#         """ """
#         d = dict(self.__dict__)
#         d['element'] = serialize(self.element)
#         return d

#     def __setstate__(self, d):
#         """ """
#         self.__dict__ = d
#         self.element = deserialize1(self.element)
    
#     # def __repr__(self) -> str:
#     #     return str(serialize(self.element))

class TBLSPublicKey(object):
    """ """
    def __init__(self, l, k, VK, VKs):
        """ """
        self.l = l  # noqa: E741
        self.k = k
        self.VK = VK
        self.VKs = VKs

    def __getstate__(self):
        """ """
        d = dict(self.__dict__)
        d['l'] = self.l
        d['k'] = self.k
        d['VK'] = serialize(self.VK)
        d['VKs'] = list(map(serialize, self.VKs))
        return d

    def __setstate__(self, d):
        """ """
        self.__dict__ = d
        self.VK = deserialize2(self.VK)
        self.VKs = list(map(deserialize2, self.VKs))
        # print("PK of Thld Sig is depickled")

    def lagrange(self, S, j):
        """ """
        # Assert S is a subset of range(0,self.l)
        assert len(S) == self.k
        assert type(S) is set
        assert S.issubset(range(0, self.l))
        S = sorted(S)

        assert j in S
        assert 0 <= j < self.l
        num = reduce(mul, [0 - jj - 1 for jj in S if jj != j], ONE)
        den = reduce(mul, [j - jj     for jj in S if jj != j], ONE)  # noqa: E272
        # assert num % den == 0
        return num / den

    def hash_message(self, m):
        """ """
        try:
            m = m.encode()
        except:
            pass
        return group.hash(m, G1)

    def verify_share(self, sig, i, h, allow_pickle=False):
        """ """
        assert 0 <= i < self.l
        B = self.VKs[i]
        # if isinstance(sig, TBLSPairingElement):
        #     sig = sig.element
        if isinstance(sig, bytes):
            sig = deserialize1(sig)
        assert isinstance(sig, pc_element), type(sig)
        assert isinstance(h, pc_element), type(h)
        assert pair(sig, g2) == pair(h, B)
        return True

    def verify_signature(self, sig, h, allow_pickle=False):
        """ """
        # if isinstance(sig, TBLSPairingElement):
        #     sig = sig.element
        if isinstance(sig, bytes):
            sig = deserialize1(sig)
        assert isinstance(sig, pc_element), type(sig)
        assert isinstance(h, pc_element), type(h)
        # assert False, f"{sig} {h} {self.VK}"
        assert pair(sig, g2) == pair(h, self.VK)
        return True

    def combine_shares(self, sigs, allow_pickle=False):
        """ """
        # sigs: a mapping from idx -> sig
        S = set(sigs.keys())
        assert S.issubset(range(self.l))

        for j in S:
            # if isinstance(sigs[j], TBLSPairingElement):
            #     sigs[j] = sigs[j].element
            if isinstance(sigs[j], bytes):
                sigs[j] = deserialize1(sigs[j])
        
        res = reduce(mul,
                     [sig ** self.lagrange(S, j)
                      for j, sig in sigs.items()], 1)
        if allow_pickle:
            return serialize(res)
        return res

        # res = 1
        # for j, sig in sigs.items():
        #     if allow_pickle and isinstance(sig, TBLSPairingElement):
        #         sig = sig.element
        #     res *= sig ** self.lagrange(S, j)
        

        
        


class TBLSPrivateKey(TBLSPublicKey):
    """ """

    def __init__(self, l, k, VK, VKs, SK, i):
        """ """
        super(TBLSPrivateKey, self).__init__(l, k, VK, VKs)
        assert 0 <= i < self.l
        self.i = i
        self.SK = SK

    def sign(self, h, allow_pickle=False):
        """ """
        res = h ** self.SK
        if not allow_pickle:
            return res
        return serialize(res)

    def __getstate__(self):
        """ """
        d = dict(self.__dict__)
        d['l'] = self.l
        d['k'] = self.k
        d['i'] = self.i
        d['SK'] = serialize(self.SK)
        d['VK'] = serialize(self.VK)
        d['VKs'] = list(map(serialize, self.VKs))
        return d

    def __setstate__(self, d):
        """ """
        self.__dict__ = d
        self.SK = deserialize0(self.SK)
        self.VK = deserialize2(self.VK)
        self.VKs = list(map(deserialize2, self.VKs))
        # print("SK of Thld Sig is depickled")



def dealer(players=10, k=5, seed=None):
    """ """
    assert k > 0
    assert isinstance(k, int)
    # Random polynomial coefficients
    a = group.random(ZR, count=k, seed=seed)
    assert len(a) == k
    secret = a[0]

    # Shares of master secret key
    SKs = [polynom_eval(i, a) for i in range(1, players+1)]
    assert polynom_eval(0, a) == secret

    # Verification keys
    VK = g2 ** secret
    VKs = [g2 ** xx for xx in SKs]

    public_key = TBLSPublicKey(players, k, VK, VKs)
    private_keys = [TBLSPrivateKey(players, k, VK, VKs, SK, i)
                    for i, SK in enumerate(SKs)]

    # Check reconstruction of 0
    S = set(range(0, k))
    lhs = polynom_eval(0, a)
    rhs = sum(public_key.lagrange(S, j) * polynom_eval(j+1, a) for j in S)
    assert lhs == rhs
    # print i, 'ok'

    return public_key, private_keys
