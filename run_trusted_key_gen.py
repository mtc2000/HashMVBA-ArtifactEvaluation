from crypto.threshsig import boldyreva
from crypto.threshenc import tpke
from crypto.ecdsa import ecdsa
import pickle
import os


def trusted_key_gen(N=6, f=1, seed=None):

    # Generate threshold enc keys
    ePK, eSKs = tpke.dealer(N, f+1)

    # Generate threshold sig keys for coin (thld f+1)
    sPK, sSKs = boldyreva.dealer(N, f+1, seed=seed)

    # Generate threshold sig keys for cbc (thld n-f)
    sPK1, sSK1s = boldyreva.dealer(N, N-f, seed=seed)

    # Generate ECDSA sig keys
    sPK2s, sSK2s = ecdsa.pki(N, seed=seed)

    folder_name = f'keys/keys-N{N}-f{f}'
    full_path = f'{os.getcwd()}/{folder_name}'

    # Save all keys to files
    os.makedirs(full_path, exist_ok=True)

    if seed is not None:
        with open(f'{full_path}/seed', 'w+') as fp:
            fp.write(seed)

    # public key of (f+1, n) thld sig
    with open(f'{full_path}/sPK.key', 'wb') as fp:
        pickle.dump(sPK, fp)

    # public key of (n-f, n) thld sig
    with open(f'{full_path}/sPK1.key', 'wb') as fp:
        pickle.dump(sPK1, fp)

    # public key of (f+1, n) thld enc
    with open(f'{full_path}/ePK.key', 'wb') as fp:
        pickle.dump(ePK, fp)

    # public keys of ECDSA
    for i in range(N):
        with open(f'{full_path}/sPK2-{i}.key', 'wb') as fp:
            pickle.dump(sPK2s[i].format(), fp)

    # private key of (f+1, n) thld sig
    for i in range(N):
        with open(f'{full_path}/sSK-{i}.key', 'wb') as fp:
            pickle.dump(sSKs[i], fp)

    # private key of (n-f, n) thld sig
    for i in range(N):
        with open(f'{full_path}/sSK1-{i}.key', 'wb') as fp:
            pickle.dump(sSK1s[i], fp)

    # private key of (f+1, n) thld enc
    for i in range(N):
        with open(f'{full_path}/eSK-{i}.key', 'wb') as fp:
            pickle.dump(eSKs[i], fp)

    # private keys of ECDSA
    for i in range(N):
        with open(f'{full_path}/sSK2-{i}.key', 'wb') as fp:
            pickle.dump(sSK2s[i].secret, fp)


def main():
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument('--N', metavar='N', required=False,
                        help='number of parties', type=int)
    parser.add_argument('--f', metavar='f', required=False,
                        help='number of faulties', type=int)
    args = parser.parse_args()

    N = args.N
    f = args.f

    # if no valid parameters are given,
    # generate keys for all N = 5f + 1, f \in [1, 41)
    if N is None and f is None:
        for f in range(1, 41):
            N = 5 * f + 1
            trusted_key_gen(N, f, f'{N}/{f}')
        return
    
    # assume N = 5f + 1
    if N is None:
        N = 5 * f + 1
    elif f is None: # f is None
        f = (N - 1) // 5
    else:
        # if both N and f are given, ignore the constrain on N = 5f + 1
        assert N > f

    trusted_key_gen(N, f, f'{N}/{f}')

if __name__ == '__main__':
    main()
