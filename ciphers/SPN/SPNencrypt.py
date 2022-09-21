# substitution box
sBox_values = [14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7]

# s-box with redundant keys piS = [0,1,1,1,4,5,6,7,8,9,10,11,12,13,14,15]
# permutation box
pBox_values = ['placeholder', 1, 5, 9, 13,
               2, 6, 10, 14, 3, 7, 11, 15, 4, 8, 12, 16]

# convert decimal to binary with array since there are only 16 values
getBin = ["0000", "0001", "0010", "0011", "0100", "0101", "0110",
          "0111", "1000", "1001", "1010", "1011", "1100", "1101", "1110", "1111"]

# key schedule
k = "00111010100101001101011000111111"
k1, k2, k3 = k[0:16], k[4:20], k[8:24]
k4 = k[12:28]
k5 = k[16:32]

# key schedule defined as [k1,k2,k3]
k = [k1, k2, k3]


# binary xor operation
def xor(a, b):
    if a == "1" and b == "1":
        return 0

    if a == "0" and b == "1":
        return 1

    if a == "1" and b == "0":
        return 1

    return 0

# gets the u value for the SPN


def getU(w, k):
    u = ""

    for i in range(len(w)):
        u += str(xor(w[i], k[i]))

    return u


def getV(u):
    uSplit = [int(u[0:4], 2), int(u[4:8], 2),
              int(u[8:12], 2), int(u[12:16], 2)]
    newSplit = ""

    for num in uSplit:
        newSplit += getBin[sBox_values[num]]

    return newSplit


def getW(v):

    # preconditions: valid v
    # postconditions: valid w

    w = ""
    for i in range(1, 17):
        w += v[pBox_values[i]]
    return w


def getCipherText(v):

    # preconditions: valid v
    # postconditions: correct ciphertext
    # gets the ciphertext

    y = ""
    for i in range(len(v)):
        y += str(xor(v[i], k5[i]))
    return y


def spn(plain):
    # preconditions: valid plain
    # postconditions: correct ciphertext
    # performs the Substitution Permutation Network algorithm on a given binary plaintext

    w = plain
    for key in k:
        u = getU(w, key)
        v = getV(u)
        v = "x" + v
        w = getW(v)

    u = getU(w, k4)
    v = getV(u)

    return getCipherText(v)
