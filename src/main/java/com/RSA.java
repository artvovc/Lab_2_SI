package com;

import java.math.BigInteger;
import java.util.Random;

class RSA {
    private int _TextSize;
    private BigInteger _PrivateKey;
    private BigInteger _PublicKey;
    private BigInteger _ProdPQ;

    private String encryptMessage(String sHexString, BigInteger N, BigInteger e) {
        if (sHexString.length() == 0)
            return null;
        int iMaxCharLenInOneStr = _TextSize / 2;
        if (iMaxCharLenInOneStr <= sHexString.length()) {
            String sRetOutStr = "";
            String sOutStr;
            int iBeginIndex = 0;
            int iEndIndex = iMaxCharLenInOneStr - 1;
            while (iBeginIndex < sHexString.length()) {
                if (iEndIndex < sHexString.length()) {
                    sOutStr = (new BigInteger(sHexString.substring(iBeginIndex, iEndIndex), 16)).modPow(e, N).toString(16);
                    iBeginIndex = iEndIndex;
                    iEndIndex += (iMaxCharLenInOneStr - 1);
                } else {
                    sOutStr = (new BigInteger(sHexString.substring(iBeginIndex), 16)).modPow(e, N).toString(16);
                    iBeginIndex = sHexString.length();
                }
                if (sOutStr.length() < iMaxCharLenInOneStr) {
                    int iLen = iMaxCharLenInOneStr - sOutStr.length();
                    for (int k = 0; k < iLen; k++)
                        sOutStr = "0" + sOutStr;
                }
                sRetOutStr += sOutStr;
            }
            return sRetOutStr;
        } else
            return (new BigInteger(sHexString, 16)).modPow(e, N).toString(16);
    }

    private String decryptMessage(String sHexString, BigInteger N, BigInteger d) {
        if (sHexString.length() == 0)
            return null;
        int iMaxCharLenInOneStr = _TextSize / 2;
        if (iMaxCharLenInOneStr < sHexString.length()) {
            String sRetOutStr = "";
            int iBeginIndex = 0;
            int iEndIndex = iMaxCharLenInOneStr;
            while (iBeginIndex < sHexString.length()) {
                if (iEndIndex < sHexString.length()) {
                    sRetOutStr += (new BigInteger(sHexString.substring(iBeginIndex, iEndIndex), 16)).modPow(d, N).toString(16);
                    iBeginIndex = iEndIndex;
                    iEndIndex += iMaxCharLenInOneStr;
                } else {
                    sRetOutStr += (new BigInteger(sHexString.substring(iBeginIndex), 16)).modPow(d, N).toString(16);
                    break;
                }
            }
            return sRetOutStr;
        } else
            return (new BigInteger(sHexString, 16)).modPow(d, N).toString(16);
    }

    private String convertStringToHex(String str) {
        char[] chars = str.toCharArray();
        StringBuilder hex = new StringBuilder();
        for (char aChar : chars) {
            hex.append(Integer.toHexString((int) aChar));
        }
        return hex.toString();
    }

    private String convertHexToString(String hex) {
        StringBuilder sb = new StringBuilder();
        StringBuilder temp = new StringBuilder();
        for (int i = 0; i < hex.length() - 1; i += 2) {
            String output = hex.substring(i, (i + 2));
            int decimal = Integer.parseInt(output, 16);
            sb.append((char) decimal);
            temp.append(decimal);
        }
        return sb.toString();
    }

    RSA(int TextSize)//Key Generator
    {
        _TextSize = TextSize;
        BigInteger primeP = BigInteger.probablePrime(_TextSize, new Random());
        BigInteger primeQ = BigInteger.probablePrime(_TextSize, new Random());
        _ProdPQ = primeP.multiply(primeQ);//n=pq
        BigInteger fi = primeP.subtract(BigInteger.valueOf(1)).multiply(primeQ.subtract(BigInteger.valueOf(1)));
        // 1 < e < ϕ(n),gcd(e,ϕ(n))=1, e is Public Key
        do {
            _PublicKey = new BigInteger(2 * _TextSize, new Random());
            if ((_PublicKey.compareTo(fi) == -1) && (_PublicKey.compareTo(BigInteger.ONE) == 1) && (_PublicKey.gcd(fi).compareTo(BigInteger.ONE) == 0))
                break;
        } while (true);
        _PrivateKey = _PublicKey.modInverse(fi);//de ≡ 1 (mod ϕ(n)).
    }

    String encryptPlainStrToHex(String sPlainStr) {
        return encryptMessage(convertStringToHex(sPlainStr), _ProdPQ, _PrivateKey);
    }

    String decryptHexCipherToPlainMsg(String sHexCipherMsg) {
        return convertHexToString(decryptMessage(sHexCipherMsg, _ProdPQ, _PublicKey));
    }

}