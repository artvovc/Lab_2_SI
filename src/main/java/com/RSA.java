package com;

import java.math.BigInteger;
import java.util.Random;

class RSA {
    private int TextSize;
    private BigInteger PrivateKey;
    private BigInteger PublicKey;
    private BigInteger ProdPQ;

    RSA(int TextSize)
    {
        this.TextSize = TextSize;
        BigInteger primeP = BigInteger.probablePrime(this.TextSize, new Random());
        BigInteger primeQ = BigInteger.probablePrime(this.TextSize, new Random());
        ProdPQ = primeP.multiply(primeQ);
        BigInteger fi = primeP.subtract(BigInteger.ONE).multiply(primeQ.subtract(BigInteger.ONE));
        do {
            PublicKey = new BigInteger(this.TextSize, new Random());
            if (    (PublicKey.compareTo(fi) == -1) &&
                    (PublicKey.compareTo(BigInteger.ONE) == 1) &&
                    (PublicKey.gcd(fi).compareTo(BigInteger.ONE) == 0)  )
                break;
        } while (true);
        PrivateKey = PublicKey.modInverse(fi);
    }

    String encryptText(String text) {
        char[] chars = text.toCharArray();
        StringBuilder hex = new StringBuilder();
        for (char aChar : chars) {
            hex.append(Integer.toHexString((int) aChar));
        }
        return encrypt(hex.toString(), ProdPQ, PublicKey);
    }

    String decryptText(String hexString) {
        String decryptedHexString = decrypt(hexString, ProdPQ, PrivateKey);
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < decryptedHexString.length() - 1; i += 2) {
            String output = decryptedHexString.substring(i, (i + 2));
            int decimal = Integer.parseInt(output, 16);
            sb.append((char) decimal);
        }
        return sb.toString();
    }

    private String encrypt(String hexString, BigInteger N, BigInteger e) {
        if (hexString.length() == 0)
            return null;
        int stringLenght = TextSize / 2;
        if (stringLenght <= hexString.length()) {
            String returnString = "";
            String pathString;
            int startIndex = 0;
            int finalIndex = stringLenght - 1;
            while (startIndex < hexString.length()) {
                if (finalIndex < hexString.length()) {
                    pathString = (new BigInteger(hexString.substring(startIndex, finalIndex), 16)).modPow(e, N).toString(16);
                    startIndex = finalIndex;
                    finalIndex += (stringLenght - 1);
                } else {
                    pathString = (new BigInteger(hexString.substring(startIndex), 16)).modPow(e, N).toString(16);
                    startIndex = hexString.length();
                }
                if (pathString.length() < stringLenght) {
                    int iLen = stringLenght - pathString.length();
                    for (int k = 0; k < iLen; k++)
                        pathString = "0" + pathString;
                }
                returnString += pathString;
            }
            return returnString;
        } else
            return (new BigInteger(hexString, 16)).modPow(e, N).toString(16);
    }

    private String decrypt(String hexString, BigInteger N, BigInteger d) {
        if (hexString.length() == 0)
            return null;
        int stringLenght = TextSize / 2;
        if (stringLenght < hexString.length()) {
            String returnString = "";
            int startIndex = 0;
            int finalIndex = stringLenght;
            while (startIndex < hexString.length()) {
                if (finalIndex < hexString.length()) {
                    returnString += (new BigInteger(hexString.substring(startIndex, finalIndex), 16)).modPow(d, N).toString(16);
                    startIndex = finalIndex;
                    finalIndex += stringLenght;
                } else {
                    returnString += (new BigInteger(hexString.substring(startIndex), 16)).modPow(d, N).toString(16);
                    break;
                }
            }
            return returnString;
        } else
            return (new BigInteger(hexString, 16)).modPow(d, N).toString(16);
    }


}