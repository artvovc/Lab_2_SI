package com;

import java.io.BufferedReader;
import java.io.InputStreamReader;

public class Main {
    public static void main(String[] args) {

        int iBitSize = 1024;
        try
        {
            RSA r = new RSA(iBitSize);
            System.out.println("Enter message: ");
            System.out.println();
            String input = (new BufferedReader(new InputStreamReader(System.in))).readLine();
            String sHexCipherText = r.encryptPlainStrToHex(input);
            String sPlainText = r.decryptHexCipherToPlainMsg(sHexCipherText);
            System.out.println();
            System.out.println("CipherText: " + sHexCipherText);
            System.out.println("PlainText/Original message: "+sPlainText);
            System.out.println();
        } catch (Exception e1) {
        }






    }
}
