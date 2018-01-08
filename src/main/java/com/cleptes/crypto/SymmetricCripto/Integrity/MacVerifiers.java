package com.cleptes.crypto.SymmetricCripto.Integrity;

import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import java.lang.reflect.Array;
import java.security.Key;
import java.util.Arrays;

public class MacVerifiers {
    public MacVerifiers() {
    }

    public boolean simpleVerifier(byte[] mac1, byte[] mac2){
        if (mac1==null || mac2==null) return false;
        if (mac1.length != mac2.length) return false;

        Boolean checker = true;
        for (int i=0;i<mac1.length;i++){
            if(mac1[i]!=mac2[i]){
                checker=false;
            }
        }
        return checker;
    }

    public boolean secureVerifier(byte[] mac1, byte[] mac2) throws Exception{
        Mac mac = Mac.getInstance("HmacSHA256");
        Key key = KeyGenerator.getInstance("HmacSHA256").generateKey();
        mac.init(key);

        byte[] mac1_h=mac.doFinal(mac1);
        byte[] mac2_h=mac.doFinal(mac2);

        return Arrays.equals(mac1_h,mac2_h);
        //return simpleVerifier(mac1_h,mac2_h);
    }
}
