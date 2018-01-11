package com.cleptes.crypto.KeyDerivation;

import com.cleptes.crypto.Agents.Agent;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.Key;
import java.security.SecureRandom;
import java.security.spec.KeySpec;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;

public class KeyDerivation {
    public static void main(String[] args) throws Exception {
        final BlockingQueue<byte[]> bob2alice = new LinkedBlockingQueue<>();
        final BlockingQueue<byte[]> alice2bob = new LinkedBlockingQueue<>();


        SecureRandom random = SecureRandom.getInstanceStrong();
        byte[] salt = new byte[16];
        random.nextBytes(salt);


        Agent alice = new Agent("Alice",alice2bob,bob2alice,null,null  /* more bit specificiran full name: DES/ECB/PKCS5Padding*/){
            // name, outgoing,incoming, cipherKey, cipher

            @Override
            public void execute() throws Exception{
                /** COMMONLY USED
                 */
                // String msg = "I love you bob now with integrity";
                // byte[] PT = msg.getBytes("UTF-8");
                // print("msg: "+msg+"\nPT: "+hex(PT));
                // print("CT: "+hex(CT)+"\nIV: "+hex(IV));
                //

                String pass = "password";
                final SecretKeyFactory pbkdf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
                KeySpec specs = new PBEKeySpec(pass.toCharArray(),salt,10000,128); // char array, salt, iteracij, kok bitov rabm
                SecretKey key = pbkdf.generateSecret(specs);
                print(hex(key.getEncoded()));
            }
        };

        Agent bob = new Agent("Bob",bob2alice,alice2bob,null,null) {
            // name, outgoing,incoming, cipherKey, cipher
            @Override
            public void execute() throws Exception {
                /**
                 * commonly used
                 */
                // byte[] IV = incoming.take();
                // byte[] CT = incoming.take();
                String pass = "password";
                final SecretKeyFactory pbkdf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
                KeySpec specs = new PBEKeySpec(pass.toCharArray(),salt,10000,128); // char array, salt, iteracij, kok bitov rabm
                SecretKey key = pbkdf.generateSecret(specs);
                print("len " +key.getEncoded().length);
            }
        };

        alice.start();
        bob.start();


    }
}
