package com.cleptes.crypto.SymmetricCripto.Integrity;

import com.cleptes.crypto.Agents.Agent;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import java.security.Key;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;
import java.security.SecureRandom;
/**
 * AuthEncryption
 * https://docs.oracle.com/javase/7/docs/api/javax/crypto/spec/GCMParameterSpec.html
 *
 * example:
 * https://gist.github.com/praseodym/f2499b3e14d872fe5b4a
 */
public class AuthEncryption {
    public static void main(String[] args) throws Exception {
        final BlockingQueue<byte[]> bob2alice = new LinkedBlockingQueue<>();
        final BlockingQueue<byte[]> alice2bob = new LinkedBlockingQueue<>();

        String[] CipherSuit = {"AES","AES/GCM/NoPadding"}; // ni paddinga ker je counter mode

        KeyGenerator keyGenerator = KeyGenerator.getInstance(CipherSuit[0]);
        //keyGenerator.init(128 /* key size*/);
        Key session_key = keyGenerator.generateKey();

        Agent alice = new Agent("Alice",alice2bob,bob2alice,session_key,CipherSuit[1] /* more bit specificiran full name: DES/ECB/PKCS5Padding*/){
            // name, outgoing,incoming, cipherKey, cipher
            @Override
            public void execute() throws Exception{
                String msg = "I love you bob now with integrity";
                byte[] PT = msg.getBytes("UTF-8");
                print("msg: "+msg+"\nPT: "+hex(PT));

                SecureRandom random = SecureRandom.getInstanceStrong();
                byte[] iv = new byte[16];
                random.nextBytes(iv);

                GCMParameterSpec gcmSpecs = new GCMParameterSpec(128,iv); // Tko nastavmo IV in MAC LEN lahko: 128, 120, 112, 104 or 96 bits
                Cipher cipherGen = Cipher.getInstance(cipher);
                cipherGen.init(Cipher.ENCRYPT_MODE,cipherKey,gcmSpecs);
                byte[] CT=cipherGen.doFinal(PT);
                byte[] IV=cipherGen.getIV();
                print("CT: "+hex(CT)+"\nIV: "+hex(IV));

                outgoing.put(IV);
                outgoing.put(CT);



            }
        };

        Agent bob = new Agent("Bob",bob2alice,alice2bob,session_key, CipherSuit[1]) {
            // name, outgoing,incoming, cipherKey, cipher
            @Override
            public void execute() throws Exception {
                byte[] IV = incoming.take();
                byte[] CT = incoming.take();
                //CT[0]=0; prevermo da res pride do tag mismatcha
                GCMParameterSpec IvSpec = new GCMParameterSpec(128,IV);

                Cipher cipherGen = Cipher.getInstance(cipher);
                cipherGen.init(Cipher.DECRYPT_MODE,cipherKey,IvSpec);
                byte[] PT=cipherGen.doFinal(CT);
                String msg=new String(PT,"UTF-8");
                print("msg: "+msg+"\nPT: "+hex(PT));



            }
        };

        alice.start();
        bob.start();


    }
}
