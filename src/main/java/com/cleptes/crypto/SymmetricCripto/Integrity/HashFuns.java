package com.cleptes.crypto.SymmetricCripto.Integrity;

import com.cleptes.crypto.Agents.Agent;

import javax.crypto.KeyGenerator;
import java.security.Key;
import java.security.MessageDigest;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;

/**
 * https://docs.oracle.com/javase/7/docs/api/java/security/MessageDigest.html
 * https://docs.oracle.com/javase/7/docs/technotes/guides/security/StandardNames.html#MessageDigest
 */
public class HashFuns {
    public static void main(String[] args) throws Exception {
        final BlockingQueue<byte[]> bob2alice = new LinkedBlockingQueue<>();
        final BlockingQueue<byte[]> alice2bob = new LinkedBlockingQueue<>();

        String cipherAlg = "SHA-512";

        Agent alice = new Agent("Alice",alice2bob,bob2alice,null,cipherAlg  /* more bit specificiran full name: DES/ECB/PKCS5Padding*/){
            // name, outgoing,incoming, cipherKey, cipher
            @Override
            public void execute() throws Exception{
                /** COMMONLY USED
                 */
                String msg = "I love you bob now with integrity";
                byte[] PT = msg.getBytes("UTF-8");
                print("msg: "+msg+"\nPT: "+hex(PT));

                MessageDigest messageDigestGen = MessageDigest.getInstance(cipher);
                byte[] md = messageDigestGen.digest(PT);

                print("MD: "+hex(md));

                outgoing.put(PT);
                outgoing.put(md);



            }
        };

        Agent bob = new Agent("Bob",bob2alice,alice2bob,null,cipherAlg) {
            // name, outgoing,incoming, cipherKey, cipher
            @Override
            public void execute() throws Exception {
                byte[] PT = incoming.take();
                byte[] md = incoming.take();
                //PT[0]=0;

                MessageDigest messageDigest = MessageDigest.getInstance(cipher);
                byte[] md_gen = messageDigest.digest(PT);

                if(MacVerifiers.secureVerifier(md,md_gen)){
                    print("OK");
                }else{
                    print("NOT OK");
                }

            }
        };

        alice.start();
        bob.start();


    }
}
