package com.cleptes.crypto.SymmetricCripto.Integrity;

import com.cleptes.crypto.Agents.Agent;

import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import java.security.Key;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;

/**
 *
 * https://en.wikipedia.org/wiki/Hash-based_message_authentication_code
 * https://docs.oracle.com/javase/7/docs/technotes/guides/security/StandardNames.html#Mac
 * https://docs.oracle.com/javase/7/docs/api/javax/crypto/Mac.htmlž
 * https://docs.oracle.com/javase/7/docs/api/javax/xml/crypto/dsig/spec/HMACParameterSpec.html
 *
 * kako narest
 * http://docs.oracle.com/javase/8/docs/technotes/guides/security/crypto/CryptoSpec.html#Mac
 */
public class Hmac {
    public static void main(String[] args) throws Exception {
        final BlockingQueue<byte[]> bob2alice = new LinkedBlockingQueue<>();
        final BlockingQueue<byte[]> alice2bob = new LinkedBlockingQueue<>();

        Key key = KeyGenerator.getInstance("HmacSHA256").generateKey();
        String cipherAlg = "HmacSHA256";

        Agent alice = new Agent("Alice",alice2bob,bob2alice,key,cipherAlg /* more bit specificiran full name: DES/ECB/PKCS5Padding*/){
            // name, outgoing,incoming, cipherKey, cipher
            @Override
            public void execute() throws Exception{
                /** COMMONLY USED
                 */
                String msg = "I love you bob, but verify this message";
                byte[] PT = msg.getBytes("UTF-8");
                print("msg: "+msg+"\nPT: "+hex(PT));
                //print("CT: "+hex(CT)+"\nIV: "+hex(IV));
                Mac mac = Mac.getInstance(cipher);
                mac.init(cipherKey);
                byte[] HMAC = mac.doFinal(PT);
                print("HMAC: "+hex(HMAC));

                outgoing.put(PT);
                outgoing.put(HMAC);




            }
        };

        Agent bob = new Agent("Bob",bob2alice,alice2bob,key,cipherAlg) {
            // name, outgoing,incoming, cipherKey, cipher
            @Override
            public void execute() throws Exception {
                byte[] PT = incoming.take();
                byte[] HMAC = incoming.take();
                //PT[0]=0;
                Mac mac = Mac.getInstance(cipher);
                mac.init(cipherKey);
                byte[] HMAC_gen = mac.doFinal(PT);

                MacVerifiers macVerifiers = new MacVerifiers();
                boolean verify = macVerifiers.secureVerifier(HMAC_gen,HMAC);
                if(verify){
                    print("PRAVILNO");
                }else{
                    print("NAROBASTO!!");
                }

            }
        };

        alice.start();
        bob.start();


    }
}
