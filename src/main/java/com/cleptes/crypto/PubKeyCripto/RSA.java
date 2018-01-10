package com.cleptes.crypto.PubKeyCripto;

import com.cleptes.crypto.Agents.Agent;


import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;

public class RSA {
    public static void main(String[] args) throws Exception {

        final BlockingQueue<byte[]> alice2bob = new LinkedBlockingQueue<>();
        final BlockingQueue<byte[]> bob2alice = new LinkedBlockingQueue<>();

        KeyPairGenerator keygen = KeyPairGenerator.getInstance("RSA");
        keygen.initialize(4096);
        final KeyPair aliceKP = keygen.generateKeyPair();
        final KeyPair bobKP = KeyPairGenerator.getInstance("RSA").generateKeyPair();

        final Agent alice = new Agent("alice", alice2bob, bob2alice, null, "RSA/ECB/NoPadding") {
            @Override
            public void execute() throws Exception {
                String msg = "Good moarning bobieboy";
                byte[] pt=msg.getBytes("UTF-8");
                Cipher rsagen=Cipher.getInstance(cipher);
                rsagen.init(Cipher.ENCRYPT_MODE,bobKP.getPublic());
                byte[] ct = rsagen.doFinal(pt);

                outgoing.put(ct);
                /*
                - Create an AES cipher and encrypt a message using Bob's PK;
                - Send the CT to Bob;
                - Reference the keys by using global variables aliceKP and bobKP.
                 */
            }
        };

        final Agent bob = new Agent("bob", bob2alice, alice2bob, null, "RSA/ECB/NoPadding") {
            @Override
            public void execute() throws Exception {
                byte[] ct = incoming.take();
                Cipher rsagen=Cipher.getInstance(cipher);
                rsagen.init(Cipher.ENCRYPT_MODE,bobKP.getPrivate());
                byte[] pt=rsagen.doFinal(ct);

                String msg=new String(pt,"UTF-8");
                print(msg);


                /*
                - Take the incoming message from the queue;
                - Create an AES cipher and decrypt incoming CT using Bob's SK;
                - Print the message;
                - Reference the keys by using global variables aliceKP and bobKP.
                 */
            }
        };

        alice.start();
        bob.start();
    }
}

