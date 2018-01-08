package com.cleptes.crypto.Agents;

import com.cleptes.crypto.Agents.Agent;

import javax.crypto.KeyGenerator;
import java.security.Key;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;

public class agentComm {
    public static void main(String[] args) throws Exception {
        final BlockingQueue<byte[]> bob2alice = new LinkedBlockingQueue<>();
        final BlockingQueue<byte[]> alice2bob = new LinkedBlockingQueue<>();

        Key key = KeyGenerator.getInstance("").generateKey();
        String cipherAlg = "";

        Agent alice = new Agent("Alice",alice2bob,bob2alice,key,cipherAlg  /* more bit specificiran full name: DES/ECB/PKCS5Padding*/){
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



            }
        };

        Agent bob = new Agent("Bob",bob2alice,alice2bob,key,cipherAlg) {
            // name, outgoing,incoming, cipherKey, cipher
            @Override
            public void execute() throws Exception {
                /**
                 * commonly used
                 */
                // byte[] IV = incoming.take();
                // byte[] CT = incoming.take();

            }
        };

        alice.start();
        bob.start();


    }
}
