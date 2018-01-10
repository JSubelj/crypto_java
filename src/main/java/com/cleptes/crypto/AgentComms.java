package com.cleptes.crypto;

import com.cleptes.crypto.Agents.Agent;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Signature;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;

class AgentComms {
    public static void main(String[] args) throws Exception {
        final BlockingQueue<byte[]> bob2alice = new LinkedBlockingQueue<>();
        final BlockingQueue<byte[]> alice2bob = new LinkedBlockingQueue<>();

        Key key_gcm = KeyGenerator.getInstance("AES").generateKey();
        Key key_ctr = KeyGenerator.getInstance("AES").generateKey();
        String cipherAlg = "";
        KeyPair bob_keypair = KeyPairGenerator.getInstance("RSA").generateKeyPair();

        Agent alice = new Agent("Alice",alice2bob,bob2alice,null,null  /* more bit specificiran full name: DES/ECB/PKCS5Padding*/){
            // name, outgoing,incoming, cipherKey, cipher
            @Override
            public void execute() throws Exception{
                /** COMMONLY USED
                 */
                String msg = "The package is in room 102";
                byte[] PT = msg.getBytes("UTF-8");
                print("msg: "+msg+"\nPT: "+hex(PT));
                // print("CT: "+hex(CT)+"\nIV: "+hex(IV));
                //
                // Pošlje confident in integrity

                Cipher cipherGen =  Cipher.getInstance("AES/GCM/NoPadding");
                cipherGen.init(Cipher.ENCRYPT_MODE,key_gcm);
                byte[] CT = cipherGen.doFinal(PT);
                byte[] IV = cipherGen.getIV();

                outgoing.add(IV);
                outgoing.add(CT);

                byte[] IV_from_bob = incoming.take();
                byte[] CT_from_bob = incoming.take();
                byte[] signature = incoming.take();

                //signature[0] = 0;

                IvParameterSpec IvSpecs = new IvParameterSpec(IV_from_bob);
                Cipher cipherGenCTR = Cipher.getInstance("AES/CTR/NoPadding");
                cipherGenCTR.init(Cipher.DECRYPT_MODE,key_ctr,IvSpecs);
                byte[] PT_from_bob = cipherGenCTR.doFinal(CT_from_bob);
                print("msg_from_bob: "+new String(PT_from_bob,"UTF-8"));
                Signature verifyer = Signature.getInstance("SHA256withRSA");
                verifyer.initVerify(bob_keypair.getPublic());
                verifyer.update(CT_from_bob);
                if (verifyer.verify(signature))
                    print("Valid signature.");
                else
                    print("Invalid signature.");

            }
        };

        Agent bob = new Agent("Bob",bob2alice,alice2bob,null,null) {
            // name, outgoing,incoming, cipherKey, cipher
            @Override
            public void execute() throws Exception {
                /**
                 * commonly used
                 */
                byte[] IV = incoming.take();
                byte[] CT = incoming.take();
                // sprejme
                //CT[0]=0;
                // ENCRYPT THEN MAC najbl varn!
                // vrne confident integrity non-rep
                Cipher GCMCipher = Cipher.getInstance("AES/GCM/NoPadding");
                GCMCipher.init(Cipher.DECRYPT_MODE,key_gcm,new GCMParameterSpec(128,IV));
                byte[] PT = GCMCipher.doFinal(CT);

                print("Msg: "+new String(PT,"UTF-8"));

                byte[] msg_to_alice="Acknowledged".getBytes("UTF-8");
                Cipher CTRCipher = Cipher.getInstance("AES/CTR/NoPadding");
                CTRCipher.init(Cipher.ENCRYPT_MODE,key_ctr);
                byte[] CT_to_alice = CTRCipher.doFinal(msg_to_alice);
                outgoing.put(CTRCipher.getIV());
                outgoing.put(CT_to_alice);

                Signature sigGen = Signature.getInstance("SHA256withRSA");
                sigGen.initSign(bob_keypair.getPrivate());
                sigGen.update(CT_to_alice);
                byte[] sig = sigGen.sign();
                outgoing.put(sig);


            }
        };

        alice.start();
        bob.start();


    }
}