package com.cleptes.crypto.PubKeyCripto.KeyAgreement;

import com.cleptes.crypto.Agents.Agent;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.KeyGenerator;
import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.*;
import java.security.spec.X509EncodedKeySpec;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;


/**
 * https://docs.oracle.com/javase/7/docs/api/javax/crypto/spec/SecretKeySpec.html
 */
public class DiffieHellman {

    public static void main(String[] args) throws Exception {
        final BlockingQueue<byte[]> bob2alice = new LinkedBlockingQueue<>();
        final BlockingQueue<byte[]> alice2bob = new LinkedBlockingQueue<>();






        Agent alice = new Agent("Alice",alice2bob,bob2alice,null,null  /* more bit specificiran full name: DES/ECB/PKCS5Padding*/){
            // name, outgoing,incoming, cipherKey, cipher
            @Override
            public void execute() throws Exception{
                KeyPairGenerator Alice_KeyPairGen = KeyPairGenerator.getInstance("DH");
                Alice_KeyPairGen.initialize(1024);
                KeyPair AliceKeyPair = Alice_KeyPairGen.generateKeyPair();

                // send "PK" to bob ("PK": A = g^a, "SK": a)
                outgoing.put(AliceKeyPair.getPublic().getEncoded());
                print("DH contribute: "+hex(AliceKeyPair.getPublic().getEncoded()));

                // get PK from bob
                X509EncodedKeySpec keySpec = new X509EncodedKeySpec(incoming.take());
                DHPublicKey bobPK = (DHPublicKey) KeyFactory.getInstance("DH").generatePublic(keySpec);

                KeyAgreement dh = KeyAgreement.getInstance("DH");
                dh.init(AliceKeyPair.getPrivate());
                dh.doPhase(bobPK,true);
                byte[] sessionKey = dh.generateSecret();
                print("Session Key: "+hex(sessionKey));

                SecretKeySpec AESSessionKey = new SecretKeySpec(sessionKey,0,16,"AES"); // key, offset, len, cipher
                print("AESKey: " + hex(AESSessionKey.getEncoded())) ;
                print("Len: "+AESSessionKey.getEncoded().length * 8);
                Cipher generator = Cipher.getInstance("AES/GCM/NoPadding");
                generator.init(Cipher.ENCRYPT_MODE,AESSessionKey);
                byte[] CT = generator.doFinal("I love you bob".getBytes("UTF-8"));
                //CT[0]=0;
                outgoing.put(generator.getIV());
                outgoing.put(CT);

            }
        };

        Agent bob = new Agent("Bob",bob2alice,alice2bob,null,null) {
            // name, outgoing,incoming, cipherKey, cipher
            @Override
            public void execute() throws Exception {
                // get PK from alice
                X509EncodedKeySpec keySpec = new X509EncodedKeySpec(incoming.take());
                DHPublicKey alicePk = (DHPublicKey) KeyFactory.getInstance("DH").generatePublic(keySpec);
                // create your own DH key pair
                DHParameterSpec aliceParameterSpec = alicePk.getParams();
                KeyPairGenerator bob_keyPairGen = KeyPairGenerator.getInstance("DH");
                bob_keyPairGen.initialize(aliceParameterSpec);
                KeyPair bob_keyPair = bob_keyPairGen.generateKeyPair();

                // send "PK" to alice ("PK": A = g^a, "SK": a)
                outgoing.put(bob_keyPair.getPublic().getEncoded());
                print("DH contribute: "+hex(bob_keyPair.getPublic().getEncoded()));

                KeyAgreement dh = KeyAgreement.getInstance("DH");
                dh.init(bob_keyPair.getPrivate());
                dh.doPhase(alicePk,true);
                byte[] session_key = dh.generateSecret();
                print("Session key: "+hex(session_key));

                byte[] IV = incoming.take();
                GCMParameterSpec gcmSpec = new GCMParameterSpec(128,IV);

                SecretKeySpec AESSessionKey = new SecretKeySpec(session_key,0,16,"AES");
                Cipher gen = Cipher.getInstance("AES/GCM/NoPadding");
                gen.init(Cipher.DECRYPT_MODE,AESSessionKey,gcmSpec);
                byte[] PT = gen.doFinal(incoming.take());

                print("Here it is : "+new String(PT,"UTF-8"));




            }
        };

        alice.start();
        bob.start();


    }
}
