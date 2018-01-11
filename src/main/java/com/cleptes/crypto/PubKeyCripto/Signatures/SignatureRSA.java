package com.cleptes.crypto.PubKeyCripto.Signatures;

import com.cleptes.crypto.Agents.Agent;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.*;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;

/**
 * https://en.wikipedia.org/wiki/Authenticated_encryption
 */
public class SignatureRSA {
    public static void main(String[] args) throws Exception {
        final BlockingQueue<byte[]> bob2alice = new LinkedBlockingQueue<>();
        final BlockingQueue<byte[]> alice2bob = new LinkedBlockingQueue<>();


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

                KeyPair aliceKP = KeyPairGenerator.getInstance("RSA").generateKeyPair();
                outgoing.put(aliceKP.getPublic().getEncoded());

                String msg = "Here i signed it u fucker";

                byte[] PT = msg.getBytes("UTF-8");

                // Dig envelope
                Key AESKey = KeyGenerator.getInstance("AES").generateKey();

                print("AESKey : "+hex(AESKey.getEncoded()));

                X509EncodedKeySpec BobKeySpec = new X509EncodedKeySpec(incoming.take());
                RSAPublicKey BobPubKey = (RSAPublicKey) KeyFactory.getInstance("RSA").generatePublic(BobKeySpec);

                Cipher RSAGen = Cipher.getInstance("RSA/ECB/OAEPPadding");
                RSAGen.init(Cipher.ENCRYPT_MODE,BobPubKey);
                outgoing.put(RSAGen.doFinal(AESKey.getEncoded()));


                Cipher AESGen = Cipher.getInstance("AES/CTR/NoPadding");
                AESGen.init(Cipher.ENCRYPT_MODE,AESKey);
                byte[] CT = AESGen.doFinal(PT);
                byte[] IV = AESGen.getIV();

                outgoing.put(IV);

                outgoing.put(CT);

                byte[] CT1 = CT.clone();


                Signature sigGen = Signature.getInstance("SHA256withRSA");
                sigGen.initSign(aliceKP.getPrivate());
                sigGen.update(CT1);
                byte[] signature = sigGen.sign();
                outgoing.put(signature);



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
                X509EncodedKeySpec aliceKeySpec = new X509EncodedKeySpec(incoming.take());

                RSAPublicKey alicePubKey = (RSAPublicKey) KeyFactory.getInstance("RSA").generatePublic(aliceKeySpec);

                KeyPair bobKP = KeyPairGenerator.getInstance("RSA").generateKeyPair();

                outgoing.put(bobKP.getPublic().getEncoded());

                byte[] keyCT = incoming.take();

                Cipher RSAgen = Cipher.getInstance("RSA/ECB/OAEPPadding");
                RSAgen.init(Cipher.DECRYPT_MODE,bobKP.getPrivate());
                byte[] keyPT = RSAgen.doFinal(keyCT);

                SecretKey keyAES = new SecretKeySpec(keyPT,0,keyPT.length,"AES");
                print("AES key: "+hex(keyAES.getEncoded()));

                byte[] IV = incoming.take();
                byte[] CT = incoming.take();
                IvParameterSpec ivSpec = new IvParameterSpec(IV);

                byte[] signature = incoming.take();
                Signature sigGen = Signature.getInstance("SHA256withRSA");
                byte[] CT1 = CT.clone();
                //CT1[0]=0;
                sigGen.initVerify(alicePubKey);
                sigGen.update(CT1);
                if(sigGen.verify(signature)){
                    print("Sig: "+hex(signature));
                    print("OK");
                    Cipher AESGen = Cipher.getInstance("AES/CTR/NoPadding");
                    AESGen.init(Cipher.DECRYPT_MODE,keyAES,ivSpec);
                    print("msg: "+new String(AESGen.doFinal(CT1),"UTF-8"));

                }
                else{
                    print("NO");
                }




            }
        };

        alice.start();
        bob.start();


    }


}
