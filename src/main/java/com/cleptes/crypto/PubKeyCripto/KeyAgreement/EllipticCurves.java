package com.cleptes.crypto.PubKeyCripto.KeyAgreement;

import com.cleptes.crypto.Agents.Agent;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECParameterSpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;

public class EllipticCurves {
    public static void main(String[] args) throws Exception {
        final BlockingQueue<byte[]> bob2alice = new LinkedBlockingQueue<>();
        final BlockingQueue<byte[]> alice2bob = new LinkedBlockingQueue<>();


        Agent alice = new Agent("Alice", alice2bob, bob2alice, null, null  /* more bit specificiran full name: DES/ECB/PKCS5Padding*/) {
            // name, outgoing,incoming, cipherKey, cipher
            @Override
            public void execute() throws Exception {
                /** COMMONLY USED
                 */
                // String msg = "I love you bob now with integrity";
                // byte[] PT = msg.getBytes("UTF-8");
                // print("msg: "+msg+"\nPT: "+hex(PT));
                // print("CT: "+hex(CT)+"\nIV: "+hex(IV));
                //

                KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
                kpg.initialize(256);
                KeyPair keyPairAlice = kpg.generateKeyPair();

                outgoing.put(keyPairAlice.getPublic().getEncoded());

                X509EncodedKeySpec keySpec = new X509EncodedKeySpec(incoming.take());
                ECPublicKey bobPK = (ECPublicKey) KeyFactory.getInstance("EC").generatePublic(keySpec);

                KeyAgreement ec = KeyAgreement.getInstance("ECDH");
                ec.init(keyPairAlice.getPrivate());
                ec.doPhase(bobPK, true);
                byte[] sharedSec = ec.generateSecret();
                print(""+hex(sharedSec)+"\n");

                SecretKeySpec AESsessionKey = new SecretKeySpec(sharedSec,0,16,"AES");
                Cipher aesGen = Cipher.getInstance("AES/CTR/NoPadding");
                aesGen.init(Cipher.ENCRYPT_MODE,AESsessionKey);

                String msg = "I love you bob now with integrity";
                byte[] PT = msg.getBytes("UTF-8");
                // print("CT: "+hex(CT)+"\nIV: "+hex(IV));

                byte[] CT = aesGen.doFinal(PT);
                byte[] IV = aesGen.getIV();

                outgoing.put(IV);
                outgoing.put(CT);
            }
        };

        Agent bob = new Agent("Bob", bob2alice, alice2bob, null, null) {
            // name, outgoing,incoming, cipherKey, cipher
            @Override
            public void execute() throws Exception {
                X509EncodedKeySpec keySpec = new X509EncodedKeySpec(incoming.take());
                ECPublicKey alicePK = (ECPublicKey) KeyFactory.getInstance("EC").generatePublic(keySpec);

                ECParameterSpec ecParameterSpec = alicePK.getParams();

                KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("EC");
                keyPairGen.initialize(ecParameterSpec);
                KeyPair bobKP = keyPairGen.generateKeyPair();

                outgoing.put(bobKP.getPublic().getEncoded());

                KeyAgreement ec = KeyAgreement.getInstance("ECDH");
                ec.init(bobKP.getPrivate());
                ec.doPhase(alicePK, true);
                byte[] sharedSec = ec.generateSecret();
                print(""+hex(sharedSec)+"\n");
                SecretKeySpec AESsessionKey = new SecretKeySpec(sharedSec,0,16,"AES");


                /**
                 * commonly used
                 */
                byte[] IV = incoming.take();
                byte[] CT = incoming.take();

                Cipher aesGen = Cipher.getInstance("AES/CTR/NoPadding");
                IvParameterSpec ivSpec = new IvParameterSpec(IV);
                aesGen.init(Cipher.DECRYPT_MODE,AESsessionKey,ivSpec);
                print("msg: "+new String(aesGen.doFinal(CT),"UTF-8"));

            }
        };

        alice.start();
        bob.start();

    }
}
