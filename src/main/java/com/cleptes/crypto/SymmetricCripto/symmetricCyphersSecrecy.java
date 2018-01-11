package com.cleptes.crypto.SymmetricCripto;

import com.cleptes.crypto.Agents.Agent;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.spec.IvParameterSpec;
import java.security.Key;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;

/// "blah".getBytes( Charset.forName( "UTF-8" ) );
/// "blah".getBytes( StandardCharsets.UTF_8 );

/*
CIPHER ALGORITHMS (v oklepajih je dolžina ključa):
    AES/CBC/NoPadding (128)
    AES/CBC/PKCS5Padding (128)
    AES/ECB/NoPadding (128)
    AES/ECB/PKCS5Padding (128)
    DES/CBC/NoPadding (56)
    DES/CBC/PKCS5Padding (56)
    DES/ECB/NoPadding (56)
    DES/ECB/PKCS5Padding (56)
    DESede/CBC/NoPadding (168)
    DESede/CBC/PKCS5Padding (168)
    DESede/ECB/NoPadding (168)
    DESede/ECB/PKCS5Padding (168)

/// padding info:
PKCS5 - definiran za 8B (64b) bloke
full specs: https://docs.oracle.com/javase/7/docs/technotes/guides/security/StandardNames.html#Cipher
            https://docs.oracle.com/javase/7/docs/api/javax/crypto/Cipher.html
CTR mode ne rab paddinga ker je načeloma stream cipher

 */


public class symmetricCyphersSecrecy {
    //BLOCK CIPHER
    public static final String[] DES = {"DES", "DES/ECB/PKCS5Padding"};
    public static final String[] DES3 = {"DESede", "DESede/ECB/PKCS5Padding"};
    public static final String[] AES_ECB = {"AES", "AES/ECB/PKCS5Padding"};
    public static final String[] AES_CBC = {"AES", "AES/CBC/PKCS5Padding"};
    // STREAM CIPHER
    public static final String[] RC4 = {"RC4", "RC4"};

    public static void main(String[] args ) throws Exception {
        final BlockingQueue<byte[]> bob2alice = new LinkedBlockingQueue<>();
        final BlockingQueue<byte[]> alice2bob = new LinkedBlockingQueue<>();


        // manualy set secret key
        // Key key=new SecretKeySpec("00000123".getBytes("UTF-8"),"DES");
        // System.out.println(new String(key.getEncoded(),"UTF-8"));

        // key generator navadn ime ciphra brez paddinga ipd
        KeyGenerator keyGenerator= KeyGenerator.getInstance("AES");
        //keyGenerator.init(128 /* key size*/); // spec keysize 128, 192, and 256
        Key session_key = keyGenerator.generateKey();

        Agent alice = new Agent("Alice",alice2bob,bob2alice,session_key,null /* more bit specificiran full name: DES/ECB/PKCS5Padding*/){
            // name, outgoing,incoming, cipherKey, cipher
            @Override
            public void execute() throws Exception{
                String msg = "I love you bob";
                // msg to bytearray
                byte[] PT = msg.getBytes("UTF-8");
                // printing msg
                print("msg: "+msg);
                print("PT: "+hex(PT));
                /**
                 * ECB modus operandi
                 */
                /*
                // CORE ENCRYPTION
                Cipher encryption = Cipher.getInstance("DES/ECB/PKCS5Padding");
                encryption.init(Cipher.ENCRYPT_MODE,cipherKey);
                byte[] CT = encryption.doFinal(PT);


                print("CT: "+hex(CT));
                print("CT in string: "+(new String(CT,"UTF-8")));

                outgoing.put(CT);
                */

                /**
                 * AES CBC modus operandi
                 */
                Cipher encryption = Cipher.getInstance("AES/CBC/PKCS5Padding");
                encryption.init(Cipher.ENCRYPT_MODE,cipherKey);
                byte[] CT = encryption.doFinal(PT);
                byte[] IV = encryption.getIV();

                print("CT: "+hex(CT));
                print("IV: "+hex(IV));

                outgoing.put(IV);
                outgoing.put(CT);


            }
        };

        Agent bob = new Agent("Bob",bob2alice,alice2bob,session_key,DES[1]) {
            // name, outgoing,incoming, cipherKey, cipher
            @Override
            public void execute() throws Exception {
                /**
                 * DES modus operandi
                 */
                /*
                byte[] CT = incoming.take();
                print("CT: "+hex(CT));

                Cipher decryption = Cipher.getInstance("DES/ECB/PKCS5Padding");
                decryption.init(Cipher.DECRYPT_MODE,cipherKey);
                byte[] PT = decryption.doFinal(CT);

                print("PT: "+hex(PT));
                print("msg: "+new String(PT,"UTF-8"));
                */

                /**
                 * AES cbc modus operandi
                 */
                byte[] IV = incoming.take();
                byte[] CT = incoming.take();

                IvParameterSpec ivSpec = new IvParameterSpec(IV);
                Cipher decription = Cipher.getInstance("AES/CBC/PKCS5Padding");
                decription.init(Cipher.DECRYPT_MODE,cipherKey,ivSpec);
                byte[] PT = decription.doFinal(CT);
                print("PT: "+hex(PT));
                print("msg: "+new String(PT,"UTF-8"));
            }
        };

        alice.start();
        bob.start();



    }

}
