package com.defrox.crypto;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.ByteBuffer;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

/**
 * AES-GCM password based encryption and decryption
 * 16 bytes IV, need the same IV and secret keys for encryption and decryption.
 * <p>
 * The output consist of iv, password's salt, encrypted content and auth tag in the following format:
 * output = byte[] {i i i s s s c c c c c c ... a a a}
 * <p>
 * i = IV bytes
 * s = Salt bytes
 * c = content bytes (encrypted content)
 * a = auth tag bytes
 */
public class EncryptorAesGcmPassword {

    private static final String ENCRYPT_ALGO = "AES/GCM/NoPadding";
    private static final int TAG_LENGTH_BYTE = 16;
    private static final int IV_LENGTH_BYTE = 16;
    private static final int SALT_LENGTH_BYTE = 16;
    private static final Charset UTF_8 = StandardCharsets.UTF_8;

    // return a base64 encoded AES encrypted text()
    public static String encrypt(byte[] pText, String password) throws Exception {

        byte[] salt = CryptoUtils.getRandomNonce(SALT_LENGTH_BYTE);

        byte[] iv = CryptoUtils.getRandomNonce(IV_LENGTH_BYTE);

        SecretKey aesKeyFromPassword = CryptoUtils.getAESKeyFromPassword(password.toCharArray(), salt);

        String encodedKey = Base64.getEncoder().encodeToString(aesKeyFromPassword.getEncoded());

        Cipher cipher = Cipher.getInstance(ENCRYPT_ALGO);

        cipher.init(Cipher.ENCRYPT_MODE, aesKeyFromPassword, new GCMParameterSpec(TAG_LENGTH_BYTE * 8, iv));

        byte[] cipherText = cipher.doFinal(pText);

        byte[] cipherTextWithIvSalt = ByteBuffer.allocate(iv.length + salt.length + cipherText.length)
                .put(iv)
                .put(salt)
                .put(cipherText)
                .array();

        byte[] decodedKey = Base64.getDecoder().decode(encodedKey);
        SecretKey originalKey = new SecretKeySpec(decodedKey, 0, decodedKey.length, "AES");

        return Base64.getEncoder().encodeToString(cipherTextWithIvSalt);

    }

    // return a decrypted string from a base64 encoded AES encrypted text()
    private static String decrypt(String cText, String password) throws Exception {

        byte[] decode = Base64.getDecoder().decode(cText.getBytes(UTF_8));

        ByteBuffer bb = ByteBuffer.wrap(decode);

        byte[] iv = new byte[IV_LENGTH_BYTE];
        bb.get(iv);

        byte[] salt = new byte[SALT_LENGTH_BYTE];
        bb.get(salt);

        byte[] cipherText = new byte[bb.remaining()];
        bb.get(cipherText);

        SecretKey aesKeyFromPassword = CryptoUtils.getAESKeyFromPassword(password.toCharArray(), salt);

        Cipher cipher = Cipher.getInstance(ENCRYPT_ALGO);

        cipher.init(Cipher.DECRYPT_MODE, aesKeyFromPassword, new GCMParameterSpec(TAG_LENGTH_BYTE * 8, iv));

        byte[] plainText = cipher.doFinal(cipherText);

        return new String(plainText, UTF_8);

    }

    private static String execute(String[] cmd, Boolean output) {
        Process p;
        try {
            p = Runtime.getRuntime().exec(cmd);
            BufferedReader br = new BufferedReader(new InputStreamReader(p.getInputStream(),StandardCharsets.UTF_8));
            String s;
            StringBuilder res = new StringBuilder();
            try {
                while ((s = br.readLine()) != null) {
                    if (output) {
                        System.out.println(s);
                    }
                    res.append(s);
                }
            } catch(IOException e){
                System.out.println("Exception in reading output "+ e.toString());
            }
            br.close();
            p.waitFor();
            p.destroy();
            return res.toString();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }


    public static void main(String[] args) throws Exception {

        String OUTPUT_FORMAT = "%-30s: %s";
        String PASSWORD = "this is a password";
        String pText = "This is a demo text to encrypt and decrypt";

        System.out.println("\n------ AES GCM Input -------------------------------");
        System.out.println(String.format(OUTPUT_FORMAT, "Text: ", pText));
        System.out.println(String.format(OUTPUT_FORMAT, "Password: ", PASSWORD));

        System.out.println("\n------ AES GCM Data --------------------------------");
        String encryptedTextBase64 = EncryptorAesGcmPassword.encrypt(pText.getBytes(UTF_8), PASSWORD);

        System.out.println("\n------ AES GCM Password-based Encryption Java ------");
        System.out.println(String.format(OUTPUT_FORMAT, "Input (plain text)", pText));
        System.out.println(String.format(OUTPUT_FORMAT, "Encrypted (base64) ", encryptedTextBase64));

        System.out.println("\n------ AES GCM Password-based Decryption Java ------");
        System.out.println(String.format(OUTPUT_FORMAT, "Input (base64)", encryptedTextBase64));
        String decryptedText = EncryptorAesGcmPassword.decrypt(encryptedTextBase64, PASSWORD);
        System.out.println(String.format(OUTPUT_FORMAT, "Decrypted (plain text)", decryptedText));

        System.out.println("\n------ AES GCM Password-based Encryption Python ----");
        System.out.println(String.format(OUTPUT_FORMAT, "Input (plain text)", pText));
        String[] cmd1 = {
                "python",
                "./src/main/resources/encryptor.py",
                "encrypt",
                String.format("-p%s", PASSWORD),
                String.format("-m%s", pText)
        };
        String test1 = execute(cmd1, false);
        System.out.println(String.format(OUTPUT_FORMAT, "Encrypted (base64) ", test1));

        System.out.println("\n------ AES GCM Password-based Decryption Python ----");
        System.out.println(String.format(OUTPUT_FORMAT, "Input (base64)", test1));
        String[] cmd2 = {
                "python",
                "./src/main/resources/encryptor.py",
                "decrypt",
                String.format("-p%s", PASSWORD),
                String.format("-m%s", test1)
        };
        String test2 = execute(cmd2, false);
        System.out.println(String.format(OUTPUT_FORMAT, "Decrypted (plain text)", test2));

        System.out.println("\n------ AES GCM Password-based Test Python ----");
        System.out.println(String.format(OUTPUT_FORMAT, "Input (base64)", pText));
        String[] cmd3 = {
                "python",
                "./src/main/resources/encryptor.py",
                "test",
                String.format("-p%s", PASSWORD),
                String.format("-m%s", test1)
        };
        System.out.println(String.format(OUTPUT_FORMAT, "Output", ""));
        String test3 = execute(cmd3, true);

    }

}
