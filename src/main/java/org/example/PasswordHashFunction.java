package org.example;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

/**
 * This class provides a method for hashing passwords using any algorithm with a specified salt.
 *
 * Reference SQL function
 *
 * ALTER FUNCTION [fn].[PasswordHash]
 * ( @Password NVARCHAR(15),
 *   @Salt VARBINARY(4))
 * RETURNS VARBINARY(255)
 * AS
 * BEGIN
 *   DECLARE @HashedPassword VARBINARY(255) = 0x0100 + @Salt + HASHBYTES('SHA1', CAST(@Password AS VARBINARY(255)) + @Salt);
 *
 *   RETURN @HashedPassword;
 * END;
 *
 */
public class PasswordHashFunction {



    public static void main(String[] args) {
        String hashedPassword = passwordHash("Password1", "24FDF817", "SHA-1");
        System.out.println (hashedPassword);
    }
    /**
     * Hashes a password using the SHA-1 algorithm with a specified salt.
     *
     * @param password     The password to be hashed.
     * @param salt         The salt used for hashing. Should be a string.
     * @param encodingType The encoding type, e.g., "SHA-1".
     * @return The hashed password in hexadecimal format.
     */
    public static String passwordHash(String password, String salt, String encodingType) {
        StringBuilder sb = new StringBuilder("0x0100");
        try {

            byte[] saltBytes = convertHexToBytes(salt);
            byte[] passwordBytes = password.getBytes(StandardCharsets.UTF_16LE); // Java uses UTF-16LE for Unicode

            MessageDigest sha1 = MessageDigest.getInstance("SHA-1");
            sha1.update(passwordBytes);
            sha1.update(saltBytes);
            byte[] hashBytes = sha1.digest();


            for (byte b : saltBytes) {
                sb.append(String.format("%02X", b));
            }
            for (byte b : hashBytes) {
                sb.append(String.format("%02X", b));
            }

            System.out.println(sb.toString());
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        return sb.toString();
    }
    static byte[] convertHexToBytes(String hexString) {
        byte[] bytes = new BigInteger(hexString, 16).toByteArray();
        if (bytes[0] == 0) {
            bytes = Arrays.copyOfRange(bytes, 1, bytes.length);
        }
        return bytes;
    }
}
