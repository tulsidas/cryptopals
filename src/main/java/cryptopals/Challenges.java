package cryptopals;

import static com.google.common.base.Preconditions.checkArgument;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.BitSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.binary.Hex;
import org.junit.Test;

import com.google.common.base.Charsets;
import com.google.common.base.Joiner;
import com.google.common.base.Preconditions;
import com.google.common.base.Splitter;
import com.google.common.base.Strings;
import com.google.common.collect.ImmutableList;
import com.google.common.collect.ImmutableMap;
import com.google.common.collect.Iterables;
import com.google.common.collect.Lists;
import com.google.common.collect.Maps;
import com.google.common.collect.Ordering;
import com.google.common.collect.Sets;
import com.google.common.io.Resources;
import com.google.common.primitives.Bytes;

public class Challenges {

  private static final int BLOCK_SIZE = 16;

  private static final String UNKNOWN_STRING = "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnk";

  private static SecureRandom RND = new SecureRandom();

  @Test
  public void challenge1() throws Exception {
    assertEquals("SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t", toBase64(fromHex(
        "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d")));
  }

  private String toBase64(byte[] in) {
    return Base64.encodeBase64String(in);
  }

  private byte[] fromHex(String in) throws DecoderException {
    return Hex.decodeHex(in.toCharArray());
  }

  @Test
  public void challenge2() throws Exception {
    assertEquals("746865206b696420646f6e277420706c6179",
        toHex(xor(fromHex("1c0111001f010100061a024b53535009181c"),
            fromHex("686974207468652062756c6c277320657965"))));
  }

  private String toHex(byte[] in) {
    return Hex.encodeHexString(in);
  }

  private byte[] xor(byte[] a, byte[] b) {
    checkArgument(a.length == b.length,
        "cannot xor different length buffers (" + a.length + " vs " + b.length + ")");

    byte[] ret = new byte[a.length];
    for (int i = 0; i < a.length; i++) {
      ret[i] = (byte) (a[i] ^ b[i]);
    }

    return ret;
  }

  @Test
  public void challenge3() throws Exception {
    assertEquals('X',
        guessSingleCharXor(fromHex("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736")));
  }

  private byte guessSingleCharXor(byte[] in) throws DecoderException {
    double deviation = Double.MAX_VALUE;
    byte ret = 0x00;

    for (int k = Byte.MIN_VALUE; k <= Byte.MAX_VALUE; k++) {
      byte[] key = new byte[in.length];
      Arrays.fill(key, (byte) k);

      String guess = new String(xor(in, key));
      double newDeviation = deviation(guess);

      if (newDeviation < deviation) {
        deviation = newDeviation;
        ret = (byte) k;
      }
    }

    return ret;
  }

  private static double[] FREQS = { 0.0834, 0.0154, 0.0273, 0.0414, 0.126, 0.0203, 0.0192, 0.0611, 0.0671,
      0.0023, 0.0087, 0.0424, 0.0253, 0.068, 0.077, 0.0166, 0.0009, 0.0568, 0.0611, 0.0937, 0.0285, 0.0106,
      0.0234, 0.002, 0.0204, 0.0006 };

  private static double deviation(String inString) {
    String upString = inString.toUpperCase();
    int[] charCounts = new int[FREQS.length];
    double[] charFreqs = new double[FREQS.length];
    int totCount = 0;

    double deviation = 0;

    for (char c : upString.toCharArray()) {
      int index = (int) (c - 'A');
      if (index >= 0 && index < 26) {
        charCounts[index]++;
        totCount++;
      }
      else if (c != ' ') { // non ascii (excluding space) chars add deviation
        deviation += 0.2;
      }
    }
    // avoid divide by zero
    totCount = Math.max(totCount, 1);

    // produce freq table and compare frequency of each letter to frequency in text and add difference^2 to
    // score for that language
    for (int i = 0; i < charFreqs.length; i++) {
      charFreqs[i] = charCounts[i] / ((double) totCount);

      deviation += Math.pow(Math.abs(FREQS[i] - charFreqs[i]), 2);
    }

    return deviation;
  }

  @Test
  public void challenge4() throws Exception {
    // for (String line : Resources.readLines(Resources.getResource("4.txt"), StandardCharsets.UTF_8)) {
    // System.out.println(guessSingleCharXor(line));
    // }
  }

  @Test
  public void challenge5() throws Exception {
    assertEquals(
        "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f",
        toHex(repeatingKeyXor(
            "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal".getBytes(),
            "ICE".getBytes())));
  }

  private byte[] repeatingKeyXor(byte[] in, byte[] key) {
    Iterator<Byte> keyStream = Iterables.cycle(Bytes.asList(key)).iterator();

    byte[] ret = new byte[in.length];
    for (int i = 0; i < in.length; i++) {
      ret[i] = (byte) (in[i] ^ keyStream.next());
    }

    return ret;
  }

  @Test
  public void challenge6() throws Exception {
    assertEquals(37, hammingDistance("this is a test".getBytes(), "wokka wokka!!!".getBytes()));

    byte[] encrypted = fromBase64(Resources.toString(Resources.getResource("6.txt"), StandardCharsets.UTF_8));

    for (int keySize : guessRepeatingXorKeySize(encrypted, 3)) {
      System.out.println("Key size " + keySize);
      List<List<Byte>> partition = Lists.partition(Bytes.asList(encrypted), keySize);

      for (int i = 0; i < keySize; i++) {
        List<Byte> transposed = Lists.newArrayList();
        for (List<Byte> chunk : partition) {
          if (chunk.size() > i) {
            transposed.add(chunk.get(i));
          }
        }

        System.out.print((char) guessSingleCharXor(Bytes.toArray(transposed)));
      }
      System.out.println();
    }
  }

  private List<Integer> guessRepeatingXorKeySize(byte[] encrypted, int count) {
    Map<Double, Integer> guesses = Maps.newHashMap();

    for (int guessKeySize = 2; guessKeySize < 40; guessKeySize++) {
      byte[] chunk1 = Arrays.copyOfRange(encrypted, guessKeySize * 0, guessKeySize * 1);
      byte[] chunk2 = Arrays.copyOfRange(encrypted, guessKeySize * 1, guessKeySize * 2);
      byte[] chunk3 = Arrays.copyOfRange(encrypted, guessKeySize * 2, guessKeySize * 3);
      byte[] chunk4 = Arrays.copyOfRange(encrypted, guessKeySize * 3, guessKeySize * 4);

      double distance = (hammingDistance(chunk1, chunk2) + hammingDistance(chunk2, chunk3)
          + hammingDistance(chunk3, chunk4)) / (double) (guessKeySize * 3);

      guesses.put(distance, guessKeySize);
    }

    List<Integer> ret = Lists.newArrayListWithCapacity(count);
    for (double distance : Ordering.natural().leastOf(guesses.keySet(), count)) {
      ret.add(guesses.get(distance));
    }

    return ret;
  }

  private int hammingDistance(byte[] left, byte[] right) {
    checkArgument(left.length == right.length);

    int ret = 0;
    for (int i = 0; i < left.length; i++) {
      ret += Integer.bitCount(left[i] ^ right[i]);
    }

    return ret;
  }

  private byte[] fromBase64(String in) {
    return Base64.decodeBase64(in);
  }

  @Test
  public void challenge7() throws Exception {
    byte[] encrypted = fromBase64(Resources.toString(Resources.getResource("7.txt"), StandardCharsets.UTF_8));

    assertTrue(new String(aes128ecbDecrypt(encrypted, "YELLOW SUBMARINE".getBytes()))
        .startsWith("I'm back and I'm ringin' the bell"));
  }

  private byte[] aes128ecbDecrypt(byte[] block, byte[] key) {
    Preconditions.checkArgument(block.length == BLOCK_SIZE);
    Preconditions.checkArgument(key.length == BLOCK_SIZE);

    try {
      Cipher cipher = Cipher.getInstance("AES/ECB/NoPadding");
      SecretKeySpec skeySpec = new SecretKeySpec(key, "AES");
      cipher.init(Cipher.DECRYPT_MODE, skeySpec);
      return cipher.doFinal(block);
    }
    catch (Exception e) {
      throw new RuntimeException(e);
    }
  }

  @Test
  public void challenge8() throws Exception {
    for (String line : Resources.readLines(Resources.getResource("8.txt"), StandardCharsets.UTF_8)) {
      byte[] encrypted = fromBase64(line);
      if (guessAESECB(encrypted)) {
        assertTrue(
            line.startsWith("d880619740a8a19b7840a8a31c810a3d08649af70dc06f4fd5d2d69c744cd283e2dd052f6b6"));
      }
    }
  }

  private boolean guessAESECB(byte[] encrypted) {
    Set<byte[]> set = Sets.newHashSet();
    for (int i = 0; i < encrypted.length / 16; i++) {
      byte[] chunk = Arrays.copyOfRange(encrypted, i * 16, (i + 1) * 16);

      if (set.stream().filter(prev -> Arrays.equals(prev, chunk)).findAny().isPresent()) {
        return true;
      }
      else {
        set.add(chunk);
      }
    }

    return false;
  }

  @Test
  public void challenge9() throws Exception {
    assertEquals("YELLOW SUBMARINE\u0002\u0002", new String(pad_pkcs7("YELLOW SUBMARINE".getBytes(), 18)));
  }

  private byte[] pad_pkcs7(byte[] data, int size) {
    int l = data.length;
    int add = size - (l % size);

    byte[] ret = Arrays.copyOf(data, l + add);

    for (int i = 0; i < add; i++) {
      ret[l + i] = (byte) add;
    }

    return ret;
  }

  @Test
  public void challenge10() throws Exception {
    String file = Resources.asCharSource(Resources.getResource("10.txt"), Charsets.US_ASCII).read()
        .replaceAll("\n", "");
    byte[] data = fromBase64(file);

    byte[] key = "YELLOW SUBMARINE".getBytes();
    byte[] iv = new byte[BLOCK_SIZE];

    assertTrue(new String(unpad_pkcs7(aes128cbcDecrypt(data, iv, key)))
        .startsWith("I'm back and I'm ringin' the bell"));
  }

  private byte[] aes128cbcDecrypt(byte[] data, byte[] iv, byte[] key) {
    byte[] block = Arrays.copyOf(data, BLOCK_SIZE);
    byte[] decrypted = aes128ecbDecrypt(block, key);
    byte[] xored = xor(decrypted, iv);

    if (data.length > BLOCK_SIZE) {
      // el resto
      byte[] rest = Arrays.copyOfRange(data, BLOCK_SIZE, data.length);
      rest = aes128cbcDecrypt(rest, block, key);

      xored = Bytes.concat(xored, rest);
    }

    return xored;
  }

  private byte[] unpad_pkcs7(byte[] data) throws Exception {
    // System.out.println(Arrays.toString(data));
    byte last = data[data.length - 1];

    // checo que los últimos bytes sean de padding
    if (last <= 0 || last > data.length) {
      throw new BadPaddingException();
    }

    byte[] cola = Arrays.copyOfRange(data, data.length - last, data.length);
    for (byte b : cola) {
      if (b != last) {
        throw new BadPaddingException();
      }
    }

    return Arrays.copyOfRange(data, 0, data.length - last);
  }

  @Test
  public void challenge11() throws Exception {
    byte[] encrypted = c11_encryptionOracle(
        "buenos días su señoría matarile lire ron, palalila palalila matarile lire ron".getBytes());

    if (guessAESECB(encrypted)) {
      System.out.println("ECB");
    }
    else {
      System.out.println("CBC");
    }
  }

  private byte[] c11_encryptionOracle(byte[] in) throws Exception {
    byte[] key = randomAESKey();
    byte[] iv = randomAESKey();

    int c = RND.nextInt(5) + 30;
    byte[] extra = Strings.repeat("x", c).getBytes();
    byte[] appended = Bytes.concat(extra, in, extra);

    if (RND.nextBoolean()) {
      System.out.println("-cbc-");
      return aes128cbcEncrypt(appended, iv, key);
    }
    else {
      System.out.println("-ecb-");
      return aes128ecbEncrypt(pad_pkcs7(appended, BLOCK_SIZE), key);
    }
  }

  private static byte[] randomAESKey() {
    byte[] key = new byte[BLOCK_SIZE];
    RND.nextBytes(key);

    return key;
  }

  private byte[] aes128cbcEncrypt(byte[] data, byte[] iv, byte[] key) {
    byte[] block = Arrays.copyOf(data, BLOCK_SIZE);
    byte[] xored = xor(block, iv);
    byte[] encrypted = aes128ecbEncrypt(xored, key);

    if (data.length > BLOCK_SIZE) {
      // el resto
      byte[] rest = Arrays.copyOfRange(data, BLOCK_SIZE, data.length);
      rest = aes128cbcEncrypt(rest, encrypted, key);

      encrypted = Bytes.concat(encrypted, rest);
    }

    return encrypted;
  }

  private byte[] aes128ecbEncrypt(byte[] block, byte[] key) {
    Preconditions.checkArgument(block.length == BLOCK_SIZE);
    Preconditions.checkArgument(key.length == BLOCK_SIZE);

    try {
      Cipher cipher = Cipher.getInstance("AES/ECB/NoPadding");
      SecretKeySpec skeySpec = new SecretKeySpec(key, "AES");
      cipher.init(Cipher.ENCRYPT_MODE, skeySpec);
      return cipher.doFinal(block);
    }
    catch (Exception e) {
      throw new RuntimeException(e);
    }
  }

  @Test
  public void challenge12() throws Exception {
    final byte[] key = randomAESKey();
    byte[] unknownString = fromBase64(UNKNOWN_STRING);
    int bytes = (int) Math.ceil(unknownString.length / 8.0);

    StringBuffer buf = new StringBuffer();
    for (int i = 0; i < bytes; i++) {
      buf.append(c12_crackByte(unknownString, i, key));
    }

    assertTrue(buf.toString().startsWith(
        "Rollin' in my 5.0\nWith my rag-top down so my hair can blow\nThe girlies on standby waving just to say hi\nDid you stop? No, I just drove by"));
  }

  private String c12_crackByte(byte[] unknownString, int byteNumber, byte[] key) throws Exception {
    String decoded = "";
    for (int i = BLOCK_SIZE - 1; i >= 0; i--) {
      String fruta = Strings.repeat("$", i);
      byte[] oneLess = Arrays.copyOfRange(c12_encryptionOracle(fruta, unknownString, key, byteNumber), 0,
          BLOCK_SIZE);

      for (byte b = Byte.MIN_VALUE; b < Byte.MAX_VALUE; b++) {
        String guess = fruta + decoded + (char) b;
        byte[] encrypted = Arrays.copyOfRange(c12_encryptionOracle(guess, unknownString, key, byteNumber), 0,
            BLOCK_SIZE);

        if (Arrays.equals(encrypted, oneLess)) {
          decoded += (char) b;
          break;
        }
      }
    }

    return new String(unpad_pkcs7(decoded.getBytes()));
  }

  private byte[] c12_encryptionOracle(String injected, byte[] unknownString, byte[] key, int byteNumber)
      throws Exception {
    byte[] unknown = Arrays.copyOfRange(unknownString, 8 * byteNumber, 8 * (byteNumber + 1));
    return aes128ecbEncrypt(pad_pkcs7(Bytes.concat(injected.getBytes(), unknown), BLOCK_SIZE), key);
  }

  @Test
  public void challenge13() throws Exception {
    byte[] key = randomAESKey();

    // .........1.........2.........3.........4.........5.........6.........
    // 123456789012345678901234567890123456789012345678901234567890123456789
    // email=__________adminPPPPPPPPPPP&uid=10&role=user
    // email=email@foo.com&uid=10&role=user

    String poison = Strings.repeat("_", 10) + "admin" + Strings.repeat("\u000b", 0x0b);
    byte[] chunk1 = aes128ecbEncrypt(pad_pkcs7(c13_profileFor(poison).getBytes(), BLOCK_SIZE), key);

    String user = "email@foo.com";
    byte[] chunk2 = aes128ecbEncrypt(pad_pkcs7(c13_profileFor(user).getBytes(), BLOCK_SIZE), key);

    byte[] hacked = Bytes.concat(Arrays.copyOfRange(chunk2, 0, 32), Arrays.copyOfRange(chunk1, 16, 32));

    assertEquals("admin", c13_login(hacked, key));
  }

  private String c13_login(byte[] token, byte[] key) throws Exception {
    byte[] decrypted = aes128ecbDecrypt(token, key);
    Map<String, String> cookie = c13_parseCookie(new String(unpad_pkcs7(decrypted)));
    return cookie.get("role");
  }

  private String c13_profileFor(String email) {
    return Joiner.on('&').withKeyValueSeparator('=').join(ImmutableMap.of("email",
        email.replaceAll("&", ".").replaceAll("=", "."), "uid", "10", "role", "user"));
  }

  private Map<String, String> c13_parseCookie(String cookie) {
    return Splitter.on('&').trimResults().withKeyValueSeparator("=").split(cookie);
  }

  @Test
  public void challenge14() throws Exception {
    // byte[] randomPrefix = new byte[RND.nextInt(30)];
    // RND.nextBytes(randomPrefix);
    //
    // final byte[] key = randomAESKey();
    //
    // byte[] unknownString = fromBase64(UNKNOWN_STRING);
    // byte[] inject = new byte[0];
    //
    // aes128ecbEncrypt(Bytes.concat(randomPrefix, inject, unknownString), key);
    fail("to-do");
  }

  @Test
  public void challenge15() throws Exception {
    unpad_pkcs7("ICE ICE BABY\u0004\u0004\u0004\u0004".getBytes());

    try {
      unpad_pkcs7("ICE ICE BABY\u0005\u0005\u0005\u0005".getBytes());
      fail("debería haber fallado, mal padding");
    }
    catch (BadPaddingException e) {}

    try {
      unpad_pkcs7("ICE ICE BABY\u0001\u0002\u0003\u0004".getBytes());
      fail("debería haber fallado, mal padding");
    }
    catch (BadPaddingException e) {}
  }

  @Test
  public void challenge16() throws Exception {
    byte[] iv = randomAESKey();
    byte[] key = randomAESKey();

    // ...............|...............|...............|...............|...............|.........
    // .........1.........2.........3.........4.........5.........6.........7.........8.........
    // 12345678901234567890123456789012345678901234567890123456789012345678901234567890123456789
    // comment1=cooking%20MCs;userdata=:admin~true;comment2=%20like%20a%20pound%20of%20bacon

    byte[] encrypted = c16_encryptUserData(":admin=true", iv, key);

    // bit flip!
    BitSet bitSet = BitSet.valueOf(encrypted);

    // : to ;
    bitSet.flip(128);

    // ~ to =
    bitSet.flip(176);
    bitSet.flip(177);
    bitSet.flip(182);

    assertTrue(c16_loginAdmin(bitSet.toByteArray(), iv, key));
  }

  private byte[] c16_encryptUserData(String in, byte[] iv, byte[] key) throws Exception {
    String data = "comment1=cooking%20MCs;userdata=" + in.replaceAll(";", ":").replaceAll("=", "~")
        + ";comment2=%20like%20a%20pound%20of%20bacon";

    return aes128cbcEncrypt(pad_pkcs7(data.getBytes(), BLOCK_SIZE), iv, key);
  }

  private boolean c16_loginAdmin(byte[] token, byte[] iv, byte[] key) throws Exception {
    String decrypted = new String(unpad_pkcs7(aes128cbcDecrypt(token, iv, key)));
    return decrypted.contains(";admin=true;");
  }

  @Test
  public void challenge17() throws Exception {
    byte[] iv = randomAESKey();
    byte[] key = randomAESKey();
    byte[] encrypted = c17_encrypt(iv, key);

    int bloques = encrypted.length / BLOCK_SIZE;

    StringBuilder buf = new StringBuilder();

    for (int i = 0; i < bloques - 1; i++) {
      // armo 2 bloques, 1 con basura y el otro con el bloque a crackear
      byte[] c1 = Arrays.copyOfRange(encrypted, BLOCK_SIZE * i, BLOCK_SIZE * (i + 1));
      byte[] c2 = Arrays.copyOfRange(encrypted, BLOCK_SIZE * (i + 1), BLOCK_SIZE * (i + 2));

      byte[] cracked = c17_crackBlock(c1, c2, iv, key);
      buf.append(new String(cracked));
    }

    System.out.println(Strings.repeat("?", 8) + buf.toString());
  }

  private byte[] c17_crackBlock(byte[] c1, byte[] c2, byte[] iv, byte[] key) throws Exception {
    byte[] poison = new byte[BLOCK_SIZE];
    byte[] found = new byte[BLOCK_SIZE];
    byte[] plain = new byte[BLOCK_SIZE];

    // byte x byte
    for (int i = 0; i < BLOCK_SIZE; i++) {
      // set poison
      for (int j = 1; j <= i; j++) {
        poison[BLOCK_SIZE - j] = (byte) (found[j - 1] ^ j ^ (i + 1)); // algo que haga P=i+1
      }

      // find padding
      for (byte b = Byte.MIN_VALUE; b < Byte.MAX_VALUE; b++) {
        poison[BLOCK_SIZE - i - 1] = b;

        if (c17_check(Bytes.concat(poison, c2), iv, key)) {
          found[i] = b;
          plain[i] = (byte) ((i + 1) ^ b ^ c1[BLOCK_SIZE - i - 1]);
          break;
        }
      }
    }

    Bytes.reverse(plain);

    return plain;
  }

  private byte[] c17_encrypt(byte[] iv, byte[] key) throws Exception {
    String data = CHALLENGE_17_STRINGS.get(RND.nextInt(CHALLENGE_17_STRINGS.size()));

    return aes128cbcEncrypt(pad_pkcs7(data.getBytes(), BLOCK_SIZE), iv, key);
  }

  private boolean c17_check(byte[] encrypted, byte[] iv, byte[] key) throws Exception {
    try {
      unpad_pkcs7(aes128cbcDecrypt(encrypted, iv, key));
      return true;
    }
    catch (BadPaddingException e) {
      return false;
    }
  }

  private static final ImmutableList<String> CHALLENGE_17_STRINGS = ImmutableList.of(
      "MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=",
      "MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=",
      "MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==",
      "MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==",
      "MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl",
      "MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==",
      "MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==",
      "MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=",
      "MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=",
      "MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93");

  @Test
  public void challenge18() throws Exception {
    final String encrypted = "L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ==";
    final String key = "YELLOW SUBMARINE";
    final long nonce = 0;

    assertEquals("Yo, VIP Let's kick it Ice, Ice, baby Ice, Ice, baby ",
        new String(aes128ctr(fromBase64(encrypted), key.getBytes(), nonce)));
  }

  private byte[] aes128ctr(byte[] in, byte[] key, long nonce) {
    ByteBuffer ret = ByteBuffer.allocate(in.length);
    for (long ctr = 0; ctr < Math.ceil(in.length / (float) BLOCK_SIZE); ctr++) {
      int from = (int) ctr * BLOCK_SIZE;
      int to = (int) (ctr + 1) * BLOCK_SIZE;

      byte[] keystream = aes128ecbEncrypt(ctr(nonce, ctr), key);
      byte[] block = Arrays.copyOfRange(in, from, to);

      byte[] xored = xor(block, keystream);

      if (to <= in.length) {
        ret.put(xored);
      }
      else {
        ret.put(Arrays.copyOf(xored, in.length - from));
      }
    }

    return ret.array();
  }

  private byte[] ctr(long nonce, long ctr) {
    return ByteBuffer.allocate(Long.BYTES * 2).order(ByteOrder.LITTLE_ENDIAN).putLong(nonce).putLong(ctr)
        .array();
  }

  @Test
  public void challenge19() throws Exception {
    byte[] key = "a fancy password".getBytes();

    final List<String> CHALLENGE_19_STRINGS = ImmutableList.of("SSBoYXZlIG1ldCB0aGVtIGF0IGNsb3NlIG9mIGRheQ==",
        "Q29taW5nIHdpdGggdml2aWQgZmFjZXM=", "RnJvbSBjb3VudGVyIG9yIGRlc2sgYW1vbmcgZ3JleQ==",
        "RWlnaHRlZW50aC1jZW50dXJ5IGhvdXNlcy4=", "SSBoYXZlIHBhc3NlZCB3aXRoIGEgbm9kIG9mIHRoZSBoZWFk",
        "T3IgcG9saXRlIG1lYW5pbmdsZXNzIHdvcmRzLA==", "T3IgaGF2ZSBsaW5nZXJlZCBhd2hpbGUgYW5kIHNhaWQ=",
        "UG9saXRlIG1lYW5pbmdsZXNzIHdvcmRzLA==", "QW5kIHRob3VnaHQgYmVmb3JlIEkgaGFkIGRvbmU=",
        "T2YgYSBtb2NraW5nIHRhbGUgb3IgYSBnaWJl", "VG8gcGxlYXNlIGEgY29tcGFuaW9u",
        "QXJvdW5kIHRoZSBmaXJlIGF0IHRoZSBjbHViLA==", "QmVpbmcgY2VydGFpbiB0aGF0IHRoZXkgYW5kIEk=",
        "QnV0IGxpdmVkIHdoZXJlIG1vdGxleSBpcyB3b3JuOg==", "QWxsIGNoYW5nZWQsIGNoYW5nZWQgdXR0ZXJseTo=",
        "QSB0ZXJyaWJsZSBiZWF1dHkgaXMgYm9ybi4=", "VGhhdCB3b21hbidzIGRheXMgd2VyZSBzcGVudA==",
        "SW4gaWdub3JhbnQgZ29vZCB3aWxsLA==", "SGVyIG5pZ2h0cyBpbiBhcmd1bWVudA==",
        "VW50aWwgaGVyIHZvaWNlIGdyZXcgc2hyaWxsLg==", "V2hhdCB2b2ljZSBtb3JlIHN3ZWV0IHRoYW4gaGVycw==",
        "V2hlbiB5b3VuZyBhbmQgYmVhdXRpZnVsLA==", "U2hlIHJvZGUgdG8gaGFycmllcnM/",
        "VGhpcyBtYW4gaGFkIGtlcHQgYSBzY2hvb2w=", "QW5kIHJvZGUgb3VyIHdpbmdlZCBob3JzZS4=",
        "VGhpcyBvdGhlciBoaXMgaGVscGVyIGFuZCBmcmllbmQ=", "V2FzIGNvbWluZyBpbnRvIGhpcyBmb3JjZTs=",
        "SGUgbWlnaHQgaGF2ZSB3b24gZmFtZSBpbiB0aGUgZW5kLA==", "U28gc2Vuc2l0aXZlIGhpcyBuYXR1cmUgc2VlbWVkLA==",
        "U28gZGFyaW5nIGFuZCBzd2VldCBoaXMgdGhvdWdodC4=", "VGhpcyBvdGhlciBtYW4gSSBoYWQgZHJlYW1lZA==",
        "QSBkcnVua2VuLCB2YWluLWdsb3Jpb3VzIGxvdXQu", "SGUgaGFkIGRvbmUgbW9zdCBiaXR0ZXIgd3Jvbmc=",
        "VG8gc29tZSB3aG8gYXJlIG5lYXIgbXkgaGVhcnQs", "WWV0IEkgbnVtYmVyIGhpbSBpbiB0aGUgc29uZzs=",
        "SGUsIHRvbywgaGFzIHJlc2lnbmVkIGhpcyBwYXJ0", "SW4gdGhlIGNhc3VhbCBjb21lZHk7",
        "SGUsIHRvbywgaGFzIGJlZW4gY2hhbmdlZCBpbiBoaXMgdHVybiw=", "VHJhbnNmb3JtZWQgdXR0ZXJseTo=",
        "QSB0ZXJyaWJsZSBiZWF1dHkgaXMgYm9ybi4=");

    List<byte[]> ciphers = CHALLENGE_19_STRINGS.stream().map(str -> aes128ctr(fromBase64(str), key, 0))
        .collect(Collectors.toList());

    byte[] keystream = new byte[BLOCK_SIZE];

    for (int i = 0; i < BLOCK_SIZE; i++) {
      byte[] guess = new byte[BLOCK_SIZE];
      int score = -999;
      byte best = 0;
      for (int b = Byte.MIN_VALUE; b <= Byte.MAX_VALUE; b++) {
        guess[i] = (byte) b;

        List<byte[]> guessedPlainTexts = ciphers.stream()
            .map(bytes -> xor(Arrays.copyOf(bytes, BLOCK_SIZE), guess)).collect(Collectors.toList());

        int _score = score(guessedPlainTexts, i);
        if (_score > score) {
          score = _score;
          best = guess[i];
        }
      }

      keystream[i] = best;
    }

    assertEquals("I have met them ", new String(xor(Arrays.copyOf(ciphers.get(0), BLOCK_SIZE), keystream)));
    assertEquals("Coming with vivi", new String(xor(Arrays.copyOf(ciphers.get(1), BLOCK_SIZE), keystream)));
    assertEquals("From counter or ", new String(xor(Arrays.copyOf(ciphers.get(2), BLOCK_SIZE), keystream)));
    assertEquals("Eighteenth-centu", new String(xor(Arrays.copyOf(ciphers.get(3), BLOCK_SIZE), keystream)));
    assertEquals("I have passed wi", new String(xor(Arrays.copyOf(ciphers.get(4), BLOCK_SIZE), keystream)));
  }

  private int score(final List<byte[]> chars, final int pos) {
    return chars.stream().map(bytes -> (char) bytes[pos]).mapToInt(c -> {
      if (isFrequent(c)) {
        return 5;
      }
      else if (isLetterOrSpace(c)) {
        return 3;
      }
      else if (isSymbol(c)) {
        return 1;
      }
      else {
        return -1;
      }
    }).sum();
  }

  private boolean isFrequent(char c) {
    return Arrays.binarySearch("AEHINORSTaehinorst".toCharArray(), c) >= 0;
  }

  private boolean isLetterOrSpace(char c) {
    return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || c == ' ';
  }

  private boolean isSymbol(char c) {
    return c == ',' || c == '\'' || c == '.';
  }
}
