package cn.beeKey.cryptography.core;

import java.security.SecureRandom;

public class PrivateKeyToHeadAndBody {

    public byte[][] KeyToHeadBody (byte[] secret) {
        if (secret == null)
            throw new IllegalArgumentException("null secret");
        byte[][] share = new byte[2][(secret.length)];
        byte[] result=new byte[secret.length];
        SecureRandom random = new SecureRandom();
        byte bytes[] = new byte[secret.length];
        random.nextBytes(bytes);
        for (int i = 0 ; i < secret.length; i++) {
            result[i] = (byte)(secret[i]^bytes[i]);
            share[0][i] = result[i];
        }
        for(int j = 0; j < bytes.length; j++) {
            share[1][j] = bytes[j];
        }
        return share;
    }

    public byte[] HeadBodyToHead(byte[] head, byte[] body){
        byte[] result=new byte[head.length];
        for (int i = 0 ; i < body.length; i++) {
            result[i] = (byte)(body[i]^head[i]);
        }
        return result;
    }

    public String StringToHexString(String str) {
        char[] chars = "0123456789ABCDEF".toCharArray();
        StringBuilder sb = new StringBuilder("");
        byte[] bs = str.getBytes();
        int bit;
        for (int i = 0; i < bs.length; i++) {
            bit = (bs[i] & 0x0f0) >> 4;
            sb.append(chars[bit]);
            bit = bs[i] & 0x0f;
            sb.append(chars[bit]);
        }
        return sb.toString().trim();
    }

    public String HexStringToString(String hexStr) {
        String str = "0123456789ABCDEF";
        char[] hexs = hexStr.toCharArray();
        byte[] bytes = new byte[hexStr.length() / 2];
        int n;
        for (int i = 0; i < bytes.length; i++) {
            n = str.indexOf(hexs[2 * i]) * 16;
            n += str.indexOf(hexs[2 * i + 1]);
            bytes[i] = (byte) (n & 0xff);
        }
        return new String(bytes);
    }
}
