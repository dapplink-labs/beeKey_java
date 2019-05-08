package cn.beeKey.cryptography.core;

import java.security.SecureRandom;

import cn.beeKey.cryptography.util.Hex;
import org.junit.Assert;
import org.junit.Test;

public class ReadmeTest {

	@Test
	public void test() {
		ThresholdSecretSharing tss = new ThresholdSecretSharing();
		byte[] secret = Hex.convert("9bf8d4b890b391736cec94220d5d41d0c8a2b9555a5385316eecbeb89ce37d61");
		byte[][] shares = tss.createShares(secret, 5, 3, new SecureRandom());
		byte[] recoveredSecret = tss.recoverSecret(shares[0], shares[2], shares[3]);
		String r = new String(recoveredSecret);
		String s = new String(secret);
		System.out.println(r);
		System.out.println(s);
		Assert.assertArrayEquals(recoveredSecret, secret);

	}

	// 密钥拆分为head和body测试
	@Test
	public void testPrivateKeyToHeadBody() {
		byte[] result=new byte[32];
		byte[] secret = Hex.convert("67756F3230313232323232317877777761");
		PrivateKeyToHeadAndBody pr = new  PrivateKeyToHeadAndBody();
		byte[][] ret = new byte[2][32];
		ret = pr.KeyToHeadBody(secret);
		System.out.println("body = " + Hex.convert(ret[0]));
		System.out.println("head = " + Hex.convert(ret[1]));
	}

	// 使用head和body恢复出完整的密钥
	@Test
	public void testRecoveredKey() {
		byte[] result=new byte[32];
		byte[] body = Hex.convert("0958D2BEDFE0EB17BBF6FC");
		byte[] head = Hex.convert("6E2DBD8CEFD1D9248CC0CE");
		PrivateKeyToHeadAndBody pr = new  PrivateKeyToHeadAndBody();
		result = pr.HeadBodyToHead(body, head);
		System.out.println("recoverKey = " + Hex.convert(result));
	}

	@Test
	public void testStringToHexString() {
		String  str = "guo201222221xwwwa";
		PrivateKeyToHeadAndBody pr = new  PrivateKeyToHeadAndBody();
		System.out.println(pr.StringToHexString(str));
	}

	@Test
	public void testHexStringToString() {
		String hexStr= "67756F3230313232323232317877777761";
		PrivateKeyToHeadAndBody pr = new  PrivateKeyToHeadAndBody();
		System.out.println(pr.HexStringToString(hexStr));
	}

}