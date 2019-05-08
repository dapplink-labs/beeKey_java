package cn.beeKey.cryptography.core;

import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Random;

import cn.beeKey.cryptography.util.Hex;
import cn.beeKey.cryptography.util.TestThread;
import junit.framework.Assert;

import org.junit.Test;

import cn.beeKey.cryptography.util.Combination;

public class ThresholdSecretSharingTest {
	private static Random rnd = new SecureRandom();
	private static int TEST_LOAD_FACTOR = 1;

	@Test
	public void kat() {
		ThresholdSecretSharing tss = new ThresholdSecretSharing();
		byte[] secret = Hex.convert("7465737400");
		//System.out.println("secret =" + secret);
		byte[][] comb = { Hex.convert("01B9FA07E185"), Hex.convert("02F5409B4511") };
		//System.out.println("comb =" + comb);
		byte[] recovered = tss.recoverSecret(comb);
		String s = new String(recovered);
		System.out.println("recovered =" + s);
		System.out.println("secret =" + secret);
		Assert.assertTrue("array mismatch", Arrays.equals(secret, recovered));
	}

	@Test
	public void shareIndexNotZero() {
		ThresholdSecretSharing tss = new ThresholdSecretSharing();
		byte[][] comb = { Hex.convert("FFB9FA07E185"), Hex.convert("00F5409B4511") };
		try {
			String ss = new String(tss.recoverSecret(comb));
			System.out.println(ss);
			Assert.fail("IllegalArgumentException expected");
		} catch (IllegalArgumentException z) {
			Assert.assertEquals("Message exception mismatch", "invalid share index: 0", z.getMessage());
			System.out.println(z.getMessage());
		}
	}

	// 密钥的拆分和恢复测试代码
	@Test
	public void keyCutAndRecover() throws Exception {
		ThresholdSecretSharing tss = new ThresholdSecretSharing();
		byte[] secret = Hex.convert("0958D2BEDFE0EB17BBF6FC");
		System.out.println("原私钥 = " + Hex.convert(secret));
		byte[][] shares = tss.createShares(secret, 4, 3, new Random(0));
		System.out.println("拆分1 = " +Hex.convert(shares[0]));
		System.out.println("拆分2 = " +Hex.convert(shares[1]));
		System.out.println("拆分3 = " +Hex.convert(shares[2]));
		System.out.println("拆分4 = " +Hex.convert(shares[3]));
		byte[] recovered = tss.recoverSecret(shares);
		System.out.println("恢复私钥 = " +Hex.convert(recovered));
		Assert.assertTrue("array mismatch", Arrays.equals(secret, recovered));
	}

	// 密钥的恢复测试
	@Test
	public void keyRecover() {
		ThresholdSecretSharing tss = new ThresholdSecretSharing();
		byte[] secret = Hex.convert("0000000000000000000000000067756f7368696a69616e673230313233373632");
		byte[][] comb = { Hex.convert("0194885849E4ED99D142B580455961F8FA7A3128B668EFF6FC1AE32C88E7E44257"), Hex.convert("02F3EBF7043D8F69B7A21DAE19C53F302F0D9CE3E13A2E71E05DB4119A845998B6"), Hex.convert("036763AF4DD962F066E0A82E5C9C39BDBA04C5A23D3BA0E97B75670C20508AECD3")};
		byte[] recovered = tss.recoverSecret(comb);
		System.out.println("recovered =" + Hex.convert(recovered));
		System.out.println("secret =" + Hex.convert(secret));
		Assert.assertTrue("array mismatch", Arrays.equals(secret, recovered));
	}

	@Test
	public void testNotEnoughtSharesFail() {
		ThresholdSecretSharing tss = new ThresholdSecretSharing();
		byte[] secret = Hex.convert("cc4a97e7");
		byte[][] comb = { Hex.convert("01446bc13d"), Hex.convert("02c0a65764"), Hex.convert("030c6442f8") };
		byte[] recovered = tss.recoverSecret(comb);
		System.out.println("recovered =" + recovered);
		System.out.println("secret =" + secret);
		Assert.assertFalse("surprise", Arrays.equals(secret, recovered));
	}

	@Test
	public void testSmallSecrets() {
		test(500 * TEST_LOAD_FACTOR, 1, 256, 3, 10, 3, 5);
	}

	@Test
	public void testMediumSecrets() {
		test(100 * TEST_LOAD_FACTOR, 256, 512, 3, 10, 3, 5);
	}

	@Test
	public void testBigSecrets() {
		test(10 * TEST_LOAD_FACTOR, 32768, 65535, 3, 10, 3, 5);
	}

	private void test(int iterations, int minSecretLen, int maxSecretLen, int minShares, int maxShares, int minThreshold, int maxThreshold) {
		System.out.print(String.format("test%n iterations:%s%n secret len:%s-%s%n shares:%s-%s%n threshold:%s-%s%n", iterations, minSecretLen, maxSecretLen,
				minShares, maxShares, minThreshold, maxThreshold));
		ThresholdSecretSharing tss = new ThresholdSecretSharing();
		long generateMs = 0;
		long recoverMs = 0;
		long T0;
		long combinations = 0;
		double secretAvg = 0;
		double thresholdAvg = 0;
		double shareAvg = 0;
		for (int i = 0; i < iterations; i++) {
			T0 = System.currentTimeMillis();
			if (i % (10 * TEST_LOAD_FACTOR) == 0)
				System.out.print(".");
			int secreLen = rnd.nextInt(maxSecretLen - minSecretLen + 1) + minSecretLen;
			System.out.println("secreLen 1 = " + secreLen);

			byte[] secret = new byte[secreLen];
			rnd.nextBytes(secret);
			int thresholdSize = rnd.nextInt(maxThreshold - minThreshold + 1) + minThreshold;
			int sharesSize = rnd.nextInt(maxShares - minShares + 1) + minShares;
			if (thresholdSize > sharesSize)
				sharesSize = thresholdSize;

			secretAvg = (secretAvg + secreLen) / 2;
			thresholdAvg = (thresholdAvg + thresholdSize) / 2;
			shareAvg = (shareAvg + sharesSize) / 2;

			byte[][] shares = tss.createShares(secret, sharesSize, thresholdSize, rnd);
			generateMs += System.currentTimeMillis() - T0;
			T0 = System.currentTimeMillis();
			Combination combination = new Combination(shares.length, thresholdSize);
			byte[][] recoverShare = new byte[thresholdSize][];
			for (int[] x : combination) {
				++combinations;

				if (rnd.nextBoolean())
					for (int j = 0, n = x.length; j < n; j++)
						recoverShare[j] = shares[x[j]];
				else
					for (int j = 0, n = x.length - 1; j <= n; j++)
						recoverShare[n - j] = shares[x[j]];

				if (combinations % (10 * TEST_LOAD_FACTOR) == 0)
					System.out.print("*");
				byte[] recovered = tss.recoverSecret(recoverShare);
				if (!Arrays.equals(secret, recovered)) {
					System.out.println("\nsecret:" + Hex.convert(secret));
					System.out.println("secret len:" + secret.length);
					System.out.println("shares:" + sharesSize);
					for (int j = 0; j < shares.length; j++)
						System.out.println("share" + j + ":" + Hex.convert(shares[j]));
					System.out.println("threshold:" + thresholdSize);
					System.out.println("recovered:" + Hex.convert(recovered));
					for (int j = 0; j < recoverShare.length; j++)
						System.out.println("recover share" + j + ":" + Hex.convert(recoverShare[j]));
					Assert.fail("array mismatch");
				}
			}
			recoverMs += System.currentTimeMillis() - T0;
		}
		System.out.println(String.format("%ngenerating (%s secret keys): %s ms - %.2f ms/key", iterations, generateMs, (double) generateMs / iterations));
		System.out.println(String.format("recovering (%s combinations): %s ms - %.2f ms/comb", combinations, recoverMs, (double) recoverMs / combinations));
		System.out.println(String.format("secret len avg: %.1f", secretAvg));
		System.out.println(String.format("share len avg: %.1f", shareAvg));
		System.out.println(String.format("threshold len avg: %.1f", thresholdAvg));
		System.out.println();
	}

	@Test
	public void testThreadSafe() throws InterruptedException {
		final int N = 100 * TEST_LOAD_FACTOR;
		int threads = 10;
		final ThresholdSecretSharing tss = new ThresholdSecretSharing();
		@SuppressWarnings("unchecked")
		TestThread<Boolean>[] cthreads = new TestThread[threads];

		for (int p = 0; p < threads; p++) {
			TestThread<Boolean> t = new TestThread<Boolean>("util-" + p) {
				@Override
				public void testableRun() throws Throwable {
					for (int i = 0; i < N; i++) {
						int secreLen = rnd.nextInt(512) + 12;
						byte[] secret = new byte[secreLen];
						byte[][] shares = tss.createShares(secret, 10, 3, rnd);
						byte[] recovered = tss.recoverSecret(shares);
						if (!Arrays.equals(secret, recovered)) {
							setError("cannot recover secret");
							break;
						}
					}
				}
				@Override
				public Boolean getResult() {
					return true;
				}
			};
			cthreads[p] = t;
			t.start();
		}

		for (TestThread<Boolean> t : cthreads)
			t.join();

		for (TestThread<Boolean> t : cthreads)
			t.assertThread();

	}

}