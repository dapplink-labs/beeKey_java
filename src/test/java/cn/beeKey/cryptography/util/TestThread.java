package cn.beeKey.cryptography.util;

import junit.framework.Assert;

public abstract class TestThread<T> extends Thread {
	private String error;

	public TestThread(String name) {
		super(name);
	}

	public void setError(String error) {
		this.error = error;
	}

	@Override
	public void run() {
		try {
			testableRun();
		} catch (Throwable e) {
			setError(e.getMessage());
		}
	}

	public abstract void testableRun() throws Throwable;

	public void assertThread() {
		if (error != null) Assert.fail(error);
	}
	
	public abstract T getResult();
	
}
