package cn.beeKey.cryptography.util;

import java.util.Arrays;
import java.util.Iterator;
import java.util.NoSuchElementException;

public class Combination implements Iterable<int[]> {
	private final int n;
	private final int k;
	private final int[] data;

	public Combination(int n, int k) {
		if (n < 0)
			throw new IllegalArgumentException("n<0");
		if (k < 0)
			throw new IllegalArgumentException("k<0");
		if (n < k)
			throw new IllegalArgumentException("n<k");
		this.n = n;
		this.k = k;
		this.data = new int[k];
		for (int i = 0; i < k; ++i)
			this.data[i] = i;
	}

	public Combination(int n, int k, int[] a) {
		if (k != a.length)
			throw new IllegalArgumentException("Array length does not equal k");

		this.n = n;
		this.k = k;
		this.data = new int[k];
		for (int i = 0; i < a.length; ++i)
			this.data[i] = a[i];

		if (!isValid())
			throw new IllegalArgumentException("Bad value from array");
	}

	private boolean isValid() {
		if (this.data.length != this.k)
			return false;

		for (int i = 0; i < this.k; ++i) {
			if (this.data[i] < 0 || this.data[i] > this.n - 1)
				return false;

			for (int j = i + 1; j < this.k; ++j)
				if (this.data[i] >= this.data[j])
					return false;
		}

		return true;
	}

	@Override
	public String toString() {
		return "{" + Arrays.toString(data) + "}";
	}

	public Combination sucessor() {
		if (this.data[0] == this.n - this.k)
			return null;

		Combination ans = new Combination(this.n, this.k);

		int i;
		for (i = 0; i < this.k; ++i)
			ans.data[i] = this.data[i];

		for (i = this.k - 1; i > 0 && ans.data[i] == this.n - this.k + i; --i)
			;

		++ans.data[i];

		for (int j = i; j < this.k - 1; ++j)
			ans.data[j + 1] = ans.data[j] + 1;

		return ans;
	}

	private int choose(int n, int k) {
		if (n < 0 || k < 0)
			throw new IllegalArgumentException("Invalid negative parameter in choose()");
		if (n < k)
			return 0;
		if (n == k)
			return 1;

		int delta, iMax;

		if (k < n - k) {
			delta = n - k;
			iMax = k;
		} else {
			delta = k;
			iMax = n - k;
		}

		int ans = delta + 1;

		for (int i = 2; i <= iMax; ++i)
			ans = (ans * (delta + i)) / i;

		return ans;

	}

	public Combination element(int m) {
		int[] ans = new int[this.k];

		int a = this.n;
		int b = this.k;
		int x = (choose(this.n, this.k) - 1) - m;

		for (int i = 0; i < this.k; ++i) {
			ans[i] = largestV(a, b, x);
			x = x - choose(ans[i], b);
			a = ans[i];
			b = b - 1;
		}

		for (int i = 0; i < this.k; ++i)
			ans[i] = (n - 1) - ans[i];

		return new Combination(this.n, this.k, ans);
	}

	private int largestV(int a, int b, int x) {
		int v = a - 1;

		while (choose(v, b) > x)
			--v;

		return v;
	}

	@Override
	public Iterator<int[]> iterator() {
		return new Iterator<int[]>() {
			private Combination current = null;
			private Combination next = Combination.this;

			@Override
			public boolean hasNext() {
				return next != null;
			}

			@Override
			public int[] next() {
				if (next == null)
					throw new NoSuchElementException();
				current = next;
				next = current.sucessor();
				return current.data;
			}

			@Override
			public void remove() {
				throw new UnsupportedOperationException("cannot remove items from combination");
			}

		};
	}

}