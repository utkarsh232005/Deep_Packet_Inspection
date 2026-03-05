package com.dpi.utils;

import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;

public class ThreadSafeQueue<T> {
    private final LinkedBlockingQueue<T> queue;

    public ThreadSafeQueue(int capacity) {
        this.queue = new LinkedBlockingQueue<>(capacity);
    }

    public void enqueue(T item) throws InterruptedException {
        queue.put(item);
    }

    public boolean enqueueWithTimeout(T item, long timeout, TimeUnit unit) throws InterruptedException {
        return queue.offer(item, timeout, unit);
    }

    public T dequeue() throws InterruptedException {
        return queue.take();
    }

    public T dequeueWithTimeout(long timeout, TimeUnit unit) throws InterruptedException {
        return queue.poll(timeout, unit);
    }

    public int size() {
        return queue.size();
    }

    public boolean isEmpty() {
        return queue.isEmpty();
    }

    public void clear() {
        queue.clear();
    }
}
