// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package com.amazon.corretto.crypto.provider.benchmarks;

import java.nio.ByteBuffer;
import java.security.Key;
import java.util.concurrent.TimeUnit;
import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import com.amazon.corretto.crypto.provider.AmazonCorrettoCryptoProvider;
import org.openjdk.jmh.annotations.Benchmark;
import org.openjdk.jmh.annotations.BenchmarkMode;
import org.openjdk.jmh.annotations.Mode;
import org.openjdk.jmh.annotations.OutputTimeUnit;
import org.openjdk.jmh.annotations.Param;
import org.openjdk.jmh.annotations.Scope;
import org.openjdk.jmh.annotations.Setup;
import org.openjdk.jmh.annotations.State;

@State(Scope.Thread)
@BenchmarkMode(Mode.AverageTime)
@OutputTimeUnit(TimeUnit.NANOSECONDS)
public class AesGcmByteBuffer {
  @Param({"512", "9000", "1048576"})
  public int size;

  @Param({"true", "false"})
  public boolean direct;

  @Param({"false", "true"})
  public boolean inPlace;

  @Param({"false", "true"})
  public boolean aad;

  @Param({AmazonCorrettoCryptoProvider.PROVIDER_NAME})
  public String provider;

  private final byte[] aadBytes = BenchmarkUtils.getRandBytes(13);

  private Key key;
  private GCMParameterSpec params1;
  private GCMParameterSpec params2;
  private boolean useParams1 = true;
  private Cipher encryptor;
  private Cipher decryptor;
  private ByteBuffer plaintext;
  private ByteBuffer ciphertext;
  private ByteBuffer output;
  private ByteBuffer work;
  private ByteBuffer workOutput;

  @Setup
  public void setup() throws Exception {
    BenchmarkUtils.setupProvider(provider);
    key = new SecretKeySpec(BenchmarkUtils.getRandBytes(32), "AES");
    params1 = new GCMParameterSpec(128, BenchmarkUtils.getRandBytes(12));
    params2 = new GCMParameterSpec(128, BenchmarkUtils.getRandBytes(12));
    encryptor = Cipher.getInstance("AES/GCM/NoPadding", provider);
    decryptor = Cipher.getInstance("AES/GCM/NoPadding", provider);

    plaintext = allocate(size);
    plaintext.put(BenchmarkUtils.getRandBytes(size)).flip();
    ciphertext = allocate(size + 16);
    encryptor.init(Cipher.ENCRYPT_MODE, key, params1);
    if (aad) {
      encryptor.updateAAD(aadBytes);
    }
    encryptor.doFinal(plaintext.duplicate(), ciphertext);
    ciphertext.flip();
    output = allocate(size + 16);
    work = allocate(size + 16);
    workOutput = work.duplicate();
    decryptor.init(Cipher.DECRYPT_MODE, key, params1);
  }

  private ByteBuffer allocate(final int length) {
    return direct ? ByteBuffer.allocateDirect(length) : ByteBuffer.allocate(length);
  }

  @Benchmark
  public ByteBuffer encrypt() throws Exception {
    useParams1 = !useParams1;
    encryptor.init(Cipher.ENCRYPT_MODE, key, useParams1 ? params1 : params2);
    if (aad) {
      encryptor.updateAAD(aadBytes);
    }
    if (inPlace) {
      work.clear().limit(size);
      workOutput.clear();
      encryptor.doFinal(work, workOutput);
      return workOutput;
    }
    plaintext.rewind();
    output.clear();
    encryptor.doFinal(plaintext, output);
    return output;
  }

  @Benchmark
  public ByteBuffer decrypt() throws Exception {
    if (aad) {
      decryptor.updateAAD(aadBytes);
    }
    ciphertext.rewind();
    if (inPlace) {
      work.clear();
      work.put(ciphertext).flip();
      workOutput.clear();
      decryptor.doFinal(work, workOutput);
      return workOutput;
    }
    output.clear();
    decryptor.doFinal(ciphertext, output);
    return output;
  }
}
